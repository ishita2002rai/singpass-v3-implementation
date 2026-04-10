package com.example.wso2;

import com.example.wso2.utils.MockPassUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONException;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Custom WSO2 OIDC authenticator implementing a FAPI-compliant flow for MockPass (Singpass v3).
 *
 * <p>Security features:
 * <ul>
 *   <li>PAR  – Pushed Authorization Requests (auth params sent via backchannel)</li>
 *   <li>PKCE – Proof Key for Code Exchange (S256)</li>
 *   <li>DPoP – Demonstrating Proof of Possession (ephemeral EC key per session)</li>
 *   <li>Private-key JWT client authentication (no shared secret)</li>
 *   <li>JWE  – Encrypted ID token (ECDH-ES, decrypted with local EC private key)</li>
 * </ul>
 *
 * <p>Constants are defined in {@link MockPassConstants}.
 * Cryptographic and encoding helpers are in {@link MockPassUtils}.
 */
public class MockPassOIDCAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log LOG = LogFactory.getLog(MockPassOIDCAuthenticator.class);

    // ── Lazily-loaded keys (double-checked locking) ───────────────────────────

    /** EC private key used to sign client assertion JWTs; loaded once from the signing keystore. */
    private volatile ECPrivateKey signingKey;

    /** EC private key used to decrypt JWE id_tokens; loaded once from the encryption keystore. */
    private volatile ECPrivateKey encryptionKey;

    // ── Identity ──────────────────────────────────────────────────────────────

    @Override
    public String getName() {
        return MockPassConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return MockPassConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    // ── Configuration properties ──────────────────────────────────────────────

    /**
     * Returns the list of configuration properties exposed in the WSO2 management console
     * for this authenticator. Inherits parent OIDC properties, removes the client secret
     * field (not used in private_key_jwt flows), and appends the PAR endpoint property.
     *
     * @return {@link List} of {@link Property} objects defining the authenticator's UI fields.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<>(
                Optional.ofNullable(super.getConfigurationProperties()).orElse(Collections.emptyList())
        );

        // Remove client secret – authentication is done via private_key_jwt, not a shared secret.
        properties.removeIf(p ->
                IdentityApplicationConstants.Authenticator.OIDC.CLIENT_SECRET.equals(p.getName()));

        Property par = new Property();
        par.setName(MockPassConstants.PARAM_PAR_ENDPOINT);
        par.setDisplayName(MockPassConstants.PAR_ENDPOINT_DISPLAY_NAME);
        par.setRequired(true);
        par.setDescription(MockPassConstants.PAR_ENDPOINT_DESCRIPTION);
        properties.add(par);

        return properties;
    }

    /**
     * Initiates the MockPass FAPI authentication flow using Pushed Authorization Requests (PAR).
     *
     * <p>Execution order:
     * <ol>
     *   <li>Generates an ephemeral EC key pair for DPoP binding.</li>
     *   <li>Generates state, nonce, and PKCE code verifier / challenge.</li>
     *   <li>Builds a DPoP proof JWT and a private_key_jwt client assertion.</li>
     *   <li>Sends authorization parameters to the PAR endpoint (backchannel POST).</li>
     *   <li>Redirects the browser to the authorization endpoint with only {@code client_id}
     *       and the returned {@code request_uri}.</li>
     * </ol>
     *
     * @param request  the incoming {@link HttpServletRequest} from the browser.
     * @param response the {@link HttpServletResponse} used to issue the redirect.
     * @param context  the {@link AuthenticationContext} that carries per-session properties.
     * @throws AuthenticationFailedException if any step in the PAR flow or redirect fails.
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("[MockPass] initiateAuthenticationRequest invoked");
        }

        try {
            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId      = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String parEndpoint   = props.get(MockPassConstants.PARAM_PAR_ENDPOINT);
            String authEndpoint  = props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
            String callback      = getCallbackUrl(props, context);

            KeyPair ephemeralKeyPair = MockPassUtils.generateEphemeralKeyPair();
            context.setProperty(MockPassConstants.CTX_EPHEMERAL_KEY, ephemeralKeyPair);

            String state      = UUID.randomUUID().toString();
            String nonce      = UUID.randomUUID().toString();
            String stateValue = state + "." + context.getContextIdentifier();
            context.setProperty(MockPassConstants.CTX_STATE, state);
            context.setProperty(MockPassConstants.CTX_NONCE, nonce);

            String codeVerifier  = MockPassUtils.generateCodeVerifier();
            String codeChallenge = MockPassUtils.computeCodeChallenge(codeVerifier);
            context.setProperty(MockPassConstants.CTX_CODE_VERIFIER, codeVerifier);

            String keyAlias = getAuthenticatorConfig().getParameterMap()
                    .get(MockPassConstants.PARAM_KEY_ALIAS);
            String dpop            = MockPassUtils.generateDPoP(parEndpoint,
                    MockPassConstants.HTTP_METHOD_POST, ephemeralKeyPair);
            String clientAssertion = MockPassUtils.generateClientAssertionJwt(
                    clientId, tokenEndpoint, keyAlias, getSigningKey());

            String requestUri = pushAuthorizationRequest(
                    parEndpoint, clientId, callback, stateValue, nonce,
                    codeChallenge, clientAssertion, dpop
            );

            String authUrl = authEndpoint
                    + "?" + MockPassConstants.PARAM_KEY_CLIENT_ID
                    + "=" + MockPassUtils.encode(clientId)
                    + "&" + MockPassConstants.PARAM_KEY_REQUEST_URI
                    + "=" + MockPassUtils.encode(requestUri);

            if (LOG.isDebugEnabled()) {
                LOG.debug("[MockPass] Redirecting to authorization endpoint: " + authEndpoint);
            }
            response.sendRedirect(authUrl);

        } catch (GeneralSecurityException e) {
            LOG.error("[MockPass] Security error during PAR flow initiation", e);
            throw new AuthenticationFailedException(
                    "Security error during MockPass authentication initiation", e);
        } catch (JOSEException e) {
            LOG.error("[MockPass] JWT/JWE error while building DPoP or client assertion during PAR initiation", e);
            throw new AuthenticationFailedException(
                    "JWT error during MockPass authentication initiation", e);
        } catch (IOException e) {
            LOG.error("[MockPass] Network or I/O error during PAR request", e);
            throw new AuthenticationFailedException(
                    "I/O error during MockPass PAR request", e);
        }
    }

    /**
     * Determines whether this authenticator can handle the incoming callback request.
     *
     * <p>Returns {@code true} when both an authorization {@code code} and a
     * {@code sessionDataKey} are present in the request, or when the parent
     * class's own check passes.
     *
     * @param request the incoming {@link HttpServletRequest} from the browser callback.
     * @return {@code true} if this authenticator should process the request; {@code false} otherwise.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        String code           = request.getParameter(MockPassConstants.PARAM_CODE);
        String sessionDataKey = request.getParameter(MockPassConstants.PARAM_SESSION_DATA_KEY);
        boolean handled       = (code != null && sessionDataKey != null) || super.canHandle(request);

        if (LOG.isDebugEnabled()) {
            LOG.debug("[MockPass] canHandle=" + handled
                    + " code=" + (code != null)
                    + " sessionDataKey=" + (sessionDataKey != null));
        }
        return handled;
    }

    /**
     * Validates the {@code state} parameter returned by the authorization server against
     * the value stored in context, then delegates to the parent to complete token exchange.
     *
     * <p>A mismatch between the returned and stored state values indicates a possible CSRF
     * attack and causes an {@link AuthenticationFailedException} to be thrown immediately.
     *
     * @param request  the callback {@link HttpServletRequest} containing {@code code} and {@code state}.
     * @param response the {@link HttpServletResponse}.
     * @param context  the {@link AuthenticationContext} holding the original state value.
     * @throws AuthenticationFailedException if state validation fails or the parent processing fails.
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String returnedState = request.getParameter(MockPassConstants.PARAM_STATE);
        String originalState = (String) context.getProperty(MockPassConstants.CTX_STATE);

        if (originalState != null && returnedState != null
                && !originalState.equals(returnedState)) {
            throw new AuthenticationFailedException(
                    "State mismatch – possible CSRF. expected=" + originalState
                            + " received=" + returnedState);
        }

        super.processAuthenticationResponse(request, response, context);
    }

    /**
     * Builds the access token request body with PKCE, private_key_jwt client authentication,
     * and a DPoP proof header bound to the session's ephemeral key pair.
     *
     * @param context       the {@link AuthenticationContext} containing the PKCE verifier,
     *                      ephemeral key pair, and authenticator properties.
     * @param authzResponse the {@link OAuthAuthzResponse} carrying the authorization code.
     * @return an {@link OAuthClientRequest} populated with all required token request parameters
     *         and a {@code DPoP} header.
     * @throws AuthenticationFailedException if the token request cannot be constructed.
     */
    @Override
    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context,
                                                       OAuthAuthzResponse authzResponse)
            throws AuthenticationFailedException {

        if (LOG.isDebugEnabled()) {
            LOG.debug("[MockPass] getAccessTokenRequest invoked");
        }

        try {
            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId      = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
            String callback      = getCallbackUrl(props, context);
            String codeVerifier  = (String) context.getProperty(MockPassConstants.CTX_CODE_VERIFIER);
            KeyPair keyPair      = (KeyPair) context.getProperty(MockPassConstants.CTX_EPHEMERAL_KEY);

            String keyAlias = getAuthenticatorConfig().getParameterMap()
                    .get(MockPassConstants.PARAM_KEY_ALIAS);
            String clientAssertion = MockPassUtils.generateClientAssertionJwt(
                    clientId, tokenEndpoint, keyAlias, getSigningKey());
            String dpop = MockPassUtils.generateDPoP(tokenEndpoint,
                    MockPassConstants.HTTP_METHOD_POST, keyPair);

            OAuthClientRequest tokenRequest = OAuthClientRequest
                    .tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setRedirectURI(callback)
                    .setCode(authzResponse.getCode())
                    .setClientId(clientId)
                    .setParameter(MockPassConstants.PARAM_KEY_CLIENT_ASSERTION_TYPE,
                            MockPassConstants.CLIENT_ASSERTION_TYPE)
                    .setParameter(MockPassConstants.PARAM_KEY_CLIENT_ASSERTION, clientAssertion)
                    .setParameter(MockPassConstants.PARAM_KEY_CODE_VERIFIER, codeVerifier)
                    .buildBodyMessage();

            tokenRequest.addHeader(MockPassConstants.HTTP_HEADER_DPOP, dpop);
            return tokenRequest;

        } catch (OAuthSystemException e) {
            LOG.error("[MockPass] OAuth system error while building token request", e);
            throw new AuthenticationFailedException("Token request construction failed", e);
        } catch (GeneralSecurityException e) {
            LOG.error("[MockPass] Security error while building token request", e);
            throw new AuthenticationFailedException("Token request construction failed due to security error", e);
        } catch (JOSEException e) {
            LOG.error("[MockPass] JWT/JWE error while building DPoP or client assertion for token request", e);
            throw new AuthenticationFailedException("Token request construction failed due to JWT error", e);
        } catch (IOException e) {
            LOG.error("[MockPass] I/O error reading signing keystore while building token request", e);
            throw new AuthenticationFailedException("Token request construction failed due to keystore I/O error", e);
        }
    }

    /**
     * Intercepts the token response to decrypt the JWE-wrapped {@code id_token} before the
     * parent class attempts to parse it. The decrypted signed JWT string is stored in context
     * so that {@link #mapIdToken} can retrieve it without re-parsing the encrypted form.
     *
     * @param request the callback {@link HttpServletRequest}.
     * @param context the {@link AuthenticationContext}.
     * @return the {@link OAuthClientResponse} from the parent's token exchange (unchanged).
     * @throws AuthenticationFailedException if JWE decryption fails.
     */
    @Override
    protected OAuthClientResponse requestAccessToken(HttpServletRequest request,
                                                     AuthenticationContext context)
            throws AuthenticationFailedException {

        OAuthClientResponse tokenResponse = super.requestAccessToken(request, context);

        String idToken = tokenResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (idToken != null) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("[MockPass] Decrypting JWE id_token");
                }
                String decryptedIdToken = decryptIdToken(idToken);
                context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, decryptedIdToken);
            } catch (ParseException e) {
                LOG.error("[MockPass] Failed to parse encrypted id_token as JWE", e);
                throw new AuthenticationFailedException("id_token decryption failed: unable to parse JWE", e);
            } catch (JOSEException e) {
                LOG.error("[MockPass] Failed to decrypt id_token JWE", e);
                throw new AuthenticationFailedException("id_token decryption failed", e);
            } catch (GeneralSecurityException e) {
                // Covers KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, etc.
                LOG.error("[MockPass] Security error while loading encryption key for id_token decryption", e);
                throw new AuthenticationFailedException(
                        "id_token decryption failed due to security error loading key", e);
            } catch (IOException e) {
                LOG.error("[MockPass] I/O error while loading encryption keystore for id_token decryption", e);
                throw new AuthenticationFailedException(
                        "id_token decryption failed due to keystore I/O error", e);
            }
        }

        return tokenResponse;
    }

    /**
     * Returns the pre-decrypted {@code id_token} stored in context, bypassing the parent's
     * attempt to use the still-encrypted token from the token response.
     *
     * @param context       the {@link AuthenticationContext} holding the decrypted token.
     * @param request       the callback {@link HttpServletRequest}.
     * @param tokenResponse the raw {@link OAuthClientResponse} from the token endpoint.
     * @return the decrypted signed JWT string, or the parent's result if none is stored in context.
     * @throws AuthenticationFailedException if the parent's mapIdToken call fails.
     */
    @Override
    protected String mapIdToken(AuthenticationContext context,
                                HttpServletRequest request,
                                OAuthClientResponse tokenResponse)
            throws AuthenticationFailedException {

        String decrypted = (String) context.getProperty(OIDCAuthenticatorConstants.ID_TOKEN);
        return (decrypted != null) ? decrypted : super.mapIdToken(context, request, tokenResponse);
    }

    /**
     * Sends the Pushed Authorization Request (PAR) to the PAR endpoint as a backchannel
     * HTTP POST and returns the {@code request_uri} from the server's JSON response.
     *
     * @param parEndpoint     the URL of the PAR endpoint.
     * @param clientId        the OAuth client identifier.
     * @param callback        the registered redirect URI.
     * @param state           the state value combining a random component and the session identifier.
     * @param nonce           a random nonce value for replay protection.
     * @param codeChallenge   the PKCE S256 code challenge derived from the verifier.
     * @param clientAssertion the signed private_key_jwt for client authentication.
     * @param dpop            the DPoP proof JWT bound to the PAR endpoint and POST method.
     * @return the {@code request_uri} string returned by the PAR server.
     * @throws AuthenticationFailedException if the server returns HTTP 4xx/5xx or the response
     *                                       JSON does not contain a {@code request_uri} field.
     * @throws IOException                   if a network or stream error occurs.
     */
    private String pushAuthorizationRequest(String parEndpoint,
                                            String clientId,
                                            String callback,
                                            String state,
                                            String nonce,
                                            String codeChallenge,
                                            String clientAssertion,
                                            String dpop)
            throws AuthenticationFailedException, IOException {

        String body = MockPassConstants.PARAM_KEY_CLIENT_ID
                + "=" + MockPassUtils.encode(clientId)
                + "&" + MockPassConstants.PARAM_KEY_REDIRECT_URI
                + "=" + MockPassUtils.encode(callback)
                + "&" + MockPassConstants.PARAM_KEY_RESPONSE_TYPE
                + "=" + MockPassUtils.encode(MockPassConstants.RESPONSE_TYPE_CODE)
                + "&" + MockPassConstants.PARAM_KEY_SCOPE
                + "=" + MockPassUtils.encode(MockPassConstants.SCOPE_OPENID_UINFIN)
                + "&" + MockPassConstants.PARAM_STATE
                + "=" + MockPassUtils.encode(state)
                + "&" + MockPassConstants.PARAM_KEY_NONCE
                + "=" + MockPassUtils.encode(nonce)
                + "&" + MockPassConstants.PARAM_KEY_CODE_CHALLENGE
                + "=" + MockPassUtils.encode(codeChallenge)
                + "&" + MockPassConstants.PARAM_KEY_CODE_CHALLENGE_METHOD
                + "=" + MockPassUtils.encode(MockPassConstants.CODE_CHALLENGE_METHOD)
                + "&" + MockPassConstants.PARAM_KEY_CLIENT_ASSERTION_TYPE
                + "=" + MockPassUtils.encode(MockPassConstants.CLIENT_ASSERTION_TYPE)
                + "&" + MockPassConstants.PARAM_KEY_CLIENT_ASSERTION
                + "=" + MockPassUtils.encode(clientAssertion);

        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(parEndpoint).openConnection();
        try {
            conn.setRequestMethod(MockPassConstants.HTTP_METHOD_POST);
            conn.setDoOutput(true);
            conn.setRequestProperty(MockPassConstants.HTTP_HEADER_CONTENT_TYPE,
                    MockPassConstants.CONTENT_TYPE_FORM);
            conn.setRequestProperty(MockPassConstants.HTTP_HEADER_CONTENT_LENGTH,
                    String.valueOf(bodyBytes.length));
            conn.setRequestProperty(MockPassConstants.HTTP_HEADER_DPOP, dpop);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
            }

            int status          = conn.getResponseCode();
            String responseBody = readBody(conn, status);

            if (LOG.isDebugEnabled()) {
                LOG.debug("[MockPass] PAR response status=" + status);
            }

            if (status >= 400) {
                throw new AuthenticationFailedException(
                        "PAR request failed with HTTP " + status + ": " + responseBody);
            }

            try {
                return new JSONObject(responseBody).getString(MockPassConstants.PARAM_KEY_REQUEST_URI);
            } catch (JSONException e) {
                LOG.error("[MockPass] PAR response JSON is missing 'request_uri' or is malformed. Response: "
                        + responseBody, e);
                throw new AuthenticationFailedException(
                        "PAR response did not contain a valid 'request_uri'", e);
            }

        } finally {
            conn.disconnect();
        }
    }

    /**
     * Reads the response body from an {@link HttpURLConnection}.
     * Uses the error stream for HTTP 4xx/5xx responses, and the regular input stream otherwise.
     *
     * @param conn   the open {@link HttpURLConnection}.
     * @param status the HTTP response status code.
     * @return the full response body as a UTF-8 string, or an empty string if the stream is null.
     * @throws IOException if an I/O error occurs while reading the stream.
     */
    private String readBody(HttpURLConnection conn, int status) throws IOException {

        InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) return "";
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    /**
     * Decrypts a JWE-wrapped {@code id_token} and returns the compact serialization of the
     * inner signed JWT so that the parent framework can verify it normally.
     *
     * <p>MockPass wraps the id_token as {@code JWE( SignedJWT )} using ECDH-ES key agreement.
     * After decryption, the payload must itself be a valid {@link SignedJWT}; otherwise an
     * {@link IllegalStateException} is thrown.
     *
     * @param encryptedJwt the compact-serialized JWE string received in the token response.
     * @return the compact-serialized inner {@link SignedJWT} string.
     * @throws ParseException           if the encrypted JWT cannot be parsed as a JWE.
     * @throws JOSEException            if decryption fails.
     * @throws GeneralSecurityException if loading the encryption private key fails.
     * @throws IOException              if the encryption keystore file cannot be read.
     */
    private String decryptIdToken(String encryptedJwt)
            throws ParseException, JOSEException, GeneralSecurityException, IOException {

        EncryptedJWT jwe = EncryptedJWT.parse(encryptedJwt);
        jwe.decrypt(new ECDHDecrypter(getEncryptionKey()));
        SignedJWT inner = jwe.getPayload().toSignedJWT();
        if (inner == null) {
            throw new IllegalStateException("Decrypted JWE payload is not a SignedJWT");
        }
        return inner.serialize();
    }

    /**
     * Returns the EC private key used for signing client assertion JWTs, loading it from the
     * configured signing keystore on first access using double-checked locking.
     *
     * @return the {@link ECPrivateKey} for client assertion signing.
     * @throws GeneralSecurityException if the keystore cannot be loaded, the alias is not found,
     *                                   or the recovered key is not an {@link ECPrivateKey}.
     * @throws IOException              if the keystore file cannot be read.
     */
    private ECPrivateKey getSigningKey() throws GeneralSecurityException, IOException {

        if (signingKey == null) {
            synchronized (this) {
                if (signingKey == null) {
                    Map<String, String> p = getAuthenticatorConfig().getParameterMap();
                    signingKey = MockPassUtils.loadPrivateKey(
                            p.get(MockPassConstants.PARAM_SIGNING_KEYSTORE),
                            p.get(MockPassConstants.PARAM_KEYSTORE_PASSWORD),
                            p.get(MockPassConstants.PARAM_KEY_ALIAS));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[MockPass] Signing key loaded from keystore alias: "
                                + p.get(MockPassConstants.PARAM_KEY_ALIAS));
                    }
                }
            }
        }
        return signingKey;
    }

    /**
     * Returns the EC private key used for decrypting JWE id_tokens, loading it from the
     * configured encryption keystore on first access using double-checked locking.
     *
     * @return the {@link ECPrivateKey} for id_token decryption.
     * @throws GeneralSecurityException if the keystore cannot be loaded, the alias is not found,
     *                                   or the recovered key is not an {@link ECPrivateKey}.
     * @throws IOException              if the keystore file cannot be read.
     */
    private ECPrivateKey getEncryptionKey() throws GeneralSecurityException, IOException {

        if (encryptionKey == null) {
            synchronized (this) {
                if (encryptionKey == null) {
                    Map<String, String> p = getAuthenticatorConfig().getParameterMap();
                    encryptionKey = MockPassUtils.loadPrivateKey(
                            p.get(MockPassConstants.PARAM_ENCRYPTION_KEYSTORE),
                            p.get(MockPassConstants.PARAM_ENCRYPTION_KEYSTORE_PASS),
                            p.get(MockPassConstants.PARAM_ENCRYPTION_KEY_ALIAS));
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("[MockPass] Encryption key loaded from keystore alias: "
                                + p.get(MockPassConstants.PARAM_ENCRYPTION_KEY_ALIAS));
                    }
                }
            }
        }
        return encryptionKey;
    }
}