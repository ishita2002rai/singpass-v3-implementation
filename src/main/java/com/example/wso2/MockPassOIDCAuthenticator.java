package com.example.wso2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

/**
 * Custom WSO2 OIDC authenticator implementing a FAPI-compliant flow for MockPass (Singpassv3).
 *
 * <p>Security features:
 * <ul>
 *   <li>PAR  – Pushed Authorization Requests (auth params sent via backchannel)</li>
 *   <li>PKCE – Proof Key for Code Exchange (S256)</li>
 *   <li>DPoP – Demonstrating Proof of Possession (ephemeral EC key per session)</li>
 *   <li>Private-key JWT client authentication (no shared secret)</li>
 *   <li>JWE  – Encrypted ID token (ECDH-ES, decrypted with local EC private key)</li>
 * </ul>
 */
public class MockPassOIDCAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log LOG = LogFactory.getLog(MockPassOIDCAuthenticator.class);

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final String AUTHENTICATOR_NAME          = "MockPassOIDCAuthenticator";
    private static final String AUTHENTICATOR_FRIENDLY_NAME = "MockPass OIDC Authenticator";

    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /** Context property keys */
    private static final String CTX_EPHEMERAL_KEY  = "EPHEMERAL_KEY";
    private static final String CTX_CODE_VERIFIER  = "CODE_VERIFIER";
    private static final String CTX_STATE          = "STATE";
    private static final String CTX_NONCE          = "NONCE";

    /** Authenticator config parameter names */
    private static final String PARAM_PAR_ENDPOINT              = "par_endpoint";
    private static final String PARAM_SIGNING_KEYSTORE           = "signing_keystore";
    private static final String PARAM_KEYSTORE_PASSWORD          = "keystore_password";
    private static final String PARAM_KEY_ALIAS                  = "key_alias";
    private static final String PARAM_ENCRYPTION_KEYSTORE        = "encryption_keystore";
    private static final String PARAM_ENCRYPTION_KEYSTORE_PASS   = "encryption_keystore_password";
    private static final String PARAM_ENCRYPTION_KEY_ALIAS       = "encryption_key_alias";

    private static final String EC_CURVE      = "secp256r1";
    private static final int    EC_COORD_SIZE = 32;             // bytes for P-256 coordinates
    private static final long   JWT_TTL_MS    = 5 * 60 * 1000L; // 5 minutes
    private static final long   DPOP_TTL_SEC  = 120L;           // 2 minutes

    // ── Lazily-loaded keys (one load per authenticator instance) ──────────────

    /** Guarded by {@code this}; loaded once from the signing keystore. */
    private volatile ECPrivateKey signingKey;

    /** Guarded by {@code this}; loaded once from the encryption keystore. */
    private volatile ECPrivateKey encryptionKey;

    // ── Identity ──────────────────────────────────────────────────────────────

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    // ── Configuration properties ──────────────────────────────────────────────

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> properties = new ArrayList<>(
                Optional.ofNullable(super.getConfigurationProperties()).orElse(Collections.emptyList())
        );

        Property par = new Property();
        par.setName(PARAM_PAR_ENDPOINT);
        par.setDisplayName("PAR Endpoint");
        par.setRequired(true);
        par.setDescription("Pushed Authorization Request endpoint for FAPI flow");
        properties.add(par);

        return properties;
    }

    // =========================================================================
    // STEP 1 – Initiate: PAR + PKCE + DPoP + redirect
    // =========================================================================

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        LOG.info("Initiating MockPass authentication (PAR flow)");

        try {
            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId      = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String parEndpoint   = props.get(PARAM_PAR_ENDPOINT);
            String authEndpoint  = props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
            String callback      = getCallbackUrl(props, context);

            // 1a. Ephemeral EC key pair – reused for DPoP at /par and /token
            KeyPair ephemeralKeyPair = generateEphemeralKeyPair();
            context.setProperty(CTX_EPHEMERAL_KEY, ephemeralKeyPair);

            // 1b. State / nonce
            String state   = UUID.randomUUID().toString();
            String nonce   = UUID.randomUUID().toString();
            String stateValue = state + "." + context.getContextIdentifier();
            context.setProperty(CTX_STATE, state);
            context.setProperty(CTX_NONCE, nonce);

            // 1c. PKCE
            String codeVerifier  = generateCodeVerifier();
            String codeChallenge = computeCodeChallenge(codeVerifier);
            context.setProperty(CTX_CODE_VERIFIER, codeVerifier);

            // 1d. Security tokens
            String dpop           = generateDPoP(parEndpoint, "POST", ephemeralKeyPair);
            String clientAssertion = generateClientAssertionJwt(clientId, tokenEndpoint);

            // 1e. Push authorization request
            String requestUri = pushAuthorizationRequest(
                    parEndpoint, clientId, callback, stateValue, nonce,
                    codeChallenge, clientAssertion, dpop
            );

            // 1f. Redirect browser to authorization endpoint
            String authUrl = authEndpoint
                    + "?client_id=" + encode(clientId)
                    + "&request_uri=" + encode(requestUri);

            LOG.info("Redirecting to authorization endpoint");
            response.sendRedirect(authUrl);

        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (Exception e) {
            LOG.error("PAR flow failed", e);
            throw new AuthenticationFailedException("Failed to initiate MockPass authentication", e);
        }
    }

    // =========================================================================
    // STEP 2 – Callback: canHandle
    // =========================================================================

    /**
     * Handles the authorization callback if both {@code code} and
     * {@code sessionDataKey} are present, or falls back to the parent check.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {
        String code           = request.getParameter("code");
        String sessionDataKey = request.getParameter("sessionDataKey");
        boolean handled       = (code != null && sessionDataKey != null) || super.canHandle(request);
        LOG.debug("canHandle=" + handled + " code=" + (code != null) + " sdk=" + (sessionDataKey != null));
        return handled;
    }

    // =========================================================================
    // STEP 3 – Process callback: validate state
    // =========================================================================

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String returnedState = request.getParameter("state");
        String originalState = (String) context.getProperty(CTX_STATE);

        if (originalState != null && returnedState != null
                && !originalState.equals(returnedState)) {
            throw new AuthenticationFailedException(
                    "State mismatch – possible CSRF. expected=" + originalState
                            + " received=" + returnedState);
        }

        super.processAuthenticationResponse(request, response, context);
    }

    // =========================================================================
    // STEP 4 – Build token request: code + PKCE + client assertion + DPoP
    // =========================================================================

    @Override
    protected OAuthClientRequest getAccessTokenRequest(AuthenticationContext context,
                                                       OAuthAuthzResponse authzResponse)
            throws AuthenticationFailedException {

        LOG.info("Building token request");

        try {
            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId      = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
            String callback      = getCallbackUrl(props, context);
            String codeVerifier  = (String) context.getProperty(CTX_CODE_VERIFIER);
            KeyPair keyPair      = (KeyPair) context.getProperty(CTX_EPHEMERAL_KEY);

            String clientAssertion = generateClientAssertionJwt(clientId, tokenEndpoint);
            String dpop            = generateDPoP(tokenEndpoint, "POST", keyPair);

            OAuthClientRequest tokenRequest = OAuthClientRequest
                    .tokenLocation(tokenEndpoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setRedirectURI(callback)
                    .setCode(authzResponse.getCode())
                    .setClientId(clientId)
                    .setParameter("client_assertion_type", CLIENT_ASSERTION_TYPE)
                    .setParameter("client_assertion", clientAssertion)
                    .setParameter("code_verifier", codeVerifier)
                    .buildBodyMessage();

            tokenRequest.addHeader("DPoP", dpop);
            return tokenRequest;

        } catch (Exception e) {
            LOG.error("Failed to build token request", e);
            throw new AuthenticationFailedException("Token request construction failed", e);
        }
    }

    // =========================================================================
    // STEP 5 – Decrypt JWE id_token
    // =========================================================================

    @Override
    protected OAuthClientResponse requestAccessToken(HttpServletRequest request,
                                                     AuthenticationContext context)
            throws AuthenticationFailedException {

        OAuthClientResponse tokenResponse = super.requestAccessToken(request, context);

        String idToken = tokenResponse.getParam("id_token");
        if (idToken != null) {
            try {
                LOG.info("Decrypting JWE id_token");
                String decryptedIdToken = decryptIdToken(idToken);
                context.setProperty(OIDCAuthenticatorConstants.ID_TOKEN, decryptedIdToken);
            } catch (Exception e) {
                throw new AuthenticationFailedException("id_token decryption failed", e);
            }
        }

        return tokenResponse;
    }

    /**
     * Returns the pre-decrypted id_token stored in context, bypassing the
     * parent's attempt to use the still-encrypted token from the response.
     */
    @Override
    protected String mapIdToken(AuthenticationContext context,
                                HttpServletRequest request,
                                OAuthClientResponse tokenResponse)
            throws AuthenticationFailedException {

        String decrypted = (String) context.getProperty(OIDCAuthenticatorConstants.ID_TOKEN);
        return (decrypted != null) ? decrypted : super.mapIdToken(context, request, tokenResponse);
    }

    // =========================================================================
    // Private helpers – PAR
    // =========================================================================

    /**
     * Sends the Pushed Authorization Request and returns the {@code request_uri}.
     *
     * @throws AuthenticationFailedException if the server responds with 4xx/5xx.
     */
    private String pushAuthorizationRequest(String parEndpoint, String clientId,
                                            String callback, String state,
                                            String nonce, String codeChallenge,
                                            String clientAssertion, String dpop)
            throws Exception {

        String body = "client_id="              + encode(clientId)
                + "&redirect_uri="              + encode(callback)
                + "&response_type=code"
                + "&scope="                     + encode("openid uinfin")
                + "&state="                     + encode(state)
                + "&nonce="                     + encode(nonce)
                + "&code_challenge="            + encode(codeChallenge)
                + "&code_challenge_method=S256"
                + "&client_assertion_type="     + encode(CLIENT_ASSERTION_TYPE)
                + "&client_assertion="          + encode(clientAssertion);

        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(parEndpoint).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));
            conn.setRequestProperty("DPoP", dpop);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
            }

            int status = conn.getResponseCode();
            String responseBody = readBody(conn, status);
            LOG.info("PAR response status=" + status);

            if (status >= 400) {
                throw new AuthenticationFailedException(
                        "PAR request failed with HTTP " + status + ": " + responseBody);
            }

            return new JSONObject(responseBody).getString("request_uri");

        } finally {
            conn.disconnect();
        }
    }

    private String readBody(HttpURLConnection conn, int status) throws IOException {
        InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) return "";
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }

    // =========================================================================
    // Private helpers – PKCE
    // =========================================================================

    private String generateCodeVerifier() {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
    }

    private String computeCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    // =========================================================================
    // Private helpers – Client assertion JWT
    // =========================================================================

    /**
     * Builds a signed JWT used as the client credential (private_key_jwt method).
     * The audience is the token endpoint base (without "/token").
     */
    private String generateClientAssertionJwt(String clientId, String tokenEndpoint) throws Exception {
        long now      = System.currentTimeMillis();
        String keyAlias  = getAuthenticatorConfig().getParameterMap().get(PARAM_KEY_ALIAS);
        String audience  = tokenEndpoint.replace("/token", "");

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(audience)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + JWT_TTL_MS))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(JOSEObjectType.JWT)
                        .keyID(keyAlias)
                        .build(),
                claims
        );
        jwt.sign(new ECDSASigner(getSigningKey()));
        return jwt.serialize();
    }

    // =========================================================================
    // Private helpers – DPoP
    // =========================================================================

    /** Generates a fresh EC key pair on the P-256 curve for use as a DPoP key. */
    private KeyPair generateEphemeralKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(EC_CURVE));
        return kpg.generateKeyPair();
    }

    /**
     * Builds a DPoP proof JWT for the given HTTP method and endpoint URI.
     *
     * <p>The public key is embedded in the JWT header as a JWK so the server
     * can verify possession without a prior key registration.
     */
    private String generateDPoP(String endpoint, String method, KeyPair keyPair) throws Exception {
        long nowSec = System.currentTimeMillis() / 1000;

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htu", endpoint)
                .claim("htm", method)
                .issueTime(new Date(nowSec * 1000))
                .expirationTime(new Date((nowSec + DPOP_TTL_SEC) * 1000))
                .jwtID(UUID.randomUUID().toString())
                .build();

        ECKey publicJwk = buildPublicEcJwk((ECPublicKey) keyPair.getPublic());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(publicJwk.toPublicJWK())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) keyPair.getPrivate()));
        return jwt.serialize();
    }

    /**
     * Converts a JDK {@link ECPublicKey} to a Nimbus {@link ECKey} (P-256).
     *
     * <p>BigInteger coordinates may carry a leading sign byte; {@link #toUnsignedBytes}
     * normalises them to exactly {@value #EC_COORD_SIZE} bytes.
     */
    private ECKey buildPublicEcJwk(ECPublicKey publicKey) {
        java.security.spec.ECPoint point = publicKey.getW();
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String x = enc.encodeToString(toUnsignedBytes(point.getAffineX(), EC_COORD_SIZE));
        String y = enc.encodeToString(toUnsignedBytes(point.getAffineY(), EC_COORD_SIZE));
        return new ECKey.Builder(Curve.P_256, new Base64URL(x), new Base64URL(y)).build();
    }

    /**
     * Returns {@code value} as a fixed-length unsigned big-endian byte array.
     *
     * <p>{@link BigInteger#toByteArray()} may include a leading 0x00 sign byte
     * when the MSB is set. This method strips or pads to produce exactly
     * {@code size} bytes, which is required by the JWK spec for curve coordinates.
     */
    private byte[] toUnsignedBytes(BigInteger value, int size) {
        byte[] src    = value.toByteArray();
        byte[] result = new byte[size];
        if (src.length >= size) {
            // Copy the least-significant `size` bytes (strips any leading sign byte)
            System.arraycopy(src, src.length - size, result, 0, size);
        } else {
            // Right-align with zero padding
            System.arraycopy(src, 0, result, size - src.length, src.length);
        }
        return result;
    }

    // =========================================================================
    // Private helpers – JWE decryption
    // =========================================================================

    /**
     * Decrypts a JWE-wrapped id_token and returns the inner signed JWT string.
     *
     * <p>MockPass wraps the id_token as: JWE( SignedJWT ).  After ECDH-ES
     * decryption the payload is itself a signed JWT which the framework can
     * verify normally.
     */
    private String decryptIdToken(String encryptedJwt) throws Exception {
        EncryptedJWT jwe = EncryptedJWT.parse(encryptedJwt);
        jwe.decrypt(new ECDHDecrypter(getEncryptionKey()));
        SignedJWT inner = jwe.getPayload().toSignedJWT();
        if (inner == null) {
            throw new IllegalStateException("Decrypted JWE payload is not a SignedJWT");
        }
        return inner.serialize();
    }

    // =========================================================================
    // Private helpers – Key loading (double-checked locking)
    // =========================================================================

    private ECPrivateKey getSigningKey() throws Exception {
        if (signingKey == null) {
            synchronized (this) {
                if (signingKey == null) {
                    Map<String, String> p = getAuthenticatorConfig().getParameterMap();
                    signingKey = loadPrivateKey(
                            p.get(PARAM_SIGNING_KEYSTORE),
                            p.get(PARAM_KEYSTORE_PASSWORD),
                            p.get(PARAM_KEY_ALIAS));
                    LOG.info("Signing key loaded");
                }
            }
        }
        return signingKey;
    }

    private ECPrivateKey getEncryptionKey() throws Exception {
        if (encryptionKey == null) {
            synchronized (this) {
                if (encryptionKey == null) {
                    Map<String, String> p = getAuthenticatorConfig().getParameterMap();
                    encryptionKey = loadPrivateKey(
                            p.get(PARAM_ENCRYPTION_KEYSTORE),
                            p.get(PARAM_ENCRYPTION_KEYSTORE_PASS),
                            p.get(PARAM_ENCRYPTION_KEY_ALIAS));
                    LOG.info("Encryption key loaded");
                }
            }
        }
        return encryptionKey;
    }

    /**
     * Loads an EC private key from a PKCS12 keystore on the local filesystem.
     *
     * @param keystoreFile path relative to {@code carbon.home}
     * @param password     keystore and key password
     * @param alias        key alias within the keystore
     */
    private ECPrivateKey loadPrivateKey(String keystoreFile, String password, String alias)
            throws Exception {

        String carbonHome  = System.getProperty("carbon.home");
        String keystorePath = carbonHome + keystoreFile;
        LOG.info("Loading keystore: " + keystorePath + " alias=" + alias);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
            Key key = ks.getKey(alias, password.toCharArray());
            if (!(key instanceof ECPrivateKey)) {
                throw new IllegalStateException(
                        "Key '" + alias + "' in " + keystorePath + " is not an ECPrivateKey");
            }
            return (ECPrivateKey) key;
        }
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    /** URL-encodes a value using UTF-8. */
    private static String encode(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
    }
}