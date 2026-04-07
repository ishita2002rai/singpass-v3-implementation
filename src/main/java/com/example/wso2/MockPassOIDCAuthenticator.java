package com.example.wso2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.Curve;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectAuthenticator;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;



import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

public class MockPassOIDCAuthenticator extends OpenIDConnectAuthenticator {

    private static final Log LOG = LogFactory.getLog(MockPassOIDCAuthenticator.class);
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String EPHEMERAL_KEY = "EPHEMERAL_KEY";

    private ECPrivateKey signingKey;
    private ECPrivateKey encryptionKey;

    @Override
    public String getName() {
        return "MockPassOIDCAuthenticator";
    }

    @Override
    public String getFriendlyName() {
        return "MockPass OIDC Authenticator";
    }

// ================= KEY LOADING =================

    private ECPrivateKey getPrivateKey() throws Exception {
        if (signingKey == null) {
            LOG.info("Loading signing key");
            Map<String, String> props = getAuthenticatorConfig().getParameterMap();
            signingKey = loadPrivateKey(
                    props.get("signing_keystore"),
                    props.get("keystore_password"),
                    props.get("key_alias")
            );
        }
        return signingKey;
    }

    @Override
    protected OAuthClientRequest getAccessTokenRequest(
            AuthenticationContext context,
            OAuthAuthzResponse authzResponse)
            throws AuthenticationFailedException {


        try {
            LOG.error("STEP 6: Building TOKEN request");

            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);
            String callback = getCallbackUrl(props, context);

            // PKCE
            String codeVerifier = (String) context.getProperty("CODE_VERIFIER");
            LOG.error("code_verifier: " + codeVerifier);

            // Client Assertion
            String clientAssertion = generateJWT(clientId, tokenEndpoint);


            OAuthClientRequest.TokenRequestBuilder builder =
                    OAuthClientRequest.tokenLocation(tokenEndpoint)
                            .setGrantType(GrantType.AUTHORIZATION_CODE)
                            .setRedirectURI(callback)
                            .setCode(authzResponse.getCode());

            builder.setClientId(clientId);
            builder.setParameter("client_assertion_type", CLIENT_ASSERTION_TYPE);
            builder.setParameter("client_assertion", clientAssertion);

            // PKCE
            builder.setParameter("code_verifier", codeVerifier);

            OAuthClientRequest request = builder.buildBodyMessage();

            // 🔐 DPoP
            java.security.KeyPair keyPair =
                    (java.security.KeyPair) context.getProperty(EPHEMERAL_KEY);

            String dpop = generateDPoP(tokenEndpoint, "POST", keyPair);
            request.addHeader("DPoP", dpop);

            LOG.info("TOKEN REQUEST READY");

            return request;

        } catch (Exception e) {
            LOG.error("TOKEN REQUEST FAILED", e);
            throw new AuthenticationFailedException("Token request failed", e);
        }


    }


    private ECPrivateKey getEncryptionPrivateKey() throws Exception {
        if (encryptionKey == null) {
            LOG.error("🔑 Loading encryption key");
            Map<String, String> props = getAuthenticatorConfig().getParameterMap();
            encryptionKey = loadPrivateKey(
                    props.get("encryption_keystore"),
                    props.get("encryption_keystore_password"),
                    props.get("encryption_key_alias")
            );
        }
        return encryptionKey;
    }

    private ECPrivateKey loadPrivateKey(String keystoreFile, String password, String alias) throws Exception {
        String carbonHome = System.getProperty("carbon.home");
        String keystorePath = carbonHome + keystoreFile;

        LOG.error("Loading keystore from: " + keystorePath);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, password.toCharArray());
            return (ECPrivateKey) keyStore.getKey(alias, password.toCharArray());
        }
    }

// ================= JWT =================

    private String generateJWT(String clientId, String tokenEndpoint) throws Exception {

        LOG.info("Generating client assertion JWT");

        long now = System.currentTimeMillis();
        String audience = tokenEndpoint.replace("/token", "");

        String keyAlias = getAuthenticatorConfig()
                .getParameterMap()
                .get("key_alias");


        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(audience)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 300000))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(keyAlias).build(),
                claims
        );

        jwt.sign(new ECDSASigner(getPrivateKey()));


        return jwt.serialize();
    }

// ================= DPoP =================

    private java.security.KeyPair generateEphemeralKeyPair() throws Exception {
        LOG.info("Generating ephemeral key");
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("EC");
        kpg.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private byte[] toUnsignedBytes(BigInteger value, int size) {
        byte[] bytes = value.toByteArray();

        if (bytes.length == size) {
            return bytes;
        }

        byte[] result = new byte[size];

        if (bytes.length > size) {
            // remove leading zero
            System.arraycopy(bytes, bytes.length - size, result, 0, size);
        } else {
            // pad with zeros
            System.arraycopy(bytes, 0, result, size - bytes.length, bytes.length);
        }

        return result;
    }

    private String generateDPoP(String endpoint, String method, java.security.KeyPair keyPair) throws Exception {

        LOG.info("Generating DPoP for: " + endpoint);

        long now = System.currentTimeMillis() / 1000; // seconds

        // ================= CLAIMS =================
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("htu", endpoint)
                .claim("htm", method)
                .issueTime(new Date(now * 1000)) // iat
                .expirationTime(new Date((now + 120) * 1000))
                .jwtID(UUID.randomUUID().toString())
                .build();

        // ================= BUILD JWK =================
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        java.security.spec.ECPoint point = publicKey.getW();

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

        String x = encoder.encodeToString(toUnsignedBytes(point.getAffineX(), 32));
        String y = encoder.encodeToString(toUnsignedBytes(point.getAffineY(), 32));

        ECKey jwk = new ECKey.Builder(
                Curve.P_256,
                new Base64URL(x),
                new Base64URL(y)
        ).build();

        LOG.info("JWK: " + jwk.toJSONObject());

        // ================= HEADER =================

//        Map<String, Object> jwkMap = new HashMap<>();
//        jwkMap.put("kty", "EC");
//        jwkMap.put("crv", "P-256");
//        jwkMap.put("x", x);
//        jwkMap.put("y", y);
//
//        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
//                .type(new JOSEObjectType("dpop+jwt"))
//                .customParam("jwk", jwkMap)
//                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(jwk)
                .build();

        LOG.info("HEADER: " + header.toJSONObject());

        // ================= SIGN =================
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) keyPair.getPrivate()));

        String token = jwt.serialize();

        LOG.info("FINAL DPoP TOKEN: " + token);

        // Debug decode
        String decodedHeader = new String(
                Base64.getUrlDecoder().decode(token.split("\\.")[0]),
                StandardCharsets.UTF_8
        );
        LOG.info("DECODED HEADER: " + decodedHeader);

        return token;
    }



    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = super.getConfigurationProperties();

        if (properties == null) {
            properties = new ArrayList<>();
        }

        Property par = new Property();
        par.setName("par_endpoint");
        par.setDisplayName("PAR Endpoint");
        par.setRequired(true);
        par.setDescription("Pushed Authorization Request endpoint for FAPI flow");

        properties.add(par);

        return properties;
    }


// ================= PAR FLOW =================

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        LOG.info("STEP 1: V3 FLOW STARTED");

        try {
            Map<String, String> props = context.getAuthenticatorProperties();

            String clientId = props.get(OIDCAuthenticatorConstants.CLIENT_ID);
            String parEndpoint = props.get("par_endpoint");
            String authEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_AUTHZ_URL);
            String tokenEndpoint = props.get(OIDCAuthenticatorConstants.OAUTH2_TOKEN_URL);

            LOG.info("PAR endpoint: " + parEndpoint);
            LOG.info("AUTH endpoint: " + authEndpoint);

            String callback = getCallbackUrl(props, context);
            LOG.info("Callback: " + callback);

            // Generate ephemeral key pair for DPoP
            java.security.KeyPair keyPair = generateEphemeralKeyPair();
            context.setProperty(EPHEMERAL_KEY, keyPair);

            // Generate DPoP and client assertion
            String dpop = generateDPoP(parEndpoint, "POST", keyPair);
            String clientAssertion = generateJWT(clientId, tokenEndpoint);
            LOG.info("CLIENT ASSERTION: " + clientAssertion);
            // Generate state and nonce
            String state = UUID.randomUUID().toString();
            String nonce = UUID.randomUUID().toString();
            context.setProperty("STATE", state);
            context.setProperty("NONCE", nonce);

            // Generate PKCE code verifier and challenge
            String codeVerifier = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(UUID.randomUUID().toString().getBytes());

            context.setProperty("CODE_VERIFIER", codeVerifier);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));

            String codeChallenge = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);

            // Build PAR request body
            String body =
                    "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8.toString()) +
                            "&redirect_uri=" + URLEncoder.encode(callback, StandardCharsets.UTF_8.toString()) +
                            "&response_type=code" +
                            "&scope=" + URLEncoder.encode("openid uinfin", StandardCharsets.UTF_8.toString()) +
                            "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8.toString()) +
                            "&nonce=" + URLEncoder.encode(nonce, StandardCharsets.UTF_8.toString()) +
                            "&code_challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8.toString()) +
                            "&code_challenge_method=S256" +
                            "&client_assertion_type=" + URLEncoder.encode(CLIENT_ASSERTION_TYPE, StandardCharsets.UTF_8.toString()) +
                            "&client_assertion=" + clientAssertion;

            LOG.info("PAR BODY: " + body);

            // Make PAR request
            HttpURLConnection conn = (HttpURLConnection) new URL(parEndpoint).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            System.out.println("DPoP HEADER BEING SENT: " + dpop);
            conn.setRequestProperty("DPoP", dpop);

            // Convert body to bytes using UTF-8
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", String.valueOf(bodyBytes.length));

            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }

            int status = conn.getResponseCode();
            LOG.info("PAR RESPONSE CODE: " + status);

            InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream();

            BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder responseStr = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                responseStr.append(line);
            }
            br.close();

            LOG.info("PAR RESPONSE: " + responseStr);

            if (status >= 400) {
                throw new RuntimeException("PAR failed: " + responseStr);
            }

            org.json.JSONObject json = new org.json.JSONObject(responseStr.toString());
            String requestUri = json.getString("request_uri");

            LOG.info("request_uri: " + requestUri);

            // Redirect to auth endpoint with both client_id and request_uri
            String authUrl = authEndpoint +
                    "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8.toString()) +
                    "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8.toString());

            LOG.info("Redirecting to AUTH: " + authUrl);

            response.sendRedirect(authUrl);

        } catch (Exception e) {
            LOG.error("PAR FLOW FAILED", e);
            throw new AuthenticationFailedException("PAR failed", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        LOG.error("STEP 5: Processing authentication response");

        String sentState = (String) context.getProperty("STATE");
        String returnedState = request.getParameter("state");

        LOG.error("🔍 STATE SENT: " + sentState);
        LOG.error("🔍 STATE RETURNED: " + returnedState);

        // Optional validation
        if (sentState != null && !sentState.equals(returnedState)) {
            throw new AuthenticationFailedException("State mismatch!");
        }

        // VERY IMPORTANT → continue default flow
        super.processAuthenticationResponse(request, response, context);
    }

    @Override
    protected OAuthClientResponse requestAccessToken(
            HttpServletRequest request,
            AuthenticationContext context)
            throws AuthenticationFailedException {

        OAuthClientResponse tokenResponse = super.requestAccessToken(request, context);

        String idToken = tokenResponse.getParam("id_token");

        if (idToken != null) {
            try {
                EncryptedJWT jwt = EncryptedJWT.parse(idToken);
                jwt.decrypt(new ECDHDecrypter(getEncryptionPrivateKey()));

                context.setProperty(
                        OIDCAuthenticatorConstants.ID_TOKEN,
                        jwt.getPayload().toSignedJWT().serialize()
                );

            } catch (Exception e) {
                throw new AuthenticationFailedException("Decryption failed", e);
            }
        }

        return tokenResponse;
    }




}
