package com.example.wso2.utils;

import com.example.wso2.MockPassConstants;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

/**
 * Stateless cryptographic and encoding utility methods for the MockPass OIDC authenticator.
 *
 * <p>All methods are {@code public static}. This class must not be instantiated.
 */
public final class MockPassUtils {

    private static final Log LOG = LogFactory.getLog(MockPassUtils.class);

    private MockPassUtils() {
        // Utility class – do not instantiate.
    }
    /**
     * Generates a cryptographically random PKCE code verifier using 32 bytes from
     * {@link SecureRandom}, Base64url-encoded without padding per RFC 7636.
     *
     * @return a URL-safe, unpadded Base64 string suitable for use as a PKCE code verifier.
     */
    public static String generateCodeVerifier() {

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes        = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }

    /**
     * Computes the PKCE S256 code challenge by SHA-256 hashing the code verifier and
     * Base64url-encoding the result without padding, per RFC 7636 §4.2.
     *
     * @param codeVerifier the plain-text PKCE code verifier.
     * @return the URL-safe, unpadded Base64 SHA-256 hash of the verifier.
     * @throws NoSuchAlgorithmException if the SHA-256 algorithm is unavailable on this JVM.
     */
    public static String computeCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {

        byte[] hash = MessageDigest.getInstance(MockPassConstants.HASH_ALGORITHM_SHA256)
                .digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Generates a fresh ephemeral EC key pair on the P-256 curve for use as the DPoP key
     * for a single authentication session.
     *
     * @return a {@link KeyPair} containing the ephemeral P-256 public and private keys.
     * @throws GeneralSecurityException if the EC algorithm is unavailable or the P-256 curve
     *                                   spec is invalid.
     */
    public static KeyPair generateEphemeralKeyPair() throws GeneralSecurityException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(MockPassConstants.KEY_ALGORITHM_EC);
        kpg.initialize(new ECGenParameterSpec(MockPassConstants.EC_CURVE));
        return kpg.generateKeyPair();
    }

    /**
     * Builds a DPoP proof JWT for the given HTTP method and endpoint URI per RFC 9449.
     *
     * <p>The ephemeral public key is embedded in the {@code jwk} header claim so the
     * server can verify possession without prior key registration. A unique {@code jti}
     * and short expiry prevent replay attacks.
     *
     * @param endpoint the URI of the HTTP endpoint the DPoP proof is bound to.
     * @param method   the HTTP method the proof is bound to (e.g., {@code "POST"}).
     * @param keyPair  the session-scoped ephemeral key pair.
     * @return the compact-serialized DPoP proof JWT string.
     * @throws JOSEException if JWT signing or JWK construction fails.
     */
    public static String generateDPoP(String endpoint, String method, KeyPair keyPair)
            throws JOSEException {

        long nowSec = System.currentTimeMillis() / 1000;

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim(MockPassConstants.CLAIM_HTU, endpoint)
                .claim(MockPassConstants.CLAIM_HTM, method)
                .issueTime(new Date(nowSec * 1000))
                .expirationTime(new Date((nowSec + MockPassConstants.DPOP_TTL_SEC) * 1000))
                .jwtID(UUID.randomUUID().toString())
                .build();

        ECKey publicJwk = buildPublicEcJwk((ECPublicKey) keyPair.getPublic());

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(MockPassConstants.DPOP_JWT_TYPE))
                .jwk(publicJwk.toPublicJWK())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) keyPair.getPrivate()));
        return jwt.serialize();
    }

    /**
     * Builds and signs a private_key_jwt client assertion per RFC 7523.
     *
     * <p>The JWT is signed with the provided EC private key. The audience is derived from
     * the token endpoint by stripping the trailing {@code /token} path segment.
     *
     * @param clientId      the OAuth client identifier used as both {@code iss} and {@code sub}.
     * @param tokenEndpoint the full token endpoint URL; the audience is set to its base path.
     * @param keyAlias      the alias of the signing key, embedded in the JWT {@code kid} header.
     * @param signingKey    the EC private key used to sign the assertion.
     * @return the compact-serialized signed JWT string.
     * @throws JOSEException if JWT signing fails.
     */
    public static String generateClientAssertionJwt(String clientId,
                                                    String tokenEndpoint,
                                                    String keyAlias,
                                                    ECPrivateKey signingKey)
            throws JOSEException {

        long now      = System.currentTimeMillis();

        String audience = tokenEndpoint.endsWith(MockPassConstants.TOKEN_PATH_SEGMENT)
                ? tokenEndpoint.substring(0, tokenEndpoint.length() - MockPassConstants.TOKEN_PATH_SEGMENT.length())
                : tokenEndpoint;

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(audience)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + MockPassConstants.JWT_TTL_MS))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(JOSEObjectType.JWT)
                        .keyID(keyAlias)
                        .build(),
                claims
        );
        jwt.sign(new ECDSASigner(signingKey));
        return jwt.serialize();
    }

    /**
     * Loads an EC private key from a PKCS12 keystore located on the local filesystem,
     * resolved relative to the {@code carbon.home} system property.
     *
     * @param keystoreFile the keystore file path relative to {@code carbon.home}
     *                     (e.g., {@code "/repository/resources/security/singpass-ec.p12"}).
     * @param password     the keystore password; also used as the key entry password.
     * @param alias        the alias of the key entry within the keystore.
     * @return the {@link ECPrivateKey} stored under the given alias.
     * @throws GeneralSecurityException if the keystore cannot be instantiated or loaded, the key
     *                                   cannot be recovered with the provided password, or the
     *                                   recovered key is not an {@link ECPrivateKey}.
     * @throws IOException              if the keystore file cannot be opened or read.
     */
    public static ECPrivateKey loadPrivateKey(String keystoreFile,
                                              String password,
                                              String alias)
            throws GeneralSecurityException, IOException {

        String carbonHome   = System.getProperty(MockPassConstants.SYSTEM_PROPERTY_CARBON_HOME);
        String keystorePath = carbonHome + keystoreFile;

        if (LOG.isDebugEnabled()) {
            LOG.debug("[MockPass] Loading keystore: " + keystorePath + ", alias=" + alias);
        }

        KeyStore ks = KeyStore.getInstance(MockPassConstants.KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
            Key key = ks.getKey(alias, password.toCharArray());
            if (!(key instanceof ECPrivateKey)) {
                throw new GeneralSecurityException(
                        "Key '" + alias + "' in " + keystorePath + " is not an ECPrivateKey");
            }
            return (ECPrivateKey) key;
        }
    }

    /**
     * Converts a JDK {@link ECPublicKey} to a Nimbus {@link ECKey} on the P-256 curve
     * using Nimbus built-in key construction.
     *
     * @param publicKey the JDK EC public key to convert.
     * @return a Nimbus {@link ECKey} containing the public key components.
     * @throws JOSEException if the key cannot be converted.
     */
    public static ECKey buildPublicEcJwk(ECPublicKey publicKey) throws JOSEException {
        return new ECKey.Builder(Curve.P_256, publicKey).build();
    }

    /**
     * URL-encodes a string value using UTF-8 encoding.
     *
     * @param value the raw string to encode.
     * @return the URL-encoded representation of {@code value}.
     */
    public static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}