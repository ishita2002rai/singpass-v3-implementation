package com.example.wso2;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;

import java.io.FileReader;
import java.security.interfaces.RSAPrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

public class JWTUtil {

    public static String generateClientAssertion(String clientId, String tokenEndpoint) throws Exception {

        long now = System.currentTimeMillis();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(tokenEndpoint)
                .issueTime(new Date(now))
                .expirationTime(new Date(now + 300000)) // 5 minutes
                .jwtID(UUID.randomUUID().toString())
                .build();

        RSAPrivateKey privateKey = loadPrivateKey("PRIVATE_KEY_PATH");

        JWSSigner signer = new RSASSASigner(privateKey);

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claims
        );

        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    private static RSAPrivateKey loadPrivateKey(String path) throws Exception {

        String key = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(path)));

        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) kf.generatePrivate(spec);
    }
}