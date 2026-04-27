package com.example.wso2.servlet;

import com.example.wso2.MockPassConstants;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet that dynamically builds and serves the JWKS (JSON Web Key Set) document
 * at {@code /mockpass/jwks.json} by loading public keys directly from the configured
 * PKCS12 keystore.
 *
 * <p>On each GET request this servlet:
 * <ol>
 *   <li>Loads the keystore from {@code ${carbon.home}} + the configured keystore path.</li>
 *   <li>Extracts the signing public key under the configured signing alias.</li>
 *   <li>Extracts the encryption public key under the configured encryption alias.</li>
 *   <li>Converts both to JWK format using Nimbus JOSE.</li>
 *   <li>Returns the combined JWKS JSON response.</li>
 * </ol>
 *
 * <p>The keystore path, password, and key aliases are passed via constructor by
 * {@link com.example.wso2.internal.CustomAuthenticatorServiceComponent}, which reads
 * them from {@code deployment.toml} using {@code FileBasedConfigurationBuilder}.
 * This eliminates hardcoded values and keeps the servlet in sync with the
 * authenticator configuration.
 *
 * <p>Registered via OSGi {@code HttpService} in
 * {@link com.example.wso2.internal.CustomAuthenticatorServiceComponent#activate},
 * following the same pattern as WSO2's own {@code CommonAuthenticationServlet}.
 */
public class JwksServlet extends HttpServlet {

    private static final Log LOG = LogFactory.getLog(JwksServlet.class);
    private static final long serialVersionUID = 1L;

    private final String keystorePath;
    private final String keystorePassword;
    private final String sigAlias;
    private final String encAlias;

    public JwksServlet(String keystorePath, String keystorePassword,
                       String sigAlias, String encAlias) {
        this.keystorePath     = keystorePath;
        this.keystorePassword = keystorePassword;
        this.sigAlias         = sigAlias;
        this.encAlias         = encAlias;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        try {
            String carbonHome = System.getProperty(MockPassConstants.SYSTEM_PROPERTY_CARBON_HOME);

            KeyStore keyStore = KeyStore.getInstance(MockPassConstants.KEYSTORE_TYPE);
            try (FileInputStream fis = new FileInputStream(carbonHome + keystorePath)) {
                keyStore.load(fis, keystorePassword.toCharArray());
            }

            ECPublicKey sigPublicKey = (ECPublicKey) keyStore
                    .getCertificate(sigAlias).getPublicKey();
            ECKey sigJwk = new ECKey.Builder(Curve.P_256, sigPublicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(sigAlias)
                    .algorithm(new com.nimbusds.jose.Algorithm(MockPassConstants.SIG_ALGORITHM))
                    .build();

            ECPublicKey encPublicKey = (ECPublicKey) keyStore
                    .getCertificate(encAlias).getPublicKey();
            ECKey encJwk = new ECKey.Builder(Curve.P_256, encPublicKey)
                    .keyUse(KeyUse.ENCRYPTION)
                    .keyID(encAlias)
                    .algorithm(new com.nimbusds.jose.Algorithm(MockPassConstants.ENC_ALGORITHM))
                    .build();

            JSONArray keys = new JSONArray();
            keys.put(new JSONObject(sigJwk.toJSONObject()));
            keys.put(new JSONObject(encJwk.toJSONObject()));

            JSONObject jwks = new JSONObject();
            jwks.put("keys", keys);
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter writer = response.getWriter();
            writer.write(jwks.toString());
            writer.flush();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            LOG.error("[MockPass] Failed to load keystore or certificates for JWKS generation", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to load keystore");
        } catch (IOException e) {
            LOG.error("[MockPass] Failed to read keystore file for JWKS generation", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to read keystore");
        }
    }
}
