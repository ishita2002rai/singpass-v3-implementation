package com.example.wso2.servlet;

import com.example.wso2.MockPassConstants;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Servlet that serves the JWKS (JSON Web Key Set) document at
 * {@code /mockpass/jwks.json}, allowing MockPass (Singpass v3) to fetch
 * the client's public keys for signature verification and ID token encryption.
 *
 * <p>Registered via OSGi {@code HttpService} in
 * {@link com.example.wso2.internal.CustomAuthenticatorServiceComponent#activate},
 * following the same pattern used by WSO2's own
 * {@code CommonAuthenticationServlet}.
 *
 * <p>The JWKS JSON file is read from the filesystem at:
 * <pre>
 *     ${carbon.home}/mockpassKeys/jwks.json
 * </pre>
 *
 * <p>MockPass uses the public keys in this document to:
 * <ul>
 *   <li>Verify the {@code client_assertion} JWT signature sent at the PAR
 *       and token endpoints.</li>
 *   <li>Encrypt the ID token returned to the client using the registered
 *       encryption public key.</li>
 * </ul>
 */
public class JwksServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    /**
     * Handles HTTP GET requests by reading {@code jwks.json} from the
     * filesystem and writing its contents directly to the HTTP response.
     *
     * <p>The full path is resolved by combining the {@code carbon.home}
     * system property with {@link MockPassConstants#JWKS_FILE_PATH}:
     * <pre>
     *     carbon.home + /mockpassKeys/jwks.json
     * </pre>
     *
     * @param request  the incoming {@link HttpServletRequest}.
     * @param response the {@link HttpServletResponse} to write the JWKS JSON into.
     * @throws IOException if the JWKS file cannot be read or the response
     *                     stream cannot be written.
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String jwksPath = System.getProperty(MockPassConstants.SYSTEM_PROPERTY_CARBON_HOME)
                + MockPassConstants.JWKS_FILE_PATH;

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        try (InputStream in = Files.newInputStream(Paths.get(jwksPath));
             OutputStream out = response.getOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
        }
    }
}