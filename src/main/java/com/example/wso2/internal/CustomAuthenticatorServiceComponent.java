package com.example.wso2.internal;

import com.example.wso2.SingpassConstants;
import com.example.wso2.SingpassV3OIDCAuthenticator;
import com.example.wso2.servlet.JwksServlet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;

import java.util.Map;

import javax.servlet.Servlet;


/**
 * OSGi Declarative Services component that activates the Singpass OIDC
 * authenticator bundle.
 *
 * <p>On activation this component:
 * <ol>
 *   <li>Registers {@link SingpassV3OIDCAuthenticator} as an
 *       {@link ApplicationAuthenticator} OSGi service, making it visible to
 *       WSO2's authentication framework.</li>
 *   <li>Reads keystore configuration from {@code deployment.toml} via
 *       {@link FileBasedConfigurationBuilder} and passes it to {@link JwksServlet}
 *       so public keys are served dynamically from the keystore without a static file.</li>
 *   <li>Registers {@link JwksServlet} via the OSGi {@link HttpService} at
 *       {@code /singpass/jwks.json}, serving the client's public JWKS so
 *       Singpass (Singpass v3) can fetch it without an external HTTP server.</li>
 * </ol>
 *
 * <p>{@link HttpService} is injected by OSGi DS via {@link #setHttpService}
 * before {@link #activate} fires — the same pattern used by WSO2's own
 * {@code FrameworkServiceComponent} to register {@code CommonAuthenticationServlet}.
 */
@Component(
        name = "singpass.oidc.authenticator.component",
        immediate = true
)
public class CustomAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    /**
     * OSGi service registration handle for the {@link SingpassV3OIDCAuthenticator}.
     * Retained so the service can be cleanly unregistered on bundle deactivation.
     */
    private ServiceRegistration<ApplicationAuthenticator> serviceRegistration;

    /**
     * OSGi {@link HttpService} injected by Declarative Services before
     * {@link #activate} is called. Used to register and later unregister
     * the {@link JwksServlet}.
     */
    private HttpService httpService;

    /**
     * Activates the bundle by registering the authenticator service and the
     * JWKS servlet.
     *
     * <p><b>Execution order:</b>
     * <ol>
     *   <li>Registers {@link SingpassV3OIDCAuthenticator} as an {@link ApplicationAuthenticator}
     *       OSGi service so WSO2's authentication framework can discover it.</li>
     *   <li>Reads keystore configuration ({@code keystore}, {@code keystore_password},
     *       {@code key_alias}, {@code encryption_key_alias}) from {@code deployment.toml}
     *       via {@link FileBasedConfigurationBuilder}.</li>
     *   <li>Registers {@link JwksServlet} via {@link HttpService}, passing the keystore
     *       config via constructor so the servlet can dynamically build the JWKS JSON
     *       from the keystore on each request.</li>
     * </ol>
     *
     * @param ctxt the OSGi {@link ComponentContext} providing the
     *             {@link BundleContext} for service registration.
     */
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            BundleContext bundleContext = ctxt.getBundleContext();

            SingpassV3OIDCAuthenticator authenticator = new SingpassV3OIDCAuthenticator();
            serviceRegistration = bundleContext
                    .registerService(ApplicationAuthenticator.class, authenticator, null);
            log.info("[Singpass] Authenticator registered successfully");


            AuthenticatorConfig config = FileBasedConfigurationBuilder.getInstance()
                    .getAuthenticatorBean(SingpassConstants.AUTHENTICATOR_NAME);

            if (config == null || config.getParameterMap() == null) {
                log.error("[Singpass] Authenticator config not found — JWKS servlet NOT registered");
                return;
            }

            Map<String, String> params  = config.getParameterMap();
            String keystorePath         = params.get(SingpassConstants.PARAM_KEYSTORE);
            String keystorePassword     = params.get(SingpassConstants.PARAM_KEYSTORE_PASSWORD);
            String sigAlias             = params.get(SingpassConstants.PARAM_SIGNING_KEY_ALIAS);
            String encAlias             = params.get(SingpassConstants.PARAM_ENCRYPTION_KEY_ALIAS);

            Servlet jwksServlet = new ContextPathServletAdaptor(
                    new JwksServlet(keystorePath, keystorePassword, sigAlias, encAlias),
                    SingpassConstants.JWKS_SERVLET_URL);
            httpService.registerServlet(
                    SingpassConstants.JWKS_SERVLET_URL, jwksServlet, null, null);
            log.info("[Singpass] JWKS servlet registered at: " + SingpassConstants.JWKS_SERVLET_URL);

        } catch (Exception e) {
            log.error("[Singpass] Error while activating Singpass authenticator bundle", e);
        }
    }

    /**
     * Deactivates the bundle by unregistering the authenticator service and
     * the JWKS servlet path.
     *
     * @param ctxt the OSGi {@link ComponentContext} (not used directly).
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        if (httpService != null) {
            httpService.unregister(SingpassConstants.JWKS_SERVLET_URL);
        }
        log.info("[Singpass] Singpass authenticator bundle deactivated");
    }

    /**
     * Binds the OSGi {@link HttpService} injected by Declarative Services.
     *
     * <p>Declared as {@link ReferenceCardinality#MANDATORY} so the DS runtime
     * guarantees this method is called before {@link #activate} — matching the
     * pattern used by WSO2's {@code FrameworkServiceComponent}.
     *
     * @param httpService the {@link HttpService} instance provided by the
     *                    Equinox HTTP runtime.
     */
    @Reference(
            name = "osgi.httpservice",
            service = HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService"
    )
    protected void setHttpService(HttpService httpService) {
        this.httpService = httpService;
    }

    /**
     * Unbinds the OSGi {@link HttpService} when it is withdrawn.
     *
     * @param httpService the {@link HttpService} instance being withdrawn.
     */
    protected void unsetHttpService(HttpService httpService) {
        this.httpService = null;
    }
}
