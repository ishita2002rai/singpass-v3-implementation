package com.example.wso2.internal;

import com.example.wso2.MockPassConstants;
import com.example.wso2.MockPassOIDCAuthenticator;
import com.example.wso2.servlet.JwksServlet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;

import javax.servlet.Servlet;

/**
 * OSGi Declarative Services component that activates the MockPass OIDC
 * authenticator bundle.
 *
 * <p>On activation this component:
 * <ol>
 *   <li>Registers {@link MockPassOIDCAuthenticator} as an
 *       {@link ApplicationAuthenticator} OSGi service, making it visible to
 *       WSO2's authentication framework.</li>
 *   <li>Registers {@link JwksServlet} via the OSGi {@link HttpService} at
 *       {@code /mockpass/jwks.json}, serving the client's public JWKS so
 *       MockPass (Singpass v3) can fetch it without an external HTTP server.</li>
 * </ol>
 *
 * <p>{@link HttpService} is injected by OSGi DS via {@link #setHttpService}
 * before {@link #activate} fires — the same pattern used by WSO2's own
 * {@code FrameworkServiceComponent} to register {@code CommonAuthenticationServlet}.
 */
@Component(
        name = "mockpass.oidc.authenticator.component",
        immediate = true
)
public class CustomAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    /**
     * OSGi service registration handle for the {@link MockPassOIDCAuthenticator}.
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
     * @param ctxt the OSGi {@link ComponentContext} providing the
     *             {@link BundleContext} for service registration.
     */
    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            BundleContext bundleContext = ctxt.getBundleContext();

            MockPassOIDCAuthenticator authenticator = new MockPassOIDCAuthenticator();
            serviceRegistration = bundleContext
                    .registerService(ApplicationAuthenticator.class, authenticator, null);
            log.info("[MockPass] Authenticator registered successfully");

            Servlet jwksServlet = new ContextPathServletAdaptor(
                    new JwksServlet(), MockPassConstants.JWKS_SERVLET_URL);
            httpService.registerServlet(
                    MockPassConstants.JWKS_SERVLET_URL, jwksServlet, null, null);
            log.info("[MockPass] JWKS servlet registered at: " + MockPassConstants.JWKS_SERVLET_URL);

        } catch (Exception e) {
            log.error("[MockPass] Error while activating MockPass authenticator bundle", e);
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
            httpService.unregister(MockPassConstants.JWKS_SERVLET_URL);
        }
        log.info("[MockPass] MockPass authenticator bundle deactivated");
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