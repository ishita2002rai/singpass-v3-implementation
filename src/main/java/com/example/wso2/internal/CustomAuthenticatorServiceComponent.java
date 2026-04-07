package com.example.wso2.internal;

import com.example.wso2.MockPassOIDCAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;

@Component(
        name = "mockpass.oidc.authenticator.component",
        immediate = true
)
public class CustomAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);
    private ServiceRegistration<ApplicationAuthenticator> serviceRegistration;

    @Activate
    protected void activate(ComponentContext ctxt) {
        System.out.println("-----ACTIVATED--------");
        try {
            MockPassOIDCAuthenticator authenticator = new MockPassOIDCAuthenticator();

            serviceRegistration = ctxt.getBundleContext()
                    .registerService(ApplicationAuthenticator.class, authenticator, null);

            log.info("Custom Authenticator bundle activated successfully");

        } catch (Exception e) {
            log.error("Error while activating custom federated authenticator", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }

        log.info("Custom Authenticator bundle deactivated");
    }
}