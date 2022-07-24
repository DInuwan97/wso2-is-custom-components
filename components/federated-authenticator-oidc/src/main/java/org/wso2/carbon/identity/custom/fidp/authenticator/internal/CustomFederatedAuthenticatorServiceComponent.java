package org.wso2.carbon.identity.custom.fidp.authenticator.internal;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.custom.fidp.authenticator.CustomAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "custom.federated.authenticator",
        immediate = true
)
public class CustomFederatedAuthenticatorServiceComponent {
    private static final Log LOG = LogFactory.getLog(CustomFederatedAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CustomAuthenticator customAuthenticator = new CustomAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customAuthenticator, null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Custom Federated Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            LOG.fatal(" Error while activating Custom federated authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Custom federated Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the Realm Service");
        }
        DataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("UnSetting the Realm Service");
        }
        DataHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "claim.manager.listener.service",
            service = ClaimMetadataManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetClaimManagementService"
    )
    protected void setClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        DataHolder.getInstance()
                .setClaimMetadataManagementService(claimMetadataManagementService);
    }

    protected void unsetClaimManagementService(ClaimMetadataManagementService claimMetadataManagementService) {

        DataHolder.getInstance()
                .setClaimMetadataManagementService(null);
    }
}
