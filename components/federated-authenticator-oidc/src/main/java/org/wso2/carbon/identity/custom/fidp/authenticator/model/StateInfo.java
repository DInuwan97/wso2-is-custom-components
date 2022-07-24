package org.wso2.carbon.identity.custom.fidp.authenticator.model;

import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStateInfo;

public class StateInfo extends AuthenticatorStateInfo {

    private String idTokenHint;

    public void setIdTokenHint(String idTokenHint) {

        this.idTokenHint = idTokenHint;
    }

    public String getIdTokenHint() {

        return idTokenHint;
    }
}
