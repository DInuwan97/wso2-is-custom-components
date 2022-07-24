package org.wso2.carbon.identity.custom.fidp.authenticator.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;


public class CustomAuthnFailedException  extends AuthenticationFailedException {
    public CustomAuthnFailedException(String message){
        super(message);
    }

    public CustomAuthnFailedException(String message, String e){
        super(message,e);
    }

    public CustomAuthnFailedException(String message, Throwable cause){
        super(message,cause);
    }

    public CustomAuthnFailedException(String code, String message, Throwable cause){
        super(code, message,cause);
    }
}
