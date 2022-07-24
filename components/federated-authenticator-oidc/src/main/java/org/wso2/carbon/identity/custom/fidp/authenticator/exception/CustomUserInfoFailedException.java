package org.wso2.carbon.identity.custom.fidp.authenticator.exception;

public class CustomUserInfoFailedException extends Exception {

    public CustomUserInfoFailedException(String message) {

        super(message);
    }

    public CustomUserInfoFailedException(String message, Throwable cause) {

        super(message, cause);
    }
}
