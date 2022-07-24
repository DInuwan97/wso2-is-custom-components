package org.wso2.carbon.identity.custom.fidp.authenticator;

public class CustomAuthenticatorConstants {
    public static final String FEDERATED_IDP_COMPONENT_NAME = "CustomAuthenticator";
    public static final String FEDERATED_IDP_COMPONENT_FRIENDLY_NAME = "CustomFIDP";
    public static final String LOGIN_TYPE = "OIDC";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String ID_TOKEN = "id_token";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String CALLBACK_URL = "callbackUrl";
    public static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";
    public static final String SCOPE = "scope";
    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String ID_TOKEN_HINT = "id_token_hint";
    public static final String HTTP_ORIGIN_HEADER = "Origin";
    public static final String LOGOUT_ENABLE = "IsLogoutEnable";
    public static final String SUB = "sub";
    public static final String OIDC_DIALECT = "http://wso2.org/oidc/claim";
    public static final String[] NON_USER_ATTRIBUTES = new String[]{"at_hash", "iss", "iat", "exp", "aud", "azp"};
    public static final String OAUTH2_ERROR = "error";

    public static class EndpointsKeys {
        public static final String AUTHZ_ENDPOINT_KEY = "AuthzEndpoint";
        public static final String TOKEN_ENDPOINT_KEY = "TokenEndpoint";
        public static final String USER_INFO_ENDPOINT_KEY = "UserInfoEndpoint";
        public static final String LOGOUT_ENDPOINT_KEY = "LogoutEndpoint";
    }


}
