package org.wso2.carbon.identity.custom.fidp.authenticator;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONArray;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.custom.fidp.authenticator.exception.CustomAuthnFailedException;
import org.wso2.carbon.identity.custom.fidp.authenticator.exception.CustomUserInfoFailedException;
import org.wso2.carbon.identity.custom.fidp.authenticator.internal.DataHolder;
import org.wso2.carbon.identity.custom.fidp.authenticator.model.StateInfo;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * The CustomAuthenticator class contains all the functional tasks handled by the authenticator with External IdP and
 * WSO2 Identity Server, such as obtaining an authorization code and access token, federated logout, claim mapping via
 * both id token and user info and obtaining user input data.
 */
public class CustomAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(CustomAuthenticatorConstants.class);

    /**
     * Checks whether the request and response can be handled by the authenticator.
     *
     * @param request  The request that is received by the authenticator.
     * @return Boolean Whether the request can be handled by the authenticator.
     */
    @Override
    public boolean canHandle(HttpServletRequest request) {

        return CustomAuthenticatorConstants.LOGIN_TYPE.equals(getLoginType(request));
    }

    /**
     * Returns a unique string to identify each request and response separately.
     * This contains the session id, processed by the WSO2 IS.
     *
     * @param request  The request that is received by the authenticator.
     * @return String  Returns the state parameter value that is carried by the request.
     */
    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return null;
    }

    /**
     * Returns the authenticator's name.
     *
     * @return String  The identifier of the authenticator.
     */
    @Override
    public String getName() {

        return CustomAuthenticatorConstants.FEDERATED_IDP_COMPONENT_NAME;
    }

    /**
     * Returns authenticator's friendly name.
     *
     * @return String  The display name of the authenticator.
     */
    @Override
    public String getFriendlyName() {

        return CustomAuthenticatorConstants.FEDERATED_IDP_COMPONENT_FRIENDLY_NAME;
    }

    /**
     * Returns the claim dialect URL.
     * Since authenticator supports OIDC, the dialect URL is OIDC dialect.
     *
     * @return String  The dialect which is supposed to map UAEPass claims.
     */
    @Override
    public String getClaimDialectURI() {

        return CustomAuthenticatorConstants.OIDC_DIALECT;
    }

    public String getLoginType(HttpServletRequest request) {

        String state = request.getParameter(CustomAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (StringUtils.isNotBlank(state)) {
            String[] stateElements = state.split(",");
            if (stateElements.length > 1) {
                return stateElements[1];
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.error("Empty split elements in state");
        }
        return null;
    }

    /**
     * Returns all user input fields of the authenticator.
     *
     * @return List<Property>  Returns the federated authenticator properties
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(CustomAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CustomAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property callbackUrl = new Property();
        callbackUrl.setDisplayName("Callback URL");
        callbackUrl.setRequired(true);
        callbackUrl.setName(CustomAuthenticatorConstants.CALLBACK_URL);
        callbackUrl.setDescription("The callback URL used to partner identity provider credentials.");
        callbackUrl.setType("string");
        callbackUrl.setDisplayOrder(3);
        configProperties.add(callbackUrl);

        Property scopes = new Property();
        scopes.setDisplayName("Scopes");
        scopes.setRequired(true);
        scopes.setName(CustomAuthenticatorConstants.SCOPE);
        scopes.setDescription("Add the required scopes.");
        scopes.setType("string");
        scopes.setDisplayOrder(4);
        configProperties.add(scopes);

        Property logoutEnabled = new Property();
        logoutEnabled.setName(CustomAuthenticatorConstants.LOGOUT_ENABLE);
        logoutEnabled.setDisplayName("If Logout is enabled");
        logoutEnabled.setRequired(false);
        logoutEnabled.setDescription("Check here to enable the logout");
        logoutEnabled.setType("boolean");
        logoutEnabled.setDisplayOrder(5);
        configProperties.add(logoutEnabled);

        return configProperties;
    }

    /**
     * Redirects the user to the login page for authentication purposes. This authenticator redirects the user to the
     * application's login page, which is set up on the UAE Pass side, which works as the external Identity Provider.
     *
     * @param request                          The request that is received by the authenticator.
     * @param response                         Appends the authorized URL once a valid authorized URL is built.
     * @param context                          The Authentication context received by the authenticator.
     * @throws AuthenticationFailedException   Exception while creating the authorization code
     */
    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Authentication Request has initialized");
            }
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            if (authenticatorProperties != null) {

                String clientId = authenticatorProperties.get(CustomAuthenticatorConstants.CLIENT_ID);
                String authorizationEP = getFileConfigValue(CustomAuthenticatorConstants.EndpointsKeys.
                        AUTHZ_ENDPOINT_KEY);
                String callBackUrl = authenticatorProperties.get(CustomAuthenticatorConstants.CALLBACK_URL);
                String state = context.getContextIdentifier() + "," + CustomAuthenticatorConstants.LOGIN_TYPE;
                String scopes = context.getAuthenticatorProperties().get(CustomAuthenticatorConstants.SCOPE);

                OAuthClientRequest authzRequest = OAuthClientRequest
                        .authorizationLocation(authorizationEP)
                        .setClientId(clientId)
                        .setRedirectURI(callBackUrl)
                        .setScope(scopes)
                        .setResponseType(CustomAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                        .setState(state)
                        .buildQueryMessage();

                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authorization request build with must required query parameters.");
                }
                String loginPage = authzRequest.getLocationUri();
                response.sendRedirect(loginPage);
            } else {
                throw new AuthenticationFailedException("Error while retrieving properties. "
                        + "Authenticator Properties cannot be null");
            }

        } catch (IOException e) {
            LOG.error("Authorization request building failed.");
            throw new AuthenticationFailedException("Unable to pick correct env or problem occurred in additional " +
                    "query params when building the authorize request", e);
        } catch (OAuthSystemException e) {
            LOG.error("Unable to build the request with must required query params.");
            throw new AuthenticationFailedException("Exception while building authorization request with must " +
                    "required query params", e);
        }
    }

    /**
     * Implements the logic of user authentication with the FIdP.
     *
     * @param request                         The request that is received by the authenticator.
     * @param response                        The response that is received to the authenticator.
     * @param context                         The Authentication context received by authenticator.
     * @throws AuthenticationFailedException  Exception while creating the access token or id token
     */
    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        try {
            OAuthAuthzResponse authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            OAuthClientRequest accessTokenRequest = getAccessTokenRequest(context, authzResponse);
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = getOAuthResponse(oAuthClient, accessTokenRequest);

            String accessToken = oAuthResponse.getParam(CustomAuthenticatorConstants.ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Access Token is empty");
                }
                throw new AuthenticationFailedException("Access token is empty");
            }

            String idToken = oAuthResponse.getParam(CustomAuthenticatorConstants.ID_TOKEN);

            AuthenticatedUser authenticatedUser;
            Map<String, Object> jsonClaimMap;
            Map<ClaimMapping, String> claims = new HashMap<>();

            if (StringUtils.isNotBlank(idToken)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Id token available from FIdP");
                }

                StateInfo stateInfo = new StateInfo();
                stateInfo.setIdTokenHint(idToken);
                context.setStateInfo(stateInfo);

                context.setProperty(CustomAuthenticatorConstants.ACCESS_TOKEN, accessToken);
                jsonClaimMap = getIdTokenClaims(context, idToken);
            } else {
                jsonClaimMap = getUserInfoUserAttributes(oAuthResponse, context);
            }

            String authenticatedUserId = getAuthenticatedUserId(jsonClaimMap);
            String attributeSeparator = getMultiAttributeSeparator(context, authenticatedUserId);

            jsonClaimMap.entrySet().stream()
                    .filter(entry -> !ArrayUtils.contains(CustomAuthenticatorConstants.
                            NON_USER_ATTRIBUTES, entry.getKey()))
                    .forEach(entry -> buildClaimMappings(claims, entry, attributeSeparator));

            if (StringUtils.isBlank(authenticatedUserId)) {
                throw new AuthenticationFailedException("Cannot find the userId from the id_token sent "
                        + "by the federated IDP.");
            }
            authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier
                    (authenticatedUserId);
            authenticatedUser.setUserAttributes(claims);
            context.setSubject(authenticatedUser);

        } catch (CustomAuthnFailedException e) {
            throw new AuthenticationFailedException("", "", e);
        } catch (CustomUserInfoFailedException e) {
            throw new AuthenticationFailedException("", "", e);
        } catch (OAuthProblemException e) {
            LOG.error("OAuth authorize response failure.");
            throw new AuthenticationFailedException("", "", e);
        }
    }

    /**
     * Logout initialization will be handled by this method.
     *
     * @param request                 The request that is received by the authenticator.
     * @param response                Appends the logout redirect URI once logged out from authenticator.
     * @param context                 The Authentication context received by authenticator.
     * @throws LogoutFailedException  LogoutFailedException will be thrown if unable to process federated IdP logout.
     */
    @Override
    protected void initiateLogoutRequest(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) throws LogoutFailedException {

        if (isLogoutEnabled(context)) {
            try {
                Map<String, String> paramMap = new HashMap<>();
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

                String idTokenHint = getIdTokenHint(context);
                if (StringUtils.isNotBlank(idTokenHint)) {
                    paramMap.put(CustomAuthenticatorConstants.ID_TOKEN_HINT, idTokenHint);
                }

                String callbackURI = authenticatorProperties.get(CustomAuthenticatorConstants.CALLBACK_URL);
                paramMap.put(CustomAuthenticatorConstants.POST_LOGOUT_REDIRECT_URI, callbackURI);

                String sessionID = context.getContextIdentifier() + "," + CustomAuthenticatorConstants.LOGIN_TYPE;
                paramMap.put(CustomAuthenticatorConstants.OAUTH2_PARAM_STATE, sessionID);




                String logoutEndpoint = getFileConfigValue(CustomAuthenticatorConstants.EndpointsKeys.
                        LOGOUT_ENDPOINT_KEY);
                String logoutUrl = FrameworkUtils.buildURLWithQueryParams(logoutEndpoint, paramMap);
                response.sendRedirect(logoutUrl);

            } catch (IllegalArgumentException | IOException e) {
                LOG.error("Error in initiate logout URI build.");
                String idpName = context.getExternalIdP().getName();
                String tenantDomain = context.getTenantDomain();
                throw new LogoutFailedException("Error occurred while initiating the logout request to IdP: " + idpName
                        + " of tenantDomain: " + tenantDomain, e);
            }
        } else {
            super.initiateLogoutRequest(request, response, context);
        }
    }

    /**
     * Used to return id token hint value when initiateLogout triggers.
     *
     * @param context The Authentication context received by authenticator.
     * @return        Returns the id token hint from the context.
     */
    private String getIdTokenHint(AuthenticationContext context) {

        if (context.getStateInfo() instanceof StateInfo) {
            return ((StateInfo) context.getStateInfo()).getIdTokenHint();
        }
        return null;
    }

    /**
     * After a successful logout, WSO2 IS returns this response.
     * Contains the details about the SP.
     *
     * @param request   The request that is received by the authenticator.
     * @param response  The response that is received to the authenticator.
     * @param context   The Authentication context received by authenticator.
     */
    @Override
    protected void processLogoutResponse(HttpServletRequest request, HttpServletResponse response,
                                         AuthenticationContext context) {

        if (LOG.isDebugEnabled()) {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + IdentityTenantUtil.getTenantDomainFromContext());
            } else {
                LOG.debug("Handled logout response from service provider " + request.getParameter("sp") +
                        " in tenant domain " + request.getParameter("tenantDomain"));
            }
        }
    }

    /**
     * Returns the OAuth type response to the back channel.
     *
     * @param oAuthClient                   OAuth client object received to the authenticator.
     * @param accessRequest                 OAuth client request received by the authenticator.
     * @return OAuthClientResponse          Returns the OAuth client response from the authenticator.
     * @throws CustomAuthnFailedException   CustomAuthnFailedException will throw to the processAuthenticationResponse.
     */
    protected OAuthClientResponse getOAuthResponse(OAuthClient oAuthClient, OAuthClientRequest accessRequest)
            throws CustomAuthnFailedException {

        OAuthClientResponse oAuthResponse = null;
        try {
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            LOG.error("OAuth client response failed.");
            throw new CustomAuthnFailedException("", "", e);
        }

        return oAuthResponse;
    }

    /**
     * Map the non-user claim values according to the attribute separator.
     *
     * @param claims     Retrieved JSON claim set from id token / userinfo endpoint of External IdP.
     * @param entry      A collective view of JSON claims without non-user attributes.
     * @param separator  The attribute separator obtained from getMultiAttributeSeparator method.
     */
    protected void buildClaimMappings(Map<ClaimMapping, String> claims, Map.Entry<String, Object> entry,
                                      String separator) {

        StringBuilder claimValue = null;
        if (StringUtils.isBlank(separator)) {
            separator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
        }
        if (entry.getValue() instanceof JSONArray) {
            JSONArray jsonArray = (JSONArray) entry.getValue();
            if (jsonArray != null && !jsonArray.isEmpty()) {
                Iterator<Object> attributeIterator = jsonArray.iterator();
                while (attributeIterator.hasNext()) {
                    if (claimValue == null) {
                        claimValue = new StringBuilder(attributeIterator.next().toString());
                    } else {
                        claimValue.append(separator).append(attributeIterator.next().toString());
                    }
                }
            }
        } else {
            claimValue = entry.getValue() != null ?
                    new StringBuilder(entry.getValue().toString()) : new StringBuilder();
        }
        claims.put(ClaimMapping.build(entry.getKey(), entry.getKey(), null, false),
                claimValue != null ? claimValue.toString() : StringUtils.EMPTY);
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_CLAIMS)) {
            LOG.debug("Adding claim mapping : " + entry.getKey() + " <> " + entry.getKey() + " : " + claimValue);
        }
    }

    /**
     * Separate the attribute from the received payload.
     *
     * @param context                         The Authentication context received by authenticator.
     * @param authenticatedUserId             The user id of authenticated user.
     * @return String                         The element which is used to separate the attributes from the
     *                                        JSON payload.
     * @throws AuthenticationFailedException
     */
    protected String getMultiAttributeSeparator(AuthenticationContext context, String authenticatedUserId)
            throws AuthenticationFailedException {

        String attributeSeparator = null;
        try {
            String tenantDomain = context.getTenantDomain();
            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            int tenantId = DataHolder.getInstance().getRealmService().getTenantManager().
                    getTenantId(tenantDomain);
            UserRealm userRealm = DataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);

            if (userRealm != null) {
                UserStoreManager userStore = (UserStoreManager) userRealm.getUserStoreManager();
                attributeSeparator = userStore.getRealmConfiguration().getUserStoreProperty(IdentityCoreConstants.
                        MULTI_ATTRIBUTE_SEPARATOR);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("For the claim mapping: " + attributeSeparator + " " +
                            "is used as the attributeSeparator in " + "tenant: " + tenantDomain);
                }
            }
        } catch (UserStoreException e) {
            throw new AuthenticationFailedException("", "", AuthenticatedUser.
                    createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId), e);
        }

        return attributeSeparator;
    }

    /**
     * Request the access token - Create a request to access token endpoint of the external IdP.
     *
     * @param context                       The Authentication context received by authenticator.
     * @param authzResponse                 The response from to authorize endpoint. (To get the received
     *                                      authorize code.)
     * @return OAuthClientRequest           Returns the access token call which was built.
     * @throws CustomAuthnFailedException   Exception throws if unable to process the token request.
     */
    public OAuthClientRequest getAccessTokenRequest(AuthenticationContext context, OAuthAuthzResponse authzResponse)
            throws CustomAuthnFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();

        OAuthClientRequest accessTokenRequest = null;
        try {
            String tokenEndPoint = getFileConfigValue(CustomAuthenticatorConstants.EndpointsKeys.TOKEN_ENDPOINT_KEY);
            String clientId = authenticatorProperties.get(CustomAuthenticatorConstants.CLIENT_ID);
            String clientSecret = authenticatorProperties.get(CustomAuthenticatorConstants.CLIENT_SECRET);
            String callbackUrl = authenticatorProperties.get(CustomAuthenticatorConstants.CALLBACK_URL);

            accessTokenRequest = OAuthClientRequest
                    .tokenLocation(tokenEndPoint)
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(clientId).setClientSecret(clientSecret)
                    .setRedirectURI(callbackUrl)
                    .setCode(authzResponse.getCode())
                    .buildBodyMessage();

            if (accessTokenRequest != null) {
                String serverURL = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                accessTokenRequest.addHeader(CustomAuthenticatorConstants.HTTP_ORIGIN_HEADER, serverURL);
            }

        } catch (OAuthSystemException e) {
            LOG.error("Unable to build the request with request's body attributes.");
            throw new CustomAuthnFailedException("Exception while building access token request " +
                    "with the request body", e);
        } catch (URLBuilderException e) {
            if (LOG.isDebugEnabled()) {
                LOG.error("Unable to identify common-auth URL on browser");
            }
            throw new CustomAuthnFailedException("Unable to get the absolute public URL from browser.", e);
        }
        return accessTokenRequest;
    }

    /**
     * This method is used to retrieve user claims from id token.
     *
     * @param context               The Authentication context received by authenticator.
     * @param idToken               The received Id token from the processAuthenticationResponse.
     * @return Map<Strng, Object>   Decoded JWT payload via JSON Key value pairs.
     */
    protected Map<String, Object> getIdTokenClaims(AuthenticationContext context, String idToken) {

        context.setProperty(CustomAuthenticatorConstants.ID_TOKEN, idToken);
        String base64Body = idToken.split("\\.")[1];
        byte[] decoded = Base64.decodeBase64(base64Body.getBytes());
        Set<Map.Entry<String, Object>> jwtAttributeSet = new HashSet<>();
        try {
            jwtAttributeSet = JSONObjectUtils.parse(new String(decoded)).entrySet();
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing JWT ID token.", e);
        }
        Map<String, Object> userInfoJwtAttributes = buildJSON(jwtAttributeSet);

        return userInfoJwtAttributes;
    }

    /**
     * This method is used to retrieve user claims as key value pairs to the Java Map object from user info endpoint.
     *
     * @param oAuthResponse         The response from OAuthClient to authenticator by the External IdP.
     *                              (Use to get the access token.)
     * @param context               The Authentication context received by authenticator.
     * @return Map<String, Object>  Map object of key value pairs of the logged user.
     */
    protected Map<String, Object> getUserInfoUserAttributes(OAuthClientResponse oAuthResponse,
                                                            AuthenticationContext context)
            throws CustomUserInfoFailedException {

        String accessToken = oAuthResponse.getParam(CustomAuthenticatorConstants.ACCESS_TOKEN);
        String userInfoJsonPayload;
        Map<String, Object> userInfoJwtAttributes = null;

        try {
            userInfoJsonPayload = sendUserInfoRequest(context, accessToken);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully returns the userinfo JSON payload");
            }
            Set<Map.Entry<String, Object>> jwtAttributeSet;
            jwtAttributeSet = JSONObjectUtils.parse(userInfoJsonPayload).entrySet();
            userInfoJwtAttributes = buildJSON(jwtAttributeSet);

        } catch (CustomUserInfoFailedException e) {
            throw new CustomUserInfoFailedException("Unable to retrieve claims from user info.", e);
        } catch (ParseException e) {
            LOG.error("Error occurred while parsing user info payload.");
            throw new CustomUserInfoFailedException("Error occurred while parsing user info payload.", e);
        }

        return userInfoJwtAttributes;
    }

    /**
     * Map the JSON payload attributes as key value pairs.
     *
     * @param jwtAttributeSet        A JSON literal object of user claims retrieved by userinfo endpoint/decoded by
     *                               id token.
     * @return Map<String, Object>   Map object of key value pairs of the logged user.
     */
    protected Map<String, Object> buildJSON(Set<Map.Entry<String, Object>> jwtAttributeSet) {

        Map<String, Object> jwtAttributeMap = new HashMap<String, Object>();
        for (Map.Entry<String, Object> entry : jwtAttributeSet) {
            jwtAttributeMap.put(entry.getKey(), entry.getValue());
            if (LOG.isDebugEnabled()) {
                LOG.debug("FIdP user claim : " + entry.getKey());
            }
        }
        return jwtAttributeMap;
    }

    /**
     * This method is used to create userinfo request with the access token.
     *
     * @param context                          The Authentication context received by authenticator.
     * @param accessToken                      The access token obtained from the processAuthenticationResponse.
     * @return String                          The response which returns from the user info API call.
     * @throws CustomUserInfoFailedException   Throws an exception, if not obtains the user claims from the user info.
     */
    protected String sendUserInfoRequest(AuthenticationContext context, String accessToken)
            throws CustomUserInfoFailedException {

        StringBuilder builder = new StringBuilder();

        try {
            String userInfoEndpoint = getFileConfigValue(CustomAuthenticatorConstants.EndpointsKeys.
                    USER_INFO_ENDPOINT_KEY);
            URL userInfoUrl = new URL(userInfoEndpoint);
            HttpURLConnection httpURLConnection = (HttpURLConnection) userInfoUrl.openConnection();
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.setRequestProperty("Authorization", "Bearer " + accessToken);
            BufferedReader reader = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
            String inputLine = reader.readLine();

            if (LOG.isDebugEnabled()) {
                LOG.debug("User info request is sent successfully.");
            }

            while (inputLine != null) {
                builder.append(inputLine).append("\n");
                inputLine = reader.readLine();
            }

        } catch (IOException e) {
            LOG.error("Unable to retrieve successful response from external IdP UserInfo.");
            throw new CustomUserInfoFailedException("FIdP UserInfo failure.", e);
        }
        if (LOG.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            LOG.debug("response: " + builder);
        }

        return builder.toString();
    }

    /**
     * Returns the user id of the authenticated user.
     *
     * @param userClaims                      The Map object with user claims returns from buildJSON.
     * @return String                         The ID of the authenticated user from FIdP.
     * @throws AuthenticationFailedException  Throws an AuthenticationFailedException exception to
     *                                        processAuthenticationResponse.
     */
    protected String getAuthenticatedUserId(Map<String, Object> userClaims)
            throws AuthenticationFailedException {

        String authenticatedUserId;
        authenticatedUserId = (String) userClaims.get(CustomAuthenticatorConstants.SUB);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authenticated user id: " + authenticatedUserId + " retrieved from the 'sub' claim.");
        }
        if (StringUtils.isBlank(authenticatedUserId)) {
            LOG.error("The authenticated user id is empty.");
            throw new AuthenticationFailedException("", "");
        }

        return authenticatedUserId;
    }

    /**
     * Checks whether the logout option has been enabled by the authenticator.
     *
     * @param context   The Authentication context received by authenticator.
     * @return Boolean  Logout option has been enabled or not by the authenticator.
     */
    protected boolean isLogoutEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        return Boolean.parseBoolean(authenticatorProperties.get(CustomAuthenticatorConstants.LOGOUT_ENABLE));
    }

    /**
     * Returns the toml configuration values of authenticator's endpoints.
     *
     * @param fileConfigKey Endpoint key configured in toml.
     * @return String       Returns th endpoint's value.
     */
    protected String getFileConfigValue(String fileConfigKey) {

        return getAuthenticatorConfig().getParameterMap().get(fileConfigKey);
    }
}
