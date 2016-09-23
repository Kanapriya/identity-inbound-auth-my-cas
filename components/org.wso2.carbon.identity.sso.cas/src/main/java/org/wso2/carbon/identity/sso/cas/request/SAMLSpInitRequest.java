/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.cas.request;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.sso.cas.CASErrorConstants;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfigs;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.exception.ServiceProviderNotFoundException;
import org.wso2.carbon.identity.sso.cas.handler.HandlerConstants;
import org.wso2.carbon.identity.sso.cas.handler.ProtocolConstants;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.identity.sso.cas.util.CASCookieUtil;
import org.wso2.carbon.identity.sso.cas.util.CASPageTemplates;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.ui.CarbonUIUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

public class SAMLSpInitRequest extends SAMLIdentityRequest {

    private static Log log = LogFactory.getLog(SAMLSpInitRequest.class);

    public SAMLSpInitRequest(PreLoginHandler builder) {
        super(builder);
    }


    public String getServiceRequest() {
        return ProtocolConstants.SERVICE_PROVIDER_ARGUMENT;
    }

    protected static void showLoginError(HttpServletResponse resp, String errorCode, Locale locale) throws IOException {
        String errorMessage = ResourceBundle.getBundle(HandlerConstants.RESOURCE_BUNDLE, locale).getString(errorCode);
        resp.getWriter().write(
                CASPageTemplates.getInstance().showLoginError(errorMessage, locale)
        );
    }

    public static class SAMLSpInitRequestBuilder extends SAMLIdentityRequestBuilder {
        public SAMLSpInitRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAMLSpInitRequestBuilder() {
        }

//        @Override
//        public SAMLSpInitRequest build() {
//            return new SAMLSpInitRequest(this);
//        }
    }

    public static class PreLoginHandler extends SAMLIdentityRequestBuilder {

        public PreLoginHandler(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
            String ticketGrantingTicketId = CASCookieUtil.getTicketGrantingTicketId(request);
            String storedSessionDataKey = CASCookieUtil.getSessionDataKey(request);
            boolean samlLogin = false;

            String queryString = request.getQueryString();
            log.debug("CAS pre-login query string: " + queryString);

            String serviceProviderUrl = request.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);

            // Fall back to "TARGET" argument for SAML-related login.
            // Older CAS clients use this argument for login instead of following
            // the CAS protocol specification.
            if (serviceProviderUrl == null) {
                log.debug("Found SAML login arguments");
                serviceProviderUrl = request
                        .getParameter(ProtocolConstants.SAML_SERVICE_PROVIDER_ARGUMENT);
                samlLogin = true;
            }

            String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);

            String forceLoginString = request.getParameter(ProtocolConstants.RENEW_ARGUMENT);
            String passiveLoginString = request.getParameter(ProtocolConstants.GATEWAY_ARGUMENT);

            boolean forceLogin = (forceLoginString != null && forceLoginString.equals(HandlerConstants.TRUE_FLAG_STRING));
            boolean passiveLogin = (passiveLoginString != null && passiveLoginString.equals(HandlerConstants.TRUE_FLAG_STRING));

            log.debug("ticketGrantingTicketId= " + ticketGrantingTicketId);

            if (ticketGrantingTicketId != null) {
                // Generates an exception for a missing TGT early in the SSO process

                TicketGrantingTicket ticketGrantingTicket = CASSSOUtil.getTicketGrantingTicket(ticketGrantingTicketId);

                log.debug("Ticket granting ticket found for " + ticketGrantingTicket.getPrincipal());
            }

            try {
                if (forceLogin && passiveLogin) {
                    showLoginError(response, CASErrorConstants.INVALID_ARGUMENTS_RENEW_GATEWAY, request.getLocale());
                } else if ((ticketGrantingTicketId != null && serviceProviderUrl == null)
                        || (ticketGrantingTicketId == null
                        && serviceProviderUrl == null && storedSessionDataKey == null)) {
                    showLoginError(response, CASErrorConstants.SERVICE_PROVIDER_MISSING, request.getLocale());
                } // Allow login and check service provider authorization afterwards
//		else if (serviceProvider == null) {
//			showLoginError(resp, CASErrorConstants.SERVICE_PROVIDER_NOT_AUTHORIZED, req.getLocale());
                else {// if (ticketGrantingTicketId == null) {
                    // Guarantee that a sessionDataKey is generated for existing SSO
                    // infrastructure
                    if (sessionDataKey == null) {
                        sessionDataKey = UUIDGenerator.generateUUID();
                    }

//                    String commonAuthURL = CarbonUIUtil.getAdminConsoleURL(request);
                    String commonAuthURL=  HandlerConstants.COMMON_AUTH_URL;
//
//                    commonAuthURL = commonAuthURL.replace(
//                            CASConfiguration.buildRelativePath("/login/carbon/"),
//                            HandlerConstants.COMMON_AUTH_ENDPOINT);

                    String selfPath;

                    if (passiveLogin && FrameworkUtils.getAuthCookie(request) == null) {
                        // CAS Protocol states to redirect to the service provider URL without a service ticket
                        selfPath = URLEncoder.encode(serviceProviderUrl, HandlerConstants.DEFAULT_ENCODING);
                    } else {

                        selfPath = URLEncoder.encode(
                                CASConfiguration.buildRelativePath(
                                        String.format(
                                                HandlerConstants.PRE_CAS_LOGIN_PATH_TEMPLATE,
                                                Base64.encodeBase64URLSafeString(
                                                        serviceProviderUrl.getBytes()
                                                ),
                                                samlLogin
                                        )
                                ),
                                HandlerConstants.DEFAULT_ENCODING);
                    }
                    String queryParams = String.format(
                            HandlerConstants.COMMON_AUTH_REDIRECT_URL,
                            "",//serviceProvider.getApplicationName(),
                            sessionDataKey, selfPath, forceLogin, passiveLogin);

//                   static String relyingParty =

                    log.debug("Redirect for CAS after authentication: " + commonAuthURL + queryParams);
                    response.sendRedirect(commonAuthURL + queryParams);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        @Override
        public SAMLSpInitRequest build() {
            return new SAMLSpInitRequest(this);
        }

    }

    public static class PostLoginHandler extends SAMLIdentityRequestBuilder {

        public PostLoginHandler(HttpServletRequest request, HttpServletResponse response) throws IOException {
            String ticketGrantingTicketId = CASCookieUtil.getTicketGrantingTicketId(request);
            String storedSessionDataKey = CASCookieUtil.getSessionDataKey(request);

            String queryString = request.getQueryString();
            log.debug("CAS post-login query string: " + queryString);

            String serviceProviderUrl = request.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);
            String sessionDataKey = request.getParameter(FrameworkConstants.SESSION_DATA_KEY);
            boolean loginComplete = false;
            boolean samlLogin = false;

            log.debug("ticketGrantingTicketId= " + ticketGrantingTicketId);

            String redirectUrl = null;
            String pathInfo = request.getRequestURI();

            log.debug("pathInfo= "+pathInfo);

            // Capture redirect after WSO2 authentication and check for CAS login
            // completion
            StringTokenizer st = new StringTokenizer(pathInfo, HandlerConstants.PATH_DELIMITER);
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                String[] tokenParts = token.split("=");
                if( tokenParts.length == 2 ) {
                    if( tokenParts[0].equals(HandlerConstants.POST_AUTH_REDIRECT_ARGUMENT) ) {
                        redirectUrl = new String(Base64.decodeBase64(tokenParts[1]));
                        log.debug(HandlerConstants.POST_AUTH_REDIRECT_ARGUMENT + "= " + redirectUrl);
                    } else if( tokenParts[0].equals(HandlerConstants.POST_AUTH_SUCCESS_ARGUMENT)) {
                        loginComplete = HandlerConstants.TRUE_FLAG_STRING.equals(tokenParts[1]);
                        log.debug(HandlerConstants.POST_AUTH_SUCCESS_ARGUMENT + "= " + loginComplete);
                    } else if( tokenParts[0].equals(HandlerConstants.POST_AUTH_SAML_LOGIN_ARGUMENT)) {
                        samlLogin = HandlerConstants.TRUE_FLAG_STRING.equals(tokenParts[1]);
                        log.debug(HandlerConstants.POST_AUTH_SAML_LOGIN_ARGUMENT + "= " + samlLogin);
                    }
                }
            }

            // Ticket granting ticket is required to generate service tickets for
            // service providers
            TicketGrantingTicket ticketGrantingTicket;

            // After authentication completes, before final CAS session
            if (sessionDataKey != null && !loginComplete) {

                String commonAuthURL = CarbonUIUtil.getAdminConsoleURL(request);

                // Move the AuthenticationResult to the new sessionDataKey
                // for future requests and remove the old entry
                AuthenticationResult authResult = CASSSOUtil.getAuthenticationResultFromCache(sessionDataKey);
//			FrameworkUtils.addAuthenticationResultToCache(storedSessionDataKey,
//					authResult, CASConfiguration.getCacheTimeout());
                FrameworkUtils.addAuthenticationResultToCache(storedSessionDataKey, authResult);
                removeAuthenticationResultFromCache(sessionDataKey);

//			ServiceProvider serviceProvider = CASSSOUtil
//					.getServiceProviderByUrl(redirectUrl, authResult.getSubject());
                ServiceProvider serviceProvider = CASSSOUtil.getServiceProviderByUrl(redirectUrl, String.valueOf(authResult.getSubject()));

                // Allow login and let them know that the service provider not authorized
                if( serviceProvider == null ) {
                    showLoginError(response, CASErrorConstants.SERVICE_PROVIDER_NOT_AUTHORIZED, request.getLocale());
                    return;
                }

                commonAuthURL = commonAuthURL.replace(CASConfiguration.buildRelativePath("/login/carbon/"),
                        HandlerConstants.COMMON_AUTH_ENDPOINT);

                String selfPath = URLEncoder.encode(
                        CASConfiguration.buildRelativePath(
                                String.format(
                                        HandlerConstants.POST_CAS_LOGIN_PATH_TEMPLATE,
                                        Base64.encodeBase64URLSafeString(redirectUrl.getBytes()),
                                        samlLogin,
                                        HandlerConstants.POST_AUTH_SUCCESS_NAME_VALUE)),
                        HandlerConstants.DEFAULT_ENCODING);

                String queryParams = String.format(
                        HandlerConstants.COMMON_AUTH_REDIRECT_URL,
                        serviceProvider.getApplicationName(),
                        sessionDataKey, selfPath, false, false);

                response.sendRedirect(commonAuthURL + queryParams);
            } else {

                try {

                    AuthenticationResult authResult = CASSSOUtil
                            .getAuthenticationResultFromCache(storedSessionDataKey);

//				ServiceProvider serviceProvider = (serviceProviderUrl != null) ? CASSSOUtil
//						.getServiceProviderByUrl(serviceProviderUrl, authResult.getSubject())
//						: CASSSOUtil.getServiceProviderByUrl(redirectUrl, authResult.getSubject());
                    ServiceProvider serviceProvider = (serviceProviderUrl != null) ? CASSSOUtil
                            .getServiceProviderByUrl(serviceProviderUrl, String.valueOf(authResult.getSubject()))
                            : CASSSOUtil.getServiceProviderByUrl(redirectUrl, String.valueOf(authResult.getSubject()));

                    // Generate ticket granting ticket for new CAS session
                    if (ticketGrantingTicketId == null && redirectUrl != null) {

//					ticketGrantingTicket = CASSSOUtil.createTicketGrantingTicket(
//							storedSessionDataKey, authResult.getSubject(), false);
                        ticketGrantingTicket = CASSSOUtil.createTicketGrantingTicket(
                                storedSessionDataKey, String.valueOf(authResult.getSubject()), false);
                    } else { // Existing TGT found
                        ticketGrantingTicket = CASSSOUtil
                                .getTicketGrantingTicket(ticketGrantingTicketId);
                        if( serviceProviderUrl != null ) {
                            redirectUrl = serviceProviderUrl;
                        }
                    }

                    CASCookieUtil.storeTicketGrantingCookie(
                            ticketGrantingTicket.getId(), request, response, 0);

                    String baseUrl = CASSSOUtil.getBaseUrl((serviceProviderUrl != null) ? serviceProviderUrl : redirectUrl, false);

                    ServiceTicket serviceTicket = ticketGrantingTicket
                            .grantServiceTicket(
                                    serviceProvider,
                                    baseUrl,
                                    samlLogin);

                    String serviceTicketId = serviceTicket.getId();

                    log.debug("Service ticket created: " + serviceTicketId);

                    // Remove "sessionDataKey" from CAS service provider
                    // redirect; consuming client does not need to understand
                    // WSO2 SSO in order to use CAS protocol.
                    int sessionDataKeyPosition = redirectUrl
                            .indexOf("sessionDataKey");

                    if (sessionDataKeyPosition > -1) {
                        redirectUrl = redirectUrl.substring(0,
                                sessionDataKeyPosition);
                    }

                    String redirectArgument = (samlLogin) ?
                            CASSSOUtil.buildUrlArgument(ProtocolConstants.SAML_SERVICE_PROVIDER_ARGUMENT,
                                    URLEncoder.encode(redirectUrl, HandlerConstants.DEFAULT_ENCODING)
                            ) +
                                    CASSSOUtil.buildUrlArgument(ProtocolConstants.SAML_SERVICE_TICKET_ARGUMENT,
                                            URLEncoder.encode(serviceTicketId, HandlerConstants.DEFAULT_ENCODING)) :
                            CASSSOUtil.buildUrlArgument(ProtocolConstants.SERVICE_TICKET_ARGUMENT, serviceTicketId);

                    log.debug("redirectArgument="+redirectArgument);

                    if (redirectUrl.indexOf('?') < 0) {
                        redirectUrl += "?";
                    }

                    // Append the service ticket to the CAS service provider URL
                    redirectUrl = redirectUrl + redirectArgument;

                    log.debug("redirecting back to service provider: "+redirectUrl);

                    response.sendRedirect(redirectUrl);
                } catch (ServiceProviderNotFoundException ex) {
                        showLoginError(response, "cas.service.provider.not.authorized", request.getLocale());
                    }
                }
            }
        }

        private static void removeAuthenticationResultFromCache(String sessionDataKey) {
            if (sessionDataKey != null) {
                AuthenticationResultCacheKey cacheKey = new AuthenticationResultCacheKey(
                        sessionDataKey);
//			AuthenticationResultCache.getInstance(0).clearCacheEntry(cacheKey);
                AuthenticationResultCache.getInstance().clearCacheEntry(cacheKey);
            }
        }
}

