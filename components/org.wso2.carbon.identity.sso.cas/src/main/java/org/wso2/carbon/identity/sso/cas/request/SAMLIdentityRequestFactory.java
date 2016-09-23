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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.sso.cas.CASErrorConstants;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.configuration.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.exception.TicketNotFoundException;
import org.wso2.carbon.identity.sso.cas.handler.HandlerConstants;
import org.wso2.carbon.identity.sso.cas.handler.PostLoginHandler;
import org.wso2.carbon.identity.sso.cas.handler.PreLoginHandler;
import org.wso2.carbon.identity.sso.cas.handler.ProtocolConstants;
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
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

public class SAMLIdentityRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(SAMLIdentityRequestFactory.class);
    boolean samlLogin = false;

    @Override
    public String getName() {
        return "SAMLIdentityRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        String serviceProviderUrl = request.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);
        String forceLoginString = request.getParameter(ProtocolConstants.RENEW_ARGUMENT);
        String passiveLoginString = request.getParameter(ProtocolConstants.GATEWAY_ARGUMENT);

        if (StringUtils.isNotBlank(serviceProviderUrl) || StringUtils.isNotBlank(forceLoginString) || StringUtils.isNotBlank(passiveLoginString)) {
            return true;
        }
        return false;
    }

    @Override
    public int getPriority() {
        return -3;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws SAML2ClientException {
//        String serviceProviderUrl = request.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);
        IdentityRequest.IdentityRequestBuilder builder = null;
        try {
            if( !request.getRequestURI().startsWith(
                    CASConfiguration.buildRelativePath(HandlerConstants.PRE_CAS_LOGIN_PATH)) ) {
                builder = new SAMLSpInitRequest.PreLoginHandler(request, response);
            } else {
                builder = new SAMLSpInitRequest.PostLoginHandler(request, response);
            }
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw SAML2ClientException.error("Error occurred while creating the Identity Request", e);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception,
                                                                            HttpServletRequest request,
                                                                            HttpServletResponse response) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        String redirectURL = CASSSOUtil.getNotificationEndpoint();
        Map<String, String[]> queryParams = new HashMap();
        //TODO Send status codes rather than full messages in the GET request
        try {
            queryParams.put(CASSSOConstants.STATUS, new String[]{URLEncoder.encode(((SAML2ClientException)
                    exception).getExceptionStatus(), StandardCharsets.UTF_8.name())});
            queryParams.put(CASSSOConstants.STATUS_MSG, new String[]{URLEncoder.encode(((SAML2ClientException)
                    exception).getExceptionMessage(), StandardCharsets.UTF_8.name())});
            if (exception.getMessage() != null) {
                queryParams.put(CASSSOConstants.SAML_RESP, new String[]{URLEncoder.encode(exception.getMessage()
                        , StandardCharsets.UTF_8.name())});
            }
            if (((SAML2ClientException) exception).getACSUrl() != null) {
                queryParams.put(CASSSOConstants.SERVICE, new String[]{URLEncoder.encode((
                        (SAML2ClientException) exception).getACSUrl(), StandardCharsets.UTF_8.name())});
            }
            builder.setParameters(queryParams);
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding query parameters.", e);
            }
        }
        builder.setRedirectURL(redirectURL);
        builder.setStatusCode(HttpServletResponse.SC_MOVED_TEMPORARILY);
        return builder;
    }

    protected void showLoginError(HttpServletResponse resp, String errorCode, Locale locale) throws IOException {
        String errorMessage = ResourceBundle.getBundle(HandlerConstants.RESOURCE_BUNDLE, locale).getString(errorCode);
        resp.getWriter().write(
                CASPageTemplates.getInstance().showLoginError(errorMessage, locale)
        );
    }
}
