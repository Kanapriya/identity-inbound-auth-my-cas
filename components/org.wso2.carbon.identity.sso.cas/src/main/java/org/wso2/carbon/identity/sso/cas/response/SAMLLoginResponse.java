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

package org.wso2.carbon.identity.sso.cas.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.handler.ProtocolConstants;
import org.wso2.carbon.identity.sso.cas.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;


public class SAMLLoginResponse extends SAMLResponse {

    private String respString;
    private String relayState;
    private String acsUrl;
    private String subject;
    private String authenticatedIdPs;
    private String tenantDomain;
    private static String success = "yes\n%s\n";
    private static String failure = "no\n\n";

    protected SAMLLoginResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.respString = ((SAMLLoginResponseBuilder) builder).respString;
        this.relayState = ((SAMLLoginResponseBuilder) builder).relayState;
        this.acsUrl = ((SAMLLoginResponseBuilder) builder).acsUrl;
        this.authenticatedIdPs = ((SAMLLoginResponseBuilder) builder).authenticatedIdPs;
        this.tenantDomain = ((SAMLLoginResponseBuilder) builder).tenantDomain;
        this.subject = ((SAMLLoginResponseBuilder) builder).subject;
    }

    public String getRespString() {
        return respString;
    }

    public String getSubject() {
        return subject;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getAuthenticatedIdPs() {
        return authenticatedIdPs;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public CASMessageContext getContext(){
        return (CASMessageContext)this.context;
    }

    public static class SAMLLoginResponseBuilder extends SAMLResponseBuilder {

        private static Log log = LogFactory.getLog(SAMLLoginResponseBuilder.class);

        private String respString;
        private String relayState;
        private String acsUrl;
        private String subject;
        private String authenticatedIdPs;
        private String tenantDomain;

        public SAMLLoginResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLLoginResponse build(){
            return new SAMLLoginResponse(this);
        }

        public String buidResponse() throws IdentityException{
            String responseString;
            CASMessageContext messageContext = (CASMessageContext)this.context;
            SAMLIdentityRequest req = messageContext.getRequest();

            try {
                log.debug("CAS " + messageContext.getRequestURI() + " query string: " + messageContext.getQueryString());

                String serviceProviderUrl = req.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);
                String serviceTicketId = req.getParameter(ProtocolConstants.SERVICE_TICKET_ARGUMENT);

                if( serviceTicketId == null || serviceProviderUrl == null) {
                    responseString = buildFailureResponse();
                } else {
                    // "ticket" must be valid and "service" URL argument must match the service provider URL
                    if( CASSSOUtil.isValidServiceProviderForServiceTicket(serviceTicketId, serviceProviderUrl) ) {
                        ServiceTicket serviceTicket = CASSSOUtil
                                .getServiceTicket(serviceTicketId);
                        String principal = serviceTicket.getParentTicket().getPrincipal();

                        responseString = buildSuccessResponse(principal);
                    } else {
                        responseString = buildFailureResponse();
                    }
                }

                log.debug("CAS " + req.getRequestURI() + " response: " + responseString);
            } catch( Exception ex) {
                log.debug("CAS "+ req.getRequestURI() + " internal error", ex);
                responseString = buildFailureResponse();
            }

            return responseString;
        }

        private String buildSuccessResponse(String userId) {
            return String.format(
                    success,
                    userId
            );
        }

        private String buildFailureResponse() {
            return failure;
        }


//        public String buildResponse() throws IdentityException {
//            CASMessageContext messageContext = (CASMessageContext)this.context;
//            ServiceProvider serviceProviderDO = messageContext.getServiceProviderByUrl();
//            if (log.isDebugEnabled()) {
//                log.debug("Building SAML Response for the consumer '" + messageContext.getAssertionConsumerURL() + "'");
//            }
//            Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
//            response.setIssuer(SAMLSSOUtil.getIssuer());
//            response.setID(SAMLSSOUtil.createID());
//           if (!messageContext.isIdpInitSSO()) {
//                response.setInResponseTo(messageContext.getId());
//            }
//            response.setDestination(messageContext.getAssertionConsumerURL());
//            response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
//            response.setVersion(SAMLVersion.VERSION_20);
//            DateTime issueInstant = new DateTime();
//            DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
//                    + SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 * 1000L);
//            response.setIssueInstant(issueInstant);
//            //@TODO sessionHandling
//            String sessionId = "";
//            Assertion assertion = SAMLSSOUtil.buildSAMLAssertion(messageContext, notOnOrAfter, sessionId);
//
//            if (serviceProviderDO.isDoEnableEncryptedAssertion()) {
//
//                String domainName = messageContext.getTenantDomain();
//                String alias = serviceProviderDO.getCertAlias();
//                if (alias != null) {
//                    EncryptedAssertion encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion,
//                            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, alias, domainName);
//                    response.getEncryptedAssertions().add(encryptedAssertion);
//                }
//            } else {
//                response.getAssertions().add(assertion);
//            }
//
//            if (serviceProviderDO.isDoSignResponse()) {
//                SAMLSSOUtil.setSignature(response, serviceProviderDO.getSigningAlgorithmUri(), serviceProviderDO
//                        .getDigestAlgorithmUri(), new SignKeyDataHolder(messageContext.getAuthenticationResult()
//                        .getSubject().getAuthenticatedSubjectIdentifier()));
//            }
//            this.setResponse(response);
//            String respString = SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
//            this.setRespString(respString);
//            return respString;
//        }

        public SAMLLoginResponseBuilder setRespString(String respString) {
            this.respString = respString;
            return this;
        }

        public SAMLLoginResponseBuilder setSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public SAMLLoginResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAMLLoginResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLLoginResponseBuilder setAuthenticatedIdPs(String authenticatedIdPs) {
            this.authenticatedIdPs = authenticatedIdPs;
            return this;
        }

        public SAMLLoginResponseBuilder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        private Status buildStatus(String status, String statMsg) {

            Status stat = new StatusBuilder().buildObject();

            // Set the status code
            StatusCode statCode = new StatusCodeBuilder().buildObject();
            statCode.setValue(status);
            stat.setStatusCode(statCode);

            // Set the status Message
            if (statMsg != null) {
                StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
                statMesssage.setMessage(statMsg);
                stat.setStatusMessage(statMesssage);
            }

            return stat;
        }
    }
}
