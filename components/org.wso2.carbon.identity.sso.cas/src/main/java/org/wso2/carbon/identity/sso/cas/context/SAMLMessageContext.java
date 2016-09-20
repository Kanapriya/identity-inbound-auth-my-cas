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

package org.wso2.carbon.identity.sso.cas.context;

import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.cas.configuration.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.request.SAMLIdentityRequest;

import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.Serializable;
import java.util.Map;

public class SAMLMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {

    private static final long serialVersionUID = 104634801939285909L;
    /**
     * The unmarshelled SAML Request
     */
    private AuthnRequest authnRequest;

    /**
     * Should be set in validateAuthnRequest
     */
    private boolean isValid;
    private String issuer;
    /**
     * Subject should be validated before set.
     * Validation is done in the request validation.
     */
    private String subject;
    private String tenantDomain;
    private int attributeConsumingServiceIndex;
    private SAMLSSOServiceProviderDO samlssoServiceProviderDO;

    public SAMLMessageContext(SAMLIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    @Override
    public SAMLIdentityRequest getRequest() {
        return (SAMLIdentityRequest) request;
    }

//    public String getDestination() {
//        if (!isIdpInitSSO() && this.authnRequest != null) {
//            return this.authnRequest.getDestination();
//        } else if (isIdpInitSSO()) {
//            return ((SAMLIdpInitRequest) this.getRequest()).getAcs();
//        }
//        return null;
//    }

//    public boolean isIdpInitSSO() {
//        return this.getRequest() instanceof  SAMLIdpInitRequest;
//    }


    public AuthnRequest getAuthnRequest() {
        return authnRequest;
    }

    public void setAuthnRequest(AuthnRequest authnRequest) {
        this.authnRequest = authnRequest;
    }

    public String getRelayState() {
        return this.getRequest().getRelayState();
    }

    public boolean isValid() {
        return isValid;
    }

    public void setValid(boolean isValid) {
        this.isValid = isValid;
    }

    public String getIssuer() {
        if (issuer.contains("@")) {
            String[] splitIssuer = issuer.split("@");
            return splitIssuer[0];
        }
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerWithDomain() {
        return this.issuer;
    }

    public int getAttributeConsumingServiceIndex() {
        return attributeConsumingServiceIndex;
    }

    public void setAttributeConsumingServiceIndex(int attributeConsumingServiceIndex) {
        this.attributeConsumingServiceIndex = attributeConsumingServiceIndex;
    }

    public String getRpSessionId() {
        return this.request.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
    }

//    public String getId() {
//        if(!isIdpInitSSO() && this.authnRequest != null) {
//            return this.authnRequest.getID();
//        }
//        return null;
//    }

    public String getAssertionConsumerURL() {
//        if(!isIdpInitSSO() && this.authnRequest != null) {
//            return this.authnRequest.getAssertionConsumerServiceURL();
//        } else {
            return samlssoServiceProviderDO.getDefaultAssertionConsumerUrl();
//        }
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public AuthenticatedUser getUser() {
        return this.getAuthenticationResult().getSubject();
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     *
     * @return AuthenticationResult saved in the messageContext
     * while authenticating in the framework.
     */
    public AuthenticationResult getAuthenticationResult() {
        if (this.getParameter(CASSSOConstants.AUTHENTICATION_RESULT) != null) {
            return (AuthenticationResult) this.getParameter(CASSSOConstants.AUTHENTICATION_RESULT);
        }
        return new AuthenticationResult();
    }

    public SAMLSSOServiceProviderDO getSamlssoServiceProviderDO() {
        return samlssoServiceProviderDO;
    }

    public void setSamlssoServiceProviderDO(SAMLSSOServiceProviderDO samlssoServiceProviderDO) {
        this.samlssoServiceProviderDO = samlssoServiceProviderDO;
    }
}