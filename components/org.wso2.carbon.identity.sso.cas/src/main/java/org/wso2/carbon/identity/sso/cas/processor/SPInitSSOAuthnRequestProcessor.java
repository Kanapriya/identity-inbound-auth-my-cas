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
package org.wso2.carbon.identity.sso.cas.processor;


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.configuration.CASSSOConstants;

import org.wso2.carbon.identity.sso.cas.context.SAMLMessageContext;

import org.wso2.carbon.identity.sso.cas.request.SAMLSpInitRequest;

import java.util.HashMap;

public class SPInitSSOAuthnRequestProcessor extends IdentityProcessor {

    private String relyingParty;

    @Override
    public String getName() {
        return CASSSOConstants.CAS_SSO;
    }

    @Override
    public int getPriority() {
        return 2;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLSpInitRequest && ((SAMLSpInitRequest) identityRequest).getSamlRequest
                () != null) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLSpInitRequest) identityRequest, new
                HashMap<String, String>());
//        HandlerManager.getInstance().validateRequest(messageContext);
        this.relyingParty = messageContext.getIssuer();
        return buildResponseForFrameworkLogin(messageContext);
    }
}
