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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.cas.response.SAMLResponse;


public class SSOLoginProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SSOLoginProcessor.class);

    @Override
    public String getName() {
        return "SSOLoginProcessor";
    }

    public int getPriority() {
        return 1;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            if (context.getRequest() instanceof SAMLSpInitRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SAMLResponse.SAMLResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        CASMessageContext messageContext = (CASMessageContext) getContextIfAvailable(identityRequest);
        AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext, identityRequest);
        return HandlerManager.getInstance().getResponse(messageContext,authnResult,identityRequest);
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }
}
