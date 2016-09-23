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
package org.wso2.carbon.identity.sso.cas.validator;


import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.response.SAMLResponse;


import java.io.IOException;

public abstract class AuthHandler extends AbstractIdentityHandler {

    public abstract boolean canHandle(CASMessageContext messageContext);

    /**
     * Process the authentication response from the framework
     */
    public abstract SAMLResponse.SAMLResponseBuilder validateAuthnResponseFromFramework(CASMessageContext
                                                                                                messageContext,
                                                                                        AuthenticationResult
                                                                                                authnResult,
                                                                                        IdentityRequest
                                                                                                identityRequest)
            throws IdentityException, IOException;
}
