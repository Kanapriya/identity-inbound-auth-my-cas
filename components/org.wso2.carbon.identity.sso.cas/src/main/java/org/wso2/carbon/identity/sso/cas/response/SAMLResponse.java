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

import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

import javax.servlet.http.Cookie;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SAMLResponse extends IdentityResponse {

    private Response response;
//    private Map< Cookie> cookies = new HashMap<>();

    private List<Cookie> cookies;

    protected SAMLResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.response = ((SAMLResponseBuilder) builder).response;
    }

    public Response getResponse() {
        return this.response;
    }

    public static class SAMLResponseBuilder extends IdentityResponseBuilder {

        private Response response;

        //Do the bootstrap first
//        static {
//            SAMLSSOUtil.doBootstrap();
//        }

        public SAMLResponseBuilder(IdentityMessageContext context) {
            super(context);
            ResponseBuilder responseBuilder = new ResponseBuilder();
            this.response = responseBuilder.buildObject();
        }

        public SAMLResponseBuilder setResponse(Response response) {
            this.response = response;
            return this;
        }
    }

    public SAMLResponse addCookie(Cookie value) {
//        if (this.cookies.containsKey(name)) {
//            throw FrameworkRuntimeException.error("Cookies map trying to override existing " +
//                    "cookie " + name);
//        }
        this.cookies.add(value);
        return this;
    }

}
