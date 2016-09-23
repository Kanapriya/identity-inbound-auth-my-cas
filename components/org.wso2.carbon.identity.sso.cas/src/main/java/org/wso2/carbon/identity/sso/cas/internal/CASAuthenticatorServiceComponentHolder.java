package org.wso2.carbon.identity.sso.cas.internal;/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */





import org.wso2.carbon.identity.sso.cas.validator.AuthHandler;
import org.wso2.carbon.identity.sso.cas.validator.CASValidator;

import java.util.ArrayList;
import java.util.List;

public class CASAuthenticatorServiceComponentHolder {

    public static CASAuthenticatorServiceComponentHolder instance = new CASAuthenticatorServiceComponentHolder();
    public List<CASValidator> casValidators = new ArrayList<>();
    public List<AuthHandler> authHandlers = new ArrayList<>();

    public static CASAuthenticatorServiceComponentHolder getInstance() {
        return instance;
    }

    public List<CASValidator> getCaslValidators() {
        return this.casValidators;
    }

    public List<AuthHandler> getAuthHandlers() {
        return this.authHandlers;
    }
}
