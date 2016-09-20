/* ***************************************************************************
 * Copyright 2014 Ellucian Company L.P. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/
package org.wso2.carbon.identity.sso.cas.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfigs;

import org.wso2.carbon.identity.sso.cas.processor.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.cas.request.SAMLIdentityRequestFactory;
import org.wso2.carbon.identity.sso.cas.response.HttpSAMLResponseFactory;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.Hashtable;
import java.util.Scanner;

/**
 * @scr.component name="identity.sso.cas.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="1..1"
 * policy="dynamic" bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="saml.processor.request"
 * interface="SPInitSSOAuthnRequestProcessor" cardinality="0..n"
 * policy="dynamic" bind="addAuthnRequestProcessor" unbind="removeAuthnRequestProcessor"
 * @scr.reference name="saml.request.factory"
 * interface="SAMLIdentityRequestFactory" cardinality="0..n"
 * policy="dynamic" bind="addSAMLRequestFactory" unbind="removeSAMLRequestFactory"
 */

public class CASAuthenticatorServiceComponent{


    private static Log log = LogFactory.getLog(CASAuthenticatorServiceComponent.class);
    private static String ssoRedirectPage = null;
    private SPInitSSOAuthnRequestProcessor authnRequestProcessor;
    private SAMLIdentityRequestFactory samlRequestFactory;

    protected void activate(ComponentContext ctxt) {

        CASSSOUtil.setBundleContext(ctxt.getBundleContext());
        // Register a SSOServiceProviderConfigManager object as an OSGi Service
//        ctxt.getBundleContext().registerService(SSOServiceProviderConfigManager.class.getName(),
//                SSOServiceProviderConfigManager.getInstance(), null);
        ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(), new
                SAMLIdentityRequestFactory(), null);
        ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                HttpSAMLResponseFactory(), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SPInitSSOAuthnRequestProcessor
                (), null);
//        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SSOLoginProcessor(), null);

        CASConfigs cas = new CASConfigs();
        Hashtable<String, String> casProps = new Hashtable<String, String>();
        ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class, cas, casProps);

        String redirectHtmlPath = null;
        FileInputStream fis = null;
        try {
            IdentityUtil.populateProperties();
            CASSSOUtil.setSingleLogoutRetryCount(Integer.parseInt(
                    IdentityUtil.getProperty(IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_COUNT)));
            CASSSOUtil.setSingleLogoutRetryInterval(Long.parseLong(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_INTERVAL)));
            redirectHtmlPath = CarbonUtils.getCarbonHome() + File.separator + "repository"
                    + File.separator + "resources" + File.separator + "identity" + File.separator + "pages" + File.separator + "samlsso_response.html";
            fis = new FileInputStream(new File(redirectHtmlPath));
            ssoRedirectPage = new Scanner(fis, StandardCharsets.UTF_8.name()).useDelimiter("\\A").next();
            if (log.isDebugEnabled()) {
                log.debug("samlsso_response.html " + ssoRedirectPage);
            }

//        HttpService httpService = CASSSOUtil.getHttpService();
//
//        String casLoginPath = CASConfiguration.buildRelativePath(CASEndpointConstants.LOGIN_PATH);
//        String casProxyLoginPath = CASConfiguration.buildRelativePath(CASEndpointConstants.PROXY_LOGIN_PATH);
//        String casLogoutPath = CASConfiguration.buildRelativePath(CASEndpointConstants.LOGOUT_PATH);
//        String casValidatePath = CASConfiguration.buildRelativePath(CASEndpointConstants.VALIDATE_PATH);
//        String casProxyValidatePath = CASConfiguration.buildRelativePath(CASEndpointConstants.PROXY_VALIDATE_PATH);
//        String casServiceValidatePath = CASConfiguration.buildRelativePath(CASEndpointConstants.SERVICE_VALIDATE_PATH);
//        String casSamlValidatePath = CASConfiguration.buildRelativePath(CASEndpointConstants.SAML_VALIDATE_PATH);
//
//        // Register CAS SSO servlets
//        Servlet casLoginServlet = new ContextPathServletAdaptor(new CASLoginServlet(), casLoginPath);
//        Servlet casProxyLoginServlet = new ContextPathServletAdaptor(new CASProxyLoginServlet(), casProxyLoginPath);
//        Servlet casLogoutServlet = new ContextPathServletAdaptor(new CASLogoutServlet(), casLogoutPath);
//        Servlet casValidateServlet = new ContextPathServletAdaptor(new CASValidationServlet(), casValidatePath);
//        Servlet casProxyValidateServlet = new ContextPathServletAdaptor(new CASProxyValidationServlet(), casProxyValidatePath);
//        Servlet casServiceValidateServlet = new ContextPathServletAdaptor(new CASServiceValidationServlet(), casServiceValidatePath);
//        Servlet casSamlValidateServlet = new ContextPathServletAdaptor(new CASSAMLValidationServlet(), casSamlValidatePath);
//
//        try {
//            httpService.registerServlet(casLoginPath, casLoginServlet, null, null);
//            httpService.registerServlet(casProxyLoginPath, casProxyLoginServlet, null, null);
//            httpService.registerServlet(casLogoutPath, casLogoutServlet, null, null);
//            httpService.registerServlet(casValidatePath, casValidateServlet, null, null);
//            httpService.registerServlet(casProxyValidatePath, casProxyValidateServlet, null, null);
//            httpService.registerServlet(casServiceValidatePath, casServiceValidateServlet, null, null);
//            httpService.registerServlet(casSamlValidatePath, casSamlValidateServlet, null, null);
//        } catch (Exception e) {
//            String errMsg = "Error when registering CAS SSO Servlet via the HttpService.";
//            log.error(errMsg, e);
//            throw new RuntimeException(errMsg, e);
//        }

        log.info("Identity CAS SSO bundle is activated");
    }  catch (FileNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find SAML SSO response page in : " + redirectHtmlPath);
            }
        }
    }

    public static String getSsoRedirectHtml() {
        return ssoRedirectPage;
    }

    protected void addSAMLRequestFactory(SAMLIdentityRequestFactory requestFactory){
        if (log.isDebugEnabled()) {
            log.debug("Adding CASIdentityRequestFactory " + requestFactory.getName());
        }
        this.samlRequestFactory = requestFactory;

    }
    protected void removeSAMLRequestFactory(SAMLIdentityRequestFactory requestFactory){
        if (log.isDebugEnabled()) {
            log.debug("Removing CASIdentityRequestFactory ");
        }
        this.samlRequestFactory = null;

    }

    protected void addAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor){
        if (log.isDebugEnabled()) {
            log.debug("Adding SPInitSSOAuthnRequestProcessor " + processor.getName());
        }
        this.authnRequestProcessor = processor;
    }
    protected void removeAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor){
        if (log.isDebugEnabled()) {
            log.debug("Removing SPInitSSOAuthnRequestProcessor ");
        }
        this.authnRequestProcessor = null;
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("Identity CAS SSO bundle is deactivated");
        }
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity CAS SSO bundle");
        }
        try {
        	CASSSOUtil.setRegistryService(registryService);
        } catch (Throwable e) {
            log.error("Failed to get a reference to the Registry in CAS SSO bundle", e);
        }
    }
    
    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in CAS SSO bundle");
        }
        CASSSOUtil.setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService){
        if(log.isDebugEnabled()){
            log.debug("Realm Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService){
        if(log.isDebugEnabled()){
            log.debug("Realm Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setRegistryService(null);
    }
    
    protected void setHttpService(HttpService httpService){
        if(log.isDebugEnabled()){
            log.debug("HTTP Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService){
        if(log.isDebugEnabled()){
            log.debug("HTTP Service is unset in the CAS SSO bundle");
        }
        CASSSOUtil.setHttpService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the CAS SSO bundle");
        }
        CASSSOUtil.setConfigCtxService(null);
    }
}

