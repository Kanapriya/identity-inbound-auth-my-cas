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
package org.wso2.carbon.identity.sso.cas.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCache;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheKey;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.cache.CacheEntry;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
//import org.wso2.carbon.identity.application.common.persistence.JDBCPersistenceManager;
//import org.wso2.carbon.identity.application.common.util.CharacterEncoder;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
//import org.wso2.carbon.identity.application.mgt.ApplicationInfoProvider;

import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.configuration.CASSSOConstants;
import org.wso2.carbon.ui.util.CharacterEncoder;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCache;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCacheEntry;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCacheKey;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCache;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCacheEntry;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCacheKey;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.exception.ServiceProviderNotFoundException;
import org.wso2.carbon.identity.sso.cas.exception.TicketNotFoundException;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

public class CASSSOUtil {
    private static Log log = LogFactory.getLog(CASSSOUtil.class);
    private static HttpService httpService;
	/*newly added*/
	private static BundleContext bundleContext;
	private static int singleLogoutRetryCount = 5;
	private static long singleLogoutRetryInterval = 60000;
	private static ConfigurationContextService configCtxService;

    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    private static RegistryService registryService;
    private static RealmService realmService;
	private static final String LOAD_APP_NAMES_AND_AUTH_KEY_BY_TENANT_ID_AND_TYPE = "SELECT APP_NAME, INBOUND_AUTH_KEY "
			+ "FROM SP_APP INNER JOIN SP_INBOUND_AUTH "
			+ "ON SP_APP.ID = SP_INBOUND_AUTH.APP_ID "
			+ "WHERE INBOUND_AUTH_TYPE = ? AND SP_APP.TENANT_ID = ? AND SP_INBOUND_AUTH.TENANT_ID=?";
    
    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }
    
    public static boolean isHttpSuccessStatusCode(int status) {
        return status >= 200 && status < 300;
    }
    
    public static String buildUrlArgument(String key, String value) {
    	return "&" + key + "=" + value;
    }
    
    public static String getServiceProviderNameByClientId(String serviceProviderUrl, String parameter, 
            String tenantDomain) throws IdentityApplicationManagementException {

        int tenantID = -1234;

        if (tenantDomain != null) {
            try {
                tenantID = realmService
                        .getTenantManager().getTenantId(tenantDomain);
                log.debug("getServiceProviderNameByClientId: tenantID updated to "+tenantID);
            } catch (Exception ex) {
            	log.error(ex);
			}
        }
    	
        String applicationName = null;
        
        // Reading application name from the database
        Connection connection = null;
        PreparedStatement storeAppPrepStmt = null;
        ResultSet appNameResult = null;
        
        // Faster to query directly than query for each service provider
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            storeAppPrepStmt = connection
                    .prepareStatement(LOAD_APP_NAMES_AND_AUTH_KEY_BY_TENANT_ID_AND_TYPE);
            storeAppPrepStmt.setString(1, CharacterEncoder.getSafeText(parameter));
            storeAppPrepStmt.setInt(2, tenantID);
            storeAppPrepStmt.setInt(3, tenantID);
            appNameResult = storeAppPrepStmt.executeQuery();
            log.debug("getServiceProviderNameByClientId: serviceProviderUrl="+serviceProviderUrl);
            while (appNameResult.next()) {
            	String authKey = appNameResult.getString(2);
            	log.debug("getServiceProviderNameByClientId: appName="+appNameResult.getString(1) + " ==> authKey=" + authKey);
            	if( authKey != null && authKey.trim().length() > 0 && serviceProviderUrl.startsWith(authKey) ) {
            		applicationName = appNameResult.getString(1);
            	}
            }
        } catch (SQLException e) {
        	log.error(e);
            throw new IdentityApplicationManagementException("Error while reading service providers");
        } finally {
            IdentityApplicationManagementUtil.closeResultSet(appNameResult);
            IdentityApplicationManagementUtil.closeStatement(storeAppPrepStmt);
            IdentityApplicationManagementUtil.closeConnection(connection);
        }
        
        return applicationName;
    }

	/*newly added*/
	public static BundleContext getBundleContext() {
		return CASSSOUtil.bundleContext;
	}

	/*newly added*/
	public static void setBundleContext(BundleContext bundleContext) {
		CASSSOUtil.bundleContext = bundleContext;
	}
    
    public static ServiceProvider getServiceProviderByUrl(String serviceProviderUrl, String username) {
    	ServiceProvider serviceProvider = null;
    	
    	if( serviceProviderUrl == null || serviceProviderUrl.trim().length() == 0) {
    		log.error("CAS service provider not specified");
    	} else {

    		try {
	    		String tenantDomain = null;
	    		
	    		if( username != null ) {
	    			tenantDomain = MultitenantUtils.getTenantDomain(username);
	    			log.debug("getServiceProviderByUrl: tenant="+tenantDomain);
	    		}
	 		
	    		if( tenantDomain == null ) {
	    			tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
	    		}
	    		
	    		String providerName = getServiceProviderNameByClientId(serviceProviderUrl, "casServiceUrl", tenantDomain);
    		
	    		if( providerName == null ) {
	    			throw new ServiceProviderNotFoundException("CAS service provider not found");
	    		}
	
				serviceProvider = ApplicationInfoProvider.getInstance().getServiceProvider(providerName, tenantDomain);
    		}catch(Exception ex) {
    			log.error(ex);
    		}
    	}
    	
    	return serviceProvider;
    }
    
    public static String getBaseUrl(String url, boolean returnBaseUrl) {
		int pathSeparatorPosition = url.indexOf(';');
		
		if( returnBaseUrl && pathSeparatorPosition == -1 ) {
			pathSeparatorPosition = url.indexOf('?');
		}
		
		if( pathSeparatorPosition != -1 ) {
			return url.substring(0, pathSeparatorPosition);
		} else {
			return url;
		}
    }
    
    public static boolean isValidServiceProvider(String serviceProviderUrl) {
    	return getServiceProviderByUrl(serviceProviderUrl, null) != null;
    }
    
    public static boolean isValidServiceProviderForServiceTicket(String serviceTicketId, String serviceProviderUrl) {
    	ServiceProvider serviceProvider = CASSSOUtil
				.getServiceTicket(serviceTicketId)
				.getService();

    	boolean isValidServiceProvider = false;

    	for( InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() ) {
    		String authType = config.getInboundAuthType();
    		String baseServiceProviderUrl = CASSSOUtil.getBaseUrl(config.getInboundAuthKey(), true);
    		if( authType.equals("casServiceUrl") ) {
    			isValidServiceProvider = serviceProviderUrl.startsWith(baseServiceProviderUrl);
    			if( isValidServiceProvider ) {
    				break;
    			}
    		}
    	}

    	return isValidServiceProvider;
    }
    
    public static String getServiceProviderUrl(ServiceProvider serviceProvider) {
    	String serviceProviderUrl = null;

    	for( InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() ) {
    		String authType = config.getInboundAuthType();

    		if( authType.equals("casServiceUrl") ) {
    			serviceProviderUrl = config.getInboundAuthKey();
    		}
    	}

    	return serviceProviderUrl;
    }
	/*newly added*/
	public static void setConfigCtxService(ConfigurationContextService configCtxService) {
		CASSSOUtil.configCtxService = configCtxService;
	}

	public static ConfigurationContextService getConfigCtxService() {
		return configCtxService;
	}

	/*newly added*/
    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setHttpService(HttpService httpService) {
        CASSSOUtil.httpService = httpService;
    }
    
    public static ServiceTicket getServiceTicket(String serviceTicketId) throws TicketNotFoundException {
    	ServiceTicketCache cache = ServiceTicketCache.getInstance( CASConfiguration.getCacheTimeout() );
    	
    	ServiceTicketCacheKey key = new ServiceTicketCacheKey(serviceTicketId);
    	
    	ServiceTicketCacheEntry entry = (ServiceTicketCacheEntry)cache.getValueFromCache(key);
    	
    	if( entry != null ) {
    		return entry.getServiceTicket();
    	} else {
    		throw new TicketNotFoundException("CAS service ticket" + serviceTicketId + " not found", serviceTicketId);
    	}
    }
    
    public static boolean isValidServiceTicket(String serviceTicketId ) {
    	try {
    		ServiceTicket serviceTicket = getServiceTicket(serviceTicketId);
    		
    		return (serviceTicket != null);
    	} catch(Exception ex) {
    		return false;
    	}
    }
    
    public static boolean isValidProxyTicket(String proxyTicketId) {
    	try {
    		return getServiceTicket(proxyTicketId).hasProxy();
    	} catch(Exception ex) {
    		return false;
    	}
    }
    
    public static ServiceTicket consumeServiceTicket( String serviceTicketId ) {
    	ServiceTicket ticket = null;
    	
    	 try {
	    	ServiceTicketCache cache = ServiceTicketCache.getInstance(CASConfiguration.getCacheTimeout());
	    	ServiceTicketCacheKey key = new ServiceTicketCacheKey( serviceTicketId );
	    	ServiceTicketCacheEntry entry = (ServiceTicketCacheEntry)cache.getValueFromCache( key );
	    	ticket = entry.getServiceTicket();
	    	ticket.updateState();
	    	
	    	// Service tickets get cleaned up after one use
	    	if( ticket.isExpired() ) {
	    		cache.clearCacheEntry(key);
	    	}
	    	
    	 } catch(Exception ex) {
    		 ticket = null;
    	 }
    	 
    	 return ticket;
    }
    
    public static TicketGrantingTicket createTicketGrantingTicket(String sessionDataKey, String username, boolean proxyRequest) {
    	TicketGrantingTicket ticket = new TicketGrantingTicket(sessionDataKey, username, proxyRequest);
    	TicketGrantingTicketCache cache = TicketGrantingTicketCache.getInstance( CASConfiguration.getCacheTimeout() );
    	TicketGrantingTicketCacheEntry entry = new TicketGrantingTicketCacheEntry();
    	entry.setTicketGrantingTicket( ticket );
    	
    	TicketGrantingTicketCacheKey key = new TicketGrantingTicketCacheKey(ticket.getId());
    	
    	cache.addToCache( key, entry );
    	
    	return ticket;
    }
    
    public static void storeServiceTicket(ServiceTicket ticket) {
    	ServiceTicketCache cache = ServiceTicketCache.getInstance( CASConfiguration.getCacheTimeout() );
    	ServiceTicketCacheEntry entry = new ServiceTicketCacheEntry();
    	entry.setServiceTicket(ticket);
    	
    	ServiceTicketCacheKey key = new ServiceTicketCacheKey(ticket.getId());
    	
    	cache.addToCache( key, entry );
    }
    
    public static boolean isValidTicketGrantingTicket(String ticketGrantingTicketId) {   	
    	try {
    		return getTicketGrantingTicket(ticketGrantingTicketId) != null;
    	} catch(Exception ex) {
    		return false;
    	}
    }
    
    public static TicketGrantingTicket getTicketGrantingTicket(String ticketGrantingTicketId) throws TicketNotFoundException {
    	TicketGrantingTicketCache cache = TicketGrantingTicketCache.getInstance( CASConfiguration.getCacheTimeout() );
    	
    	TicketGrantingTicketCacheKey key = new TicketGrantingTicketCacheKey(ticketGrantingTicketId);
    	
    	TicketGrantingTicketCacheEntry entry = (TicketGrantingTicketCacheEntry)cache.getValueFromCache(key);
    	
    	if( entry != null ) {
    		return entry.getTicketGrantingTicket();
    	} else {
    		throw new TicketNotFoundException("CAS ticket granting ticket " + ticketGrantingTicketId + " not found", ticketGrantingTicketId);
    	}
    }
    
    public static void removeSession(String ticketGrantingTicketId) {
    	try {
	    	TicketGrantingTicket ticket = CASSSOUtil.getTicketGrantingTicket(ticketGrantingTicketId);
	    	
	    	TicketGrantingTicketCache cache = TicketGrantingTicketCache.getInstance( CASConfiguration.getCacheTimeout() );
	    	TicketGrantingTicketCacheKey key = new TicketGrantingTicketCacheKey(ticket.getId());
	    	cache.clearCacheEntry(key);
	    	log.debug("CAS ticket granting ticket removed: " + ticketGrantingTicketId);
	        
    	} catch(Exception tnfe) {
    		log.error("CAS ticket granting ticket was not removed for " + ticketGrantingTicketId);
    	}
    }
    
    public static AuthenticationResult getAuthenticationResultFromCache(String sessionDataKey) {
    	
    	AuthenticationResultCacheKey authResultCacheKey = new AuthenticationResultCacheKey(sessionDataKey);
//		CacheEntry cacheEntry = AuthenticationResultCache.getInstance(CASConfiguration.getCacheTimeout()).getValueFromCache(authResultCacheKey);
		CacheEntry cacheEntry = AuthenticationResultCache.getInstance().getValueFromCache(authResultCacheKey);
		AuthenticationResult authResult = null;
		
		if (cacheEntry != null) {
			AuthenticationResultCacheEntry authResultCacheEntry = (AuthenticationResultCacheEntry)cacheEntry;
			authResult = authResultCacheEntry.getResult();
		} else {
			log.error("Cannot find AuthenticationResult in the cache");
		}
		
		return authResult;
    }
    
    public static Map<String, String> getUserClaimValues(String username, ClaimMapping[] claimMappings, String profile)
            throws IdentityException {
		Map<String, String> localClaimValues = null;
        try {
        	List<String> requestedClaims = new ArrayList<String>();
        	List<String> mappedClaims = new ArrayList<String>();
        	
        	UserRealm userRealm = AnonymousSessionUtil.getRealmByUserName(CASSSOUtil.getRegistryService(),
            		CASSSOUtil.getRealmService(),
                    username);
        	
            for( ClaimMapping claimMapping : claimMappings ) {
            	mappedClaims.add(claimMapping.getLocalClaim().getClaimUri());
            }

        	// Get all supported claims
        	ClaimManager claimManager = userRealm.getClaimManager();
            org.wso2.carbon.user.api.ClaimMapping[] mappings = claimManager.getAllSupportClaimMappingsByDefault();

            for( org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings ) {
            	requestedClaims.add(claimMapping.getClaim().getClaimUri());
            }
        	
            // Get claim values for the user
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            username = MultitenantUtils.getTenantAwareUsername(username);
            log.debug("getUserClaimValues: username="+username);
//            Map<String, String> localClaimValues = userStoreManager.getUserClaimValues(username, requestedClaims.toArray(new String[requestedClaims.size()]), profile);
			localClaimValues = userStoreManager.getUserClaimValues(username, requestedClaims.toArray(new String[requestedClaims.size()]), profile);

			String localClaimValue = null;
            String localClaimUri = null;
            String remoteClaimUri = null;
            
            // Remove the original claim URI and add the new mapped claim URI
            for( ClaimMapping claimMapping : claimMappings ) {
            	localClaimUri = claimMapping.getLocalClaim().getClaimUri();
            	localClaimValue = localClaimValues.get(localClaimUri);
            	remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
            	
            	log.debug("getUserClaimValues: localClaimUri="+localClaimUri + " ==> localClaimValue="+localClaimValue+" ==> remoteClaimUri="+remoteClaimUri);
            	
            	if( localClaimValue != null ) {
            		localClaimValues.remove(localClaimUri);
            		localClaimValues.put(remoteClaimUri, localClaimValue);
            	}
            }

            // Remove the original claim URI and add the mapped attribute
            for( org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings ) {
            	localClaimUri = claimMapping.getClaim().getClaimUri();
            	localClaimValue = localClaimValues.get(localClaimUri);
            	remoteClaimUri = claimMapping.getMappedAttribute();
            	
            	// Avoid re-inserting a mapped claim
            	if( localClaimValue != null && !mappedClaims.contains(localClaimUri) ) {
            		localClaimValues.remove(localClaimUri);
            		localClaimValues.put(remoteClaimUri, localClaimValue);
            	}
            }
            
            // Clean up old strings
    		localClaimUri = null;
    		localClaimValue = null;
    		remoteClaimUri = null;
            
//            return localClaimValues;
        } catch (UserStoreException e) {
            log.info("Error while retrieving claims values", e);
//            throw new IdentityException("Error while retrieving claims values", e);
        } catch (CarbonException e) {
            log.info("Error while retrieving claims values", e);
//            throw new IdentityException("Error while retrieving claim values", e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.info("Error while retrieving claims values", e);
//            throw new IdentityException("Error while retrieving claim values", e);
		}
		return localClaimValues;
    }
    
    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static RealmService getRealmService() {
        return realmService;
    }
    
    public static void setRegistryService(RegistryService registryService) {
        CASSSOUtil.registryService = registryService;
    }

    public static void setRealmService(RealmService realmService) {
    	CASSSOUtil.realmService = realmService;
    }
    
    public static String formatSoapDate(Date dateToFormat) {
    	return dateFormat.format(dateToFormat);
    }


	/*Newly added*/
	public static String getNotificationEndpoint(){
		String redirectURL = IdentityUtil.getProperty(IdentityConstants.ServerConfig
				.NOTIFICATION_ENDPOINT);
		if (StringUtils.isBlank(redirectURL)){
			redirectURL = IdentityUtil.getServerURL(CASSSOConstants.NOTIFICATION_ENDPOINT, false, false);
		}
		return redirectURL;
	}

	public static void setSingleLogoutRetryCount(int singleLogoutRetryCount) {
		CASSSOUtil.singleLogoutRetryCount = singleLogoutRetryCount;
	}

	public static long getSingleLogoutRetryInterval() {
		return singleLogoutRetryInterval;
	}

	public static void setSingleLogoutRetryInterval(long singleLogoutRetryInterval) {
		CASSSOUtil.singleLogoutRetryInterval = singleLogoutRetryInterval;
	}

	public static int getSAMLResponseValidityPeriod() {
		if (StringUtils.isNotBlank(IdentityUtil.getProperty(IdentityConstants.ServerConfig
				.SAML_RESPONSE_VALIDITY_PERIOD))) {
			return Integer.parseInt(IdentityUtil.getProperty(
					IdentityConstants.ServerConfig.SAML_RESPONSE_VALIDITY_PERIOD).trim());
		} else {
			return 5;
		}
	}

//	public static Assertion buildSAMLAssertion(SAMLMessageContext context, DateTime notOnOrAfter,
//											   String sessionId) throws IdentityException {
//
//		doBootstrap();
//		String assertionBuilderClass = null;
//		try {
//			assertionBuilderClass = IdentityUtil.getProperty("SSOService.SAMLSSOAssertionBuilder").trim();
//			if (StringUtils.isBlank(assertionBuilderClass)) {
//				assertionBuilderClass = DefaultSAMLAssertionBuilder.class.getName();
//			}
//		} catch (Exception e) {
//			if (log.isDebugEnabled()) {
//				log.debug("SAMLSSOAssertionBuilder configuration is set to default builder ", e);
//			}
//			assertionBuilderClass = DefaultSAMLAssertionBuilder.class.getName();
//		}
//
//		try {
//
//			synchronized (Runtime.getRuntime().getClass()) {
//				samlAssertionBuilder = (SAMLAssertionBuilder) Class.forName(assertionBuilderClass).newInstance();
//				samlAssertionBuilder.init();
//			}
//			return samlAssertionBuilder.buildAssertion(context, notOnOrAfter, sessionId);
//
//		} catch (ClassNotFoundException e) {
//			throw IdentityException.error("Class not found: "
//					+ assertionBuilderClass, e);
//		} catch (InstantiationException e) {
//			throw IdentityException.error("Error while instantiating class: "
//					+ assertionBuilderClass, e);
//		} catch (IllegalAccessException e) {
//			throw IdentityException.error("Illegal access to class: "
//					+ assertionBuilderClass, e);
//		} catch (Exception e) {
//			throw IdentityException.error("Error while building the saml assertion", e);
//		}
//	}


	public static String decodeForPost(String encodedStr)
			throws IdentityException {
		try {
			org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
			byte[] xmlBytes = encodedStr.getBytes(StandardCharsets.UTF_8.name());
			byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

			String decodedString = new String(base64DecodedByteArray, StandardCharsets.UTF_8.name());
			if (log.isDebugEnabled()) {
				log.debug("Request message " + decodedString);
			}
			return decodedString;

		} catch (IOException e) {
			throw IdentityException.error(
					"Error when decoding the SAML Request.", e);
		}

	}

	/**
	 * Decoding and deflating the encoded AuthReq
	 *
	 * @param encodedStr encoded AuthReq
	 * @return decoded AuthReq
	 */
	public static String decode(String encodedStr) throws IdentityException {
		try {
			org.apache.commons.codec.binary.Base64 base64Decoder =
					new org.apache.commons.codec.binary.Base64();
			byte[] xmlBytes = encodedStr.getBytes(StandardCharsets.UTF_8.name());
			byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

			try {
				Inflater inflater = new Inflater(true);
				inflater.setInput(base64DecodedByteArray);
				byte[] xmlMessageBytes = new byte[5000];
				int resultLength = inflater.inflate(xmlMessageBytes);

				if (!inflater.finished()) {
					throw new RuntimeException("End of the compressed data stream has NOT been reached");
				}

				inflater.end();
				String decodedString = new String(xmlMessageBytes, 0, resultLength, StandardCharsets.UTF_8.name());
				if (log.isDebugEnabled()) {
					log.debug("Request message " + decodedString);
				}
				return decodedString;

			} catch (DataFormatException e) {
				ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(base64DecodedByteArray);
				ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				InflaterInputStream iis = new InflaterInputStream(byteArrayInputStream);
				byte[] buf = new byte[1024];
				int count = iis.read(buf);
				while (count != -1) {
					byteArrayOutputStream.write(buf, 0, count);
					count = iis.read(buf);
				}
				iis.close();
				String decodedStr = new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);
				if (log.isDebugEnabled()) {
					log.debug("Request message " + decodedStr, e);
				}
				return decodedStr;
			}
		} catch (IOException e) {
			throw IdentityException.error("Error when decoding the SAML Request.", e);
		}

	}

	public static String getParameterFromQueryString(String queryString, String paraName) throws
			UnsupportedEncodingException {
		if (StringUtils.isNotBlank(queryString)) {
			String[] params = queryString.split("&");
			if (!ArrayUtils.isEmpty(params)) {
				for (String param : params) {
					if (StringUtils.equals(param.split("=")[0], paraName)) {
						return URLDecoder.decode(param.split("=")[1], StandardCharsets.UTF_8.name());
					}
				}
			}
		}
		return null;
	}
}
