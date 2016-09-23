package org.wso2.carbon.identity.sso.cas.context;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.exception.ServiceProviderNotFoundException;
import org.wso2.carbon.identity.sso.cas.handler.ProtocolConstants;
import org.wso2.carbon.identity.sso.cas.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.cas.response.SAMLResponse;
import org.wso2.carbon.identity.sso.cas.util.ApplicationInfoProvider;
import org.wso2.carbon.ui.util.CharacterEncoder;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.Cookie;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.TimeZone;

public class CASMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {
    private static Log log = LogFactory.getLog(CASMessageContext.class);
    private static final String CAS_COOKIE_NAME = "CASTGC";
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    private static String ticketGrantingTicketId;
    private static RealmService realmService;
    private static final String LOAD_APP_NAMES_AND_AUTH_KEY_BY_TENANT_ID_AND_TYPE = "SELECT APP_NAME, INBOUND_AUTH_KEY "
            + "FROM SP_APP INNER JOIN SP_INBOUND_AUTH "
            + "ON SP_APP.ID = SP_INBOUND_AUTH.APP_ID "
            + "WHERE INBOUND_AUTH_TYPE = ? AND SP_APP.TENANT_ID = ? AND SP_INBOUND_AUTH.TENANT_ID=?";

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    private AuthnRequest authnRequest;
    private static String storedSessionDataKey = null;
    private static Cookie cookie;
    private SAMLSSOServiceProviderDO casssoServiceProviderDO;

    public CASMessageContext(SAMLIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    public static Cookie getTicketGrantingCookie(SAMLIdentityRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(CASMessageContext.CAS_COOKIE_NAME)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    @Override
    public SAMLIdentityRequest getRequest() {
        return (SAMLIdentityRequest) request;
    }

    public String getServiceURL(){
        return request.getParameter(ProtocolConstants.SERVICE_PROVIDER_ARGUMENT);
    }
    public AuthnRequest getAuthnRequest() {
        return authnRequest;
    }
    public String getRequestURI(){
        return request.getRequestURI();
    }
    public String getQueryString(){
       return request.getQueryString();
    }
    public void setAuthnRequest(AuthnRequest authnRequest) {
        this.authnRequest = authnRequest;
    }

    public static String getSessionDataKey(SAMLIdentityRequest req) {
//        Cookie authCookie = FrameworkUtils.getAuthCookie(req);
        Cookie authCookie = getAuthCookie(req);


        if (authCookie != null) {
            storedSessionDataKey = authCookie.getValue();
        }

        return storedSessionDataKey;
    }

    public void setSessionDataKey(String storedSessionDataKey) {
        this.storedSessionDataKey = storedSessionDataKey;
    }

    public static Cookie getAuthCookie(SAMLIdentityRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            Cookie[] arr$ = cookies;
            int len$ = cookies.length;

            for (int i$ = 0; i$ < len$; ++i$) {
                cookie = arr$[i$];
                if (cookie.getName().equals("commonAuthId")) {
                    return cookie;
                }
            }
        }

        return null;
    }

    public void setAuthCookie(Cookie cookie) {
        this.cookie = cookie;
    }

    public static String getTicketGrantingTicketId(SAMLIdentityRequest req) {

        Cookie ticketGrantingCookie = CASMessageContext.getTicketGrantingCookie(req);

        if (ticketGrantingCookie != null) {
            ticketGrantingTicketId = ticketGrantingCookie.getValue();
        }

        return ticketGrantingTicketId;
    }

    public void setTicketGrantingTicketId(String ticketGrantingTicketId) {
        this.ticketGrantingTicketId = ticketGrantingTicketId;
    }

    public void storeTicketGrantingCookie(String sessionId, SAMLIdentityRequest req, SAMLResponse resp,
                                          int sessionTimeout) {
        Cookie ticketGrantingCookie = getTicketGrantingCookie(req);
        if (ticketGrantingCookie == null) {
            ticketGrantingCookie = new Cookie(CASMessageContext.CAS_COOKIE_NAME, sessionId);
        }

        ticketGrantingCookie.setPath(CASConfiguration.getBasePath());
        ticketGrantingCookie.setSecure(true);
        resp.addCookie(ticketGrantingCookie);
    }

    //    public String getRelayState() {
//        return this.getRequest().getRelayState();
//    }
    public String getRelayState() {
        return ProtocolConstants.SERVICE_PROVIDER_ARGUMENT;
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
    public static String getServiceProviderNameByClientId(String serviceProviderUrl, String parameter,
                                                          String tenantDomain) throws IdentityApplicationManagementException {

        int tenantID = -1234;

        if (tenantDomain != null) {
            try {
                tenantID = realmService.getTenantManager().getTenantId(tenantDomain);
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
            storeAppPrepStmt = connection.prepareStatement(LOAD_APP_NAMES_AND_AUTH_KEY_BY_TENANT_ID_AND_TYPE);
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
}
