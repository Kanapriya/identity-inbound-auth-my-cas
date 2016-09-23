package org.wso2.carbon.identity.sso.cas.requestHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.cas.handler.ProtocolConstants;
import org.wso2.carbon.identity.sso.cas.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by kanapriya on 9/20/16.
 */
public class simpleValidation {
    private static Log log = LogFactory.getLog(simpleValidation.class);
    private static String success = "yes\n%s\n";
    private static String failure = "no\n\n";

    public String buildResponse(SAMLIdentityRequest req) {
        String responseString;

        try {
            log.debug("CAS " + req.getRequestURI() + " query string: " + req.getQueryString());

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
}

