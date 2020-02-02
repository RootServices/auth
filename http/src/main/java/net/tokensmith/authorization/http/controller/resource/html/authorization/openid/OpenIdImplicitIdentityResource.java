package net.tokensmith.authorization.http.controller.resource.html.authorization.openid;


import net.tokensmith.otter.controller.Resource;
import net.tokensmith.otter.controller.entity.StatusCode;
import net.tokensmith.otter.controller.entity.request.Request;
import net.tokensmith.otter.controller.entity.response.Response;
import net.tokensmith.otter.controller.header.ContentType;
import net.tokensmith.otter.controller.header.Header;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import net.tokensmith.authorization.authenticate.exception.UnauthorizedException;
import net.tokensmith.authorization.exception.ServerException;
import net.tokensmith.authorization.http.controller.resource.html.authorization.helper.AuthorizationHelper;
import net.tokensmith.authorization.http.controller.security.WebSiteSession;
import net.tokensmith.authorization.http.controller.security.WebSiteUser;
import net.tokensmith.authorization.http.presenter.AuthorizationPresenter;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.request.ValidateOpenIdIdImplicitGrant;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.response.RequestOpenIdIdentity;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.response.entity.OpenIdImplicitIdentity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class OpenIdImplicitIdentityResource extends Resource<WebSiteSession, WebSiteUser> {
    private static final Logger logger = LoggerFactory.getLogger(OpenIdImplicitIdentityResource.class);

    private static String JSP_PATH = "/WEB-INF/jsp/authorization.jsp";
    protected static String EMAIL = "email";
    protected static String PASSWORD = "password";
    protected static String BLANK = "";

    private String globalCssPath;
    private AuthorizationHelper authorizationHelper;
    private ValidateOpenIdIdImplicitGrant validateOpenIdIdImplicitGrant;
    private RequestOpenIdIdentity requestOpenIdIdentity;

    public OpenIdImplicitIdentityResource() {}

    @Autowired
    public OpenIdImplicitIdentityResource(String globalCssPath, AuthorizationHelper authorizationHelper, ValidateOpenIdIdImplicitGrant validateOpenIdIdImplicitGrant, RequestOpenIdIdentity requestOpenIdIdentity) {
        this.globalCssPath = globalCssPath;
        this.authorizationHelper = authorizationHelper;
        this.validateOpenIdIdImplicitGrant = validateOpenIdIdImplicitGrant;
        this.requestOpenIdIdentity = requestOpenIdIdentity;
    }

    @Override
    public Response<WebSiteSession> get(Request<WebSiteSession, WebSiteUser> request, Response<WebSiteSession> response) {
        try {
            validateOpenIdIdImplicitGrant.run(request.getQueryParams());
        } catch (InformResourceOwnerException e) {
            authorizationHelper.prepareNotFoundResponse(globalCssPath, response);
            return response;
        } catch (InformClientException e) {
            authorizationHelper.prepareErrorResponse(response, e.getRedirectURI(), e.getError(), e.getDescription(), e.getState());
            return response;
        } catch (ServerException e) {
            logger.error(e.getMessage(), e);
            authorizationHelper.prepareServerErrorResponse(globalCssPath, response);
            return response;
        }

        AuthorizationPresenter presenter = authorizationHelper.makeAuthorizationPresenter(globalCssPath, BLANK, request.getCsrfChallenge().get());

        authorizationHelper.prepareResponse(response, StatusCode.OK, presenter, JSP_PATH);
        return response;
    }

    @Override
    public Response<WebSiteSession> post(Request<WebSiteSession, WebSiteUser> request, Response<WebSiteSession> response) {
        String userName = authorizationHelper.getFormValue(request.getFormData().get(EMAIL));
        String password = authorizationHelper.getFormValue(request.getFormData().get(PASSWORD));

        OpenIdImplicitIdentity identity;
        try {
            identity = requestOpenIdIdentity.request(userName, password, request.getQueryParams());
        } catch (UnauthorizedException e) {
            AuthorizationPresenter presenter = authorizationHelper.makeAuthorizationPresenter(globalCssPath, userName, request.getCsrfChallenge().get());
            authorizationHelper.prepareResponse(response, StatusCode.FORBIDDEN, presenter, JSP_PATH);
            return response;
        } catch (InformResourceOwnerException e) {
            authorizationHelper.prepareNotFoundResponse(globalCssPath, response);
            return response;
        } catch (InformClientException e) {
            authorizationHelper.prepareErrorResponse(response, e.getRedirectURI(), e.getError(), e.getDescription(), e.getState());
            return response;
        } catch (ServerException e) {
            logger.error(e.getMessage(), e);
            authorizationHelper.prepareServerErrorResponse(globalCssPath, response);
            return response;
        }


        response.getHeaders().put(Header.CONTENT_TYPE.getValue(), ContentType.FORM_URL_ENCODED.getValue());
        String location = authorizationHelper.makeRedirectURIForOpenIdIdentity(identity);;
        response.getHeaders().put(Header.LOCATION.getValue(), location);
        response.setStatusCode(StatusCode.MOVED_TEMPORARILY);

        WebSiteSession session = new WebSiteSession(
                identity.getSessionToken(),
                identity.getSessionTokenIssuedAt()
        );
        response.setSession(Optional.of(session));
        
        return response;
    }
}
