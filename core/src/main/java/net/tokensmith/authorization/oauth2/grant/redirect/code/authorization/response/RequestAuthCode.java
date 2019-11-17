package net.tokensmith.authorization.oauth2.grant.redirect.code.authorization.response;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.authorization.exception.ServerException;
import net.tokensmith.authorization.oauth2.grant.redirect.code.authorization.request.ValidateCodeGrant;
import net.tokensmith.authorization.oauth2.grant.redirect.code.authorization.request.context.GetConfidentialClientRedirectUri;
import net.tokensmith.authorization.authenticate.LoginResourceOwner;
import net.tokensmith.authorization.authenticate.exception.UnauthorizedException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.builder.InformClientExceptionBuilder;
import net.tokensmith.authorization.oauth2.grant.redirect.code.authorization.response.factory.AuthResponseFactory;
import net.tokensmith.authorization.oauth2.grant.redirect.code.authorization.response.exception.AuthCodeInsertException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.entity.AuthRequest;
import net.tokensmith.repository.entity.ResourceOwner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Created by tommackenzie on 4/16/15.
 *
 * Section 4.1.2
 */
@Component
public class RequestAuthCode {
    private static final Logger logger = LoggerFactory.getLogger(RequestAuthCode.class);

    private ValidateCodeGrant validateCodeGrant;
    protected LoginResourceOwner loginResourceOwner;
    protected IssueAuthCode issueAuthCode;
    protected AuthResponseFactory authResponseFactory;
    protected GetConfidentialClientRedirectUri getConfidentialClientRedirectUri;

    private static String MSG_TOKEN = "Failed to issue authorization code";
    private static String SERVER_ERROR = "server_error";

    public RequestAuthCode() {}

    @Autowired
    public RequestAuthCode(ValidateCodeGrant validateCodeGrant, LoginResourceOwner loginResourceOwner, IssueAuthCode issueAuthCode, AuthResponseFactory authResponseFactory, GetConfidentialClientRedirectUri getConfidentialClientRedirectUri) {
        this.validateCodeGrant = validateCodeGrant;
        this.loginResourceOwner = loginResourceOwner;
        this.issueAuthCode = issueAuthCode;
        this.authResponseFactory = authResponseFactory;
        this.getConfidentialClientRedirectUri = getConfidentialClientRedirectUri;
    }

    public AuthResponse run(String username, String password, Map<String, List<String>> parameters) throws UnauthorizedException, InformResourceOwnerException, InformClientException, ServerException {

        AuthRequest authRequest = validateCodeGrant.run(parameters);

        return makeAuthResponse(
            username,
            password,
            authRequest.getClientId(),
            authRequest.getRedirectURI(),
            authRequest.getScopes(),
            authRequest.getState()
        );
    }

    protected AuthResponse makeAuthResponse(String userName, String password, UUID clientId, Optional<URI> redirectUri, List<String> scopes, Optional<String> state) throws UnauthorizedException, InformResourceOwnerException, InformClientException {

        ResourceOwner resourceOwner = loginResourceOwner.run(userName, password);

        String authorizationCode;
        try {
            authorizationCode = issueAuthCode.run(
                    resourceOwner.getId(),
                    clientId,
                    redirectUri,
                    scopes
            );
        } catch (AuthCodeInsertException e) {
            logger.error(e.getMessage(), e);

            URI redirectURI = getConfidentialClientRedirectUri.run(clientId, redirectUri, e);
            ErrorCode ec = ErrorCode.SERVER_ERROR;
            throw new InformClientExceptionBuilder()
                    .setMessage(MSG_TOKEN)
                    .setError(SERVER_ERROR)
                    .setDescription(ec.getDescription())
                    .setErrorCode(ec.getCode())
                    .setRedirectURI(redirectURI)
                    .setState(state)
                    .setCause(e)
                    .build();
        }

        return authResponseFactory.makeAuthResponse(
                clientId,
                authorizationCode,
                state,
                redirectUri
        );
    }
}
