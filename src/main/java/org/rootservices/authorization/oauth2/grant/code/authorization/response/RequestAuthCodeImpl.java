package org.rootservices.authorization.oauth2.grant.code.authorization.response;

import org.rootservices.authorization.oauth2.grant.code.authorization.request.ValidateParams;
import org.rootservices.authorization.authenticate.LoginResourceOwner;
import org.rootservices.authorization.authenticate.exception.UnauthorizedException;
import org.rootservices.authorization.oauth2.grant.code.authorization.request.exception.InformClientException;
import org.rootservices.authorization.oauth2.grant.code.authorization.request.exception.InformResourceOwnerException;
import org.rootservices.authorization.oauth2.grant.code.authorization.response.exception.AuthCodeInsertException;
import org.rootservices.authorization.oauth2.grant.code.authorization.request.entity.AuthRequest;
import org.rootservices.authorization.oauth2.grant.code.authorization.response.builder.AuthResponseBuilder;
import org.rootservices.authorization.persistence.entity.ResourceOwner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Created by tommackenzie on 4/16/15.
 *
 * Section 4.1.2
 */
@Component("requestAuthCodeImpl")
public class RequestAuthCodeImpl implements RequestAuthCode {

    @Autowired
    private ValidateParams validateParams;
    @Autowired
    protected LoginResourceOwner loginResourceOwner;
    @Autowired
    protected GrantAuthCode grantAuthCode;
    @Autowired
    protected AuthResponseBuilder authResponseBuilder;

    public RequestAuthCodeImpl() {}

    public RequestAuthCodeImpl(ValidateParams validateParams, LoginResourceOwner loginResourceOwner, GrantAuthCode grantAuthCode, AuthResponseBuilder authResponseBuilder) {
        this.validateParams = validateParams;
        this.loginResourceOwner = loginResourceOwner;
        this.grantAuthCode = grantAuthCode;
        this.authResponseBuilder = authResponseBuilder;
    }

    @Override
    public AuthResponse run(AuthCodeInput input) throws UnauthorizedException, InformResourceOwnerException, InformClientException, AuthCodeInsertException {

        AuthRequest authRequest = validateParams.run(
            input.getClientIds(),
            input.getResponseTypes(),
            input.getRedirectUris(),
            input.getScopes(),
            input.getStates()
        );

        return makeAuthResponse(
                input.getUserName(),
                input.getPlainTextPassword(),
                authRequest.getClientId(),
                authRequest.getRedirectURI(),
                authRequest.getScopes(),
                authRequest.getState()
        );
    }

    protected AuthResponse makeAuthResponse(String userName, String password, UUID clientId, Optional<URI> redirectUri, List<String> scopes, Optional<String> state) throws UnauthorizedException, AuthCodeInsertException, InformResourceOwnerException {

        ResourceOwner resourceOwner = loginResourceOwner.run(userName, password);

        String authorizationCode = grantAuthCode.run(
                resourceOwner.getUuid(),
                clientId,
                redirectUri,
                scopes
        );

        return authResponseBuilder.run(
                clientId,
                authorizationCode,
                state,
                redirectUri
        );
    }
}