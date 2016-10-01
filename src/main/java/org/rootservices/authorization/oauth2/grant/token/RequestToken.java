package org.rootservices.authorization.oauth2.grant.token;

import org.rootservices.authorization.authenticate.exception.UnauthorizedException;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.token.entity.TokenResponse;
import org.rootservices.authorization.oauth2.grant.token.exception.*;
import org.rootservices.authorization.oauth2.grant.token.factory.RequestTokenGrantFactory;
import org.rootservices.authorization.oauth2.grant.token.translator.JsonToMapTranslator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.util.Map;
import java.util.UUID;

/**
 * Created by tommackenzie on 9/27/16.
 */
@Component
public class RequestToken {
    private JsonToMapTranslator jsonToMapTranslator;
    private BadRequestExceptionBuilder badRequestExceptionBuilder;
    private RequestTokenGrantFactory requestTokenGrantFactory;
    private static String GRANT_TYPE = "grant_type";

    @Autowired
    public RequestToken(JsonToMapTranslator jsonToMapTranslator, BadRequestExceptionBuilder badRequestExceptionBuilder, RequestTokenGrantFactory requestTokenGrantFactory) {
        this.jsonToMapTranslator = jsonToMapTranslator;
        this.badRequestExceptionBuilder = badRequestExceptionBuilder;
        this.requestTokenGrantFactory = requestTokenGrantFactory;
    }

    public TokenResponse request(String clientUserName, String clientPassword, BufferedReader request) throws BadRequestException, UnauthorizedException, NotFoundException {
        UUID clientId = null;
        try {
            clientId = UUID.fromString(clientUserName);
        } catch (IllegalArgumentException e) {
            throw new UnauthorizedException(ErrorCode.CLIENT_USERNAME_DATA_TYPE.getDescription(), e, ErrorCode.CLIENT_USERNAME_DATA_TYPE.getCode());
        }

        Map<String, String> tokenInput = null;
        try {
            tokenInput = jsonToMapTranslator.to(request);
        } catch (DuplicateKeyException e) {
            throw badRequestExceptionBuilder.DuplicateKey(e.getKey(), e.getCode(), e).build();
        } catch (InvalidPayloadException e) {
            throw badRequestExceptionBuilder.InvalidPayload(e.getCode(), e).build();
        }

        RequestTokenGrant requestTokenGrant = requestTokenGrantFactory.make(tokenInput.get(GRANT_TYPE));

        if (requestTokenGrant == null) {
            throw badRequestExceptionBuilder.InvalidKeyValue(GRANT_TYPE, ErrorCode.GRANT_TYPE_INVALID.getCode(), null).build();
        }

        TokenResponse tokenResponse = requestTokenGrant.request(clientId, clientPassword, tokenInput);
        return tokenResponse;
    }
}
