package net.tokensmith.authorization.oauth2.grant.redirect.implicit.authorization.response;

import net.tokensmith.authorization.authenticate.CreateLocalToken;
import net.tokensmith.authorization.authenticate.LoginResourceOwner;
import net.tokensmith.authorization.authenticate.exception.LocalSessionException;
import net.tokensmith.authorization.authenticate.exception.UnauthorizedException;
import net.tokensmith.authorization.authenticate.model.Session;
import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.authorization.exception.ServerException;
import net.tokensmith.authorization.oauth2.grant.redirect.implicit.authorization.request.ValidateImplicitGrant;
import net.tokensmith.authorization.oauth2.grant.redirect.implicit.authorization.response.entity.ImplicitAccessToken;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.entity.AuthRequest;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.builder.InformClientExceptionBuilder;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenGraph;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenType;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.ResourceOwner;
import net.tokensmith.repository.exceptions.RecordNotFoundException;
import net.tokensmith.repository.repo.ClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Requests an access token for the token grant flow
 */
@Component
public class RequestAccessToken {
    private static final Logger logger = LoggerFactory.getLogger(RequestAccessToken.class);

    private LoginResourceOwner loginResourceOwner;
    private ValidateImplicitGrant validateImplicitGrant;
    private IssueTokenImplicitGrant issueTokenImplicitGrant;
    private CreateLocalToken createLocalToken;
    private ClientRepository clientRepository;

    private static String MSG_TOKEN = "Failed to issue token";
    private static String SERVER_ERROR = "server_error";

    @Autowired
    public RequestAccessToken(LoginResourceOwner loginResourceOwner, ValidateImplicitGrant validateImplicitGrant, IssueTokenImplicitGrant issueTokenImplicitGrant, CreateLocalToken createLocalToken, ClientRepository clientRepository) {
        this.loginResourceOwner = loginResourceOwner;
        this.validateImplicitGrant = validateImplicitGrant;
        this.issueTokenImplicitGrant = issueTokenImplicitGrant;
        this.createLocalToken = createLocalToken;
        this.clientRepository = clientRepository;
    }

    public ImplicitAccessToken requestToken(String userName, String password, Map<String, List<String>> parameters) throws InformClientException, InformResourceOwnerException, UnauthorizedException, ServerException {

        AuthRequest authRequest = validateImplicitGrant.run(parameters);
        ResourceOwner resourceOwner = loginResourceOwner.run(userName, password);
        URI redirectURI = getRedirectURI(authRequest.getRedirectURI(), authRequest.getClientId());
        List<Client> audience = makeAudience(authRequest.getClientId());

        TokenGraph tokenGraph;
        Session localSession;
        try {
            tokenGraph = issueTokenImplicitGrant.run(
                    authRequest.getClientId(),
                    resourceOwner,
                    authRequest.getScopes(),
                    audience,
                    Optional.empty()
            );

            localSession = createLocalToken.makeAndRevokeSession(resourceOwner.getId(), 1);
        } catch (ServerException | LocalSessionException e) {
            logger.error(e.getMessage(), e);

            ErrorCode ec = ErrorCode.SERVER_ERROR;
            throw new InformClientExceptionBuilder()
                    .setMessage(MSG_TOKEN)
                    .setError(SERVER_ERROR)
                    .setDescription(ec.getDescription())
                    .setErrorCode(ec.getCode())
                    .setRedirectURI(redirectURI)
                    .setState(authRequest.getState())
                    .setCause(e)
                    .build();
        }
        return translate(
                redirectURI,
                tokenGraph.getPlainTextAccessToken(),
                tokenGraph.getToken().getSecondsToExpiration(),
                authRequest.getScopes(),
                authRequest.getState(),
                localSession
        );
    }

    private URI getRedirectURI(Optional<URI> requestRedirectURI, UUID clientId) throws InformResourceOwnerException {
        URI redirectUri;
        if (requestRedirectURI.isPresent()) {
            redirectUri = requestRedirectURI.get();
        } else {
            redirectUri = fetchClientRedirectURI(clientId);
        }
        return redirectUri;
    }

    private URI fetchClientRedirectURI(UUID clientId) throws InformResourceOwnerException {

        try {
            Client client = clientRepository.getById(clientId);
            return client.getRedirectURI();
        } catch (RecordNotFoundException e) {
            throw new InformResourceOwnerException(
                    ErrorCode.CLIENT_NOT_FOUND.getDescription(), e, ErrorCode.CLIENT_NOT_FOUND.getCode()
            );
        }
    }

    private List<Client> makeAudience(UUID clientId) throws InformResourceOwnerException {
        List<Client> audience = new ArrayList<>();

        Client client;
        try {
            client = clientRepository.getById(clientId);
        } catch (RecordNotFoundException e) {
            throw new InformResourceOwnerException(
                    ErrorCode.CLIENT_NOT_FOUND.getDescription(), e, ErrorCode.CLIENT_NOT_FOUND.getCode()
            );
        }
        audience.add(client);
        return audience;
    }

    private ImplicitAccessToken translate(URI redirectUri, String accessToken, Long secondsToExpiration, List<String> scopes, Optional<String> state, Session localSession) {

        Optional<String> scopesForToken = Optional.empty();
        if (scopes != null && scopes.size() > 0) {
            scopesForToken = Optional.of(scopes.stream().map(i -> i.toString()).collect(Collectors.joining(" ")));
        }

        return new ImplicitAccessToken(
                redirectUri,
                accessToken,
                TokenType.BEARER,
                secondsToExpiration,
                scopesForToken,
                state,
                localSession.getToken(),
                localSession.getIssuedAt()
        );
    }
}
