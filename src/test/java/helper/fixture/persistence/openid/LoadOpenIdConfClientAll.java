package helper.fixture.persistence.openid;

import helper.fixture.FixtureFactory;
import helper.fixture.persistence.LoadConfClientTokenReady;
import org.rootservices.authorization.persistence.entity.*;
import org.rootservices.authorization.persistence.exceptions.DuplicateRecordException;
import org.rootservices.authorization.persistence.repository.*;
import org.rootservices.authorization.security.HashTextStaticSalt;
import org.rootservices.authorization.security.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.net.URISyntaxException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Created by tommackenzie on 1/24/16.
 *
 * Loads all data associated with a confidential client.
 *  - scopes (openid)
 *  - resource owner
 *  - access request
 *  - access request scopes (openid)
 *  - auth code
 *  - token
 */
@Component
public class LoadOpenIdConfClientAll {
    private LoadConfClientTokenReady loadConfClientOpendIdTokenReady;
    private RandomString randomString;
    private HashTextStaticSalt hashText;
    private TokenRepository tokenRepository;
    private TokenScopeRepository tokenScopeRepository;
    private AuthCodeTokenRepository authCodeTokenRepository;
    private ClientTokenRepository clientTokenRepository;
    private ResourceOwnerTokenRepository resourceOwnerTokenRepository;
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public LoadOpenIdConfClientAll(LoadConfClientTokenReady loadConfClientOpendIdTokenReady, RandomString randomString, HashTextStaticSalt hashText, TokenRepository tokenRepository, TokenScopeRepository tokenScopeRepository, AuthCodeTokenRepository authCodeTokenRepository, ClientTokenRepository clientTokenRepository, ResourceOwnerTokenRepository resourceOwnerTokenRepository, RefreshTokenRepository refreshTokenRepository){
        this.loadConfClientOpendIdTokenReady = loadConfClientOpendIdTokenReady;
        this.randomString = randomString;
        this.tokenRepository = tokenRepository;
        this.tokenScopeRepository = tokenScopeRepository;
        this.authCodeTokenRepository = authCodeTokenRepository;
        this.clientTokenRepository = clientTokenRepository;
        this.resourceOwnerTokenRepository = resourceOwnerTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public AuthCode loadAuthCode(String plainTextAuthCode) throws DuplicateRecordException, URISyntaxException {
        AuthCode authCode = loadConfClientOpendIdTokenReady.run(true, false, plainTextAuthCode);
        return authCode;
    }

    public RefreshToken loadRefreshTokenForResourceOwner(String refreshAccessToken, OffsetDateTime tokenExpiresAt, UUID authCodeId, UUID clientId, UUID resourceOwnerId, List<Scope> scopesForToken) throws DuplicateRecordException {

        String accessToken = randomString.run();
        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId);
        token.setExpiresAt(tokenExpiresAt);
        token.setGrantType(GrantType.AUTHORIZATION_CODE);
        tokenRepository.insert(token);

        for(Scope scope: scopesForToken) {
            TokenScope ts = new TokenScope();
            ts.setId(UUID.randomUUID());
            ts.setScope(scope);
            ts.setTokenId(token.getId());
            tokenScopeRepository.insert(ts);
        }

        AuthCodeToken authCodeToken = new AuthCodeToken();
        authCodeToken.setId(UUID.randomUUID());
        authCodeToken.setTokenId(token.getId());
        authCodeToken.setAuthCodeId(authCodeId);
        authCodeTokenRepository.insert(authCodeToken);

        ClientToken clientToken = new ClientToken();
        clientToken.setId(UUID.randomUUID());
        clientToken.setClientId(clientId);
        clientToken.setTokenId(token.getId());
        clientTokenRepository.insert(clientToken);

        // now onto resource owner token
        ResourceOwner resourceOwner = new ResourceOwner();
        resourceOwner.setId(resourceOwnerId);

        ResourceOwnerToken rot = new ResourceOwnerToken();
        rot.setId(UUID.randomUUID());
        rot.setToken(token);
        rot.setResourceOwner(resourceOwner);
        resourceOwnerTokenRepository.insert(rot);

        String headAccessToken = randomString.run();
        Token headToken = FixtureFactory.makeOpenIdToken(headAccessToken, clientId);
        tokenRepository.insert(headToken);

        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token, headToken);
        refreshTokenRepository.insert(refreshToken);
        return refreshToken;
    }

    public RefreshToken loadRefreshTokenForClient(String refreshAccessToken, OffsetDateTime tokenExpiresAt, UUID authCodeId, UUID clientId, List<Scope> scopesForToken) throws DuplicateRecordException {
        String accessToken = randomString.run();
        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId);
        token.setToken(accessToken.getBytes());
        token.setExpiresAt(tokenExpiresAt);

        // TODO: need to change this once client_credentials is done.
        token.setGrantType(GrantType.AUTHORIZATION_CODE);
        tokenRepository.insert(token);

        for(Scope scope: scopesForToken) {
            TokenScope ts = new TokenScope();
            ts.setId(UUID.randomUUID());
            ts.setScope(scope);
            ts.setTokenId(token.getId());
            tokenScopeRepository.insert(ts);
        }

        AuthCodeToken authCodeToken = new AuthCodeToken();
        authCodeToken.setId(UUID.randomUUID());
        authCodeToken.setTokenId(token.getId());
        authCodeToken.setAuthCodeId(authCodeId);
        authCodeTokenRepository.insert(authCodeToken);

        ClientToken clientToken = new ClientToken();
        clientToken.setId(UUID.randomUUID());
        clientToken.setClientId(clientId);
        clientToken.setTokenId(token.getId());
        clientTokenRepository.insert(clientToken);

        String headAccessToken = randomString.run();
        Token headToken = FixtureFactory.makeOpenIdToken(headAccessToken, clientId);
        tokenRepository.insert(headToken);

        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token, headToken);
        refreshTokenRepository.insert(refreshToken);
        return refreshToken;
    }
}
