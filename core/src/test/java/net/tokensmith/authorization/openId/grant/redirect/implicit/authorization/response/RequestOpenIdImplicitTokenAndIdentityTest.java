package net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.response;

import helper.fixture.FixtureFactory;
import net.tokensmith.authorization.authenticate.CreateLocalToken;
import net.tokensmith.authorization.authenticate.LoginResourceOwner;
import net.tokensmith.authorization.authenticate.model.Session;
import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.authorization.exception.ServerException;
import net.tokensmith.authorization.oauth2.grant.redirect.implicit.authorization.response.IssueTokenImplicitGrant;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenClaims;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenGraph;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenType;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.request.ValidateOpenIdIdImplicitGrant;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.request.entity.OpenIdImplicitAuthRequest;
import net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.response.entity.OpenIdImplicitAccessToken;
import net.tokensmith.authorization.openId.identity.MakeImplicitIdentityToken;
import net.tokensmith.authorization.openId.identity.exception.IdTokenException;
import net.tokensmith.authorization.openId.identity.exception.KeyNotFoundException;
import net.tokensmith.authorization.openId.identity.exception.ProfileNotFoundException;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.ResourceOwner;
import net.tokensmith.repository.repo.ClientRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 9/6/16.
 */
public class RequestOpenIdImplicitTokenAndIdentityTest {

    private RequestOpenIdImplicitTokenAndIdentity subject;

    @Mock
    private ValidateOpenIdIdImplicitGrant mockValidateOpenIdIdImplicitGrant;
    @Mock
    private LoginResourceOwner mockLoginResourceOwner;
    @Mock
    private IssueTokenImplicitGrant mockIssueTokenImplicitGrant;
    @Mock
    private MakeImplicitIdentityToken mockMakeImplicitIdentityToken;
    @Mock
    private CreateLocalToken mockCreateLocalToken;
    @Mock
    private ClientRepository mockClientRepository;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new RequestOpenIdImplicitTokenAndIdentity(
                mockValidateOpenIdIdImplicitGrant,
                mockLoginResourceOwner,
                mockIssueTokenImplicitGrant,
                mockMakeImplicitIdentityToken,
                mockCreateLocalToken,
                mockClientRepository,
                "https://sso.tokensmith.net"
        );
    }

    @Test
    public void requestShouldReturnToken() throws Exception {
        String responseType = "token id_token";
        UUID clientId = UUID.randomUUID();

        String userName = FixtureFactory.makeRandomEmail();
        String password = FixtureFactory.PLAIN_TEXT_PASSWORD;
        Map<String, List<String>> params = FixtureFactory.makeOpenIdParameters(clientId, responseType);

        OpenIdImplicitAuthRequest request = FixtureFactory.makeOpenIdImplicitAuthRequest(clientId);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        List<Client> audience = FixtureFactory.makeAudience(clientId);
        TokenGraph tokenGraph = FixtureFactory.makeImplicitTokenGraph(clientId, audience);
        tokenGraph.getToken().setCreatedAt(OffsetDateTime.now());

        List<String> scopesForIdToken = tokenGraph.getToken().getTokenScopes().stream()
                .map(item -> item.getScope().getName())
                .collect(Collectors.toList());

        ArgumentCaptor<TokenClaims> tcArgumentCaptor = ArgumentCaptor.forClass(TokenClaims.class);

        String idToken = "encoded-jwt";

        when(mockValidateOpenIdIdImplicitGrant.run(params)).thenReturn(request);
        when(mockLoginResourceOwner.run(userName, password)).thenReturn(resourceOwner);
        when(mockClientRepository.getById(clientId)).thenReturn(audience.get(0));
        when(mockIssueTokenImplicitGrant.run(request.getClientId(), resourceOwner, request.getScopes(), audience, Optional.of(request.getNonce()))).thenReturn(tokenGraph);
        when(mockMakeImplicitIdentityToken.makeForAccessToken(
                eq(tokenGraph.getPlainTextAccessToken()), eq(request.getNonce()), tcArgumentCaptor.capture(), eq(resourceOwner), eq(scopesForIdToken))
        ).thenReturn(idToken);

        Session localSession = new Session("local-token", OffsetDateTime.now().toEpochSecond());
        when(mockCreateLocalToken.makeAndRevokeSession(eq(resourceOwner.getId()), eq(1))).thenReturn(localSession);

        OpenIdImplicitAccessToken actual = subject.request(userName, password, params);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAccessToken(), is(tokenGraph.getPlainTextAccessToken()));
        assertThat(actual.getExpiresIn(), is(tokenGraph.getToken().getSecondsToExpiration()));
        assertThat(actual.getIdToken(), is(idToken));
        assertThat(actual.getRedirectUri(), is(request.getRedirectURI()));
        assertThat(actual.getState(), is(Optional.of("state")));
        assertThat(actual.getScope(), is(Optional.empty()));
        assertThat(actual.getTokenType(), is(TokenType.BEARER));
        assertThat(actual.getSessionToken(), is(localSession.getToken()));
        assertThat(actual.getSessionTokenIssuedAt(), is(localSession.getIssuedAt()));

        assertThat(tcArgumentCaptor.getValue().getIssuer(), is("https://sso.tokensmith.net"));
        assertThat(tcArgumentCaptor.getValue().getAudience(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getAudience().size(), is(1));
        assertThat(tcArgumentCaptor.getValue().getAudience().get(0), is(request.getClientId().toString()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getExpirationTime(), is(tokenGraph.getToken().getExpiresAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getAuthTime(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getNonce(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getNonce().isPresent(), is(true));
        assertThat(tcArgumentCaptor.getValue().getNonce().get(), is("nonce"));
    }

    @Test
    public void requestWhenServerErrorShouldThrowInformClientException() throws Exception {
        String responseType = "token id_token";
        UUID clientId = UUID.randomUUID();

        String userName = FixtureFactory.makeRandomEmail();
        String password = FixtureFactory.PLAIN_TEXT_PASSWORD;
        Map<String, List<String>> params = FixtureFactory.makeOpenIdParameters(clientId, responseType);

        OpenIdImplicitAuthRequest request = FixtureFactory.makeOpenIdImplicitAuthRequest(clientId);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        List<Client> audience = FixtureFactory.makeAudience(clientId);

        when(mockValidateOpenIdIdImplicitGrant.run(params)).thenReturn(request);

        when(mockLoginResourceOwner.run(userName, password)).thenReturn(resourceOwner);

        when(mockClientRepository.getById(clientId)).thenReturn(audience.get(0));

        ServerException se = new ServerException("test", null);
        when(mockIssueTokenImplicitGrant.run(request.getClientId(), resourceOwner, request.getScopes(), audience, Optional.of(request.getNonce()))).thenThrow(se);

        InformClientException expected = null;
        try {
            subject.request(userName, password, params);
        } catch (InformClientException actual) {
            expected = actual;
        }

        assertThat(expected, is(notNullValue()));
        assertThat(expected.getError(), is("server_error"));
        assertThat(expected.getDescription(), is(ErrorCode.SERVER_ERROR.getDescription()));
        assertThat(expected.getCode(), is(ErrorCode.SERVER_ERROR.getCode()));
        assertThat(expected.getRedirectURI(), is(request.getRedirectURI()));
        assertThat(expected.getState(), is(request.getState()));
        assertThat(expected.getCause(), instanceOf(ServerException.class));
    }

    @Test
    public void requestWhenProfileNotFoundShouldThrowInformClientException() throws Exception {

        String responseType = "token id_token";
        UUID clientId = UUID.randomUUID();

        String userName = FixtureFactory.makeRandomEmail();
        String password = FixtureFactory.PLAIN_TEXT_PASSWORD;
        Map<String, List<String>> params = FixtureFactory.makeOpenIdParameters(clientId, responseType);

        OpenIdImplicitAuthRequest request = FixtureFactory.makeOpenIdImplicitAuthRequest(clientId);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        List<Client> audience = FixtureFactory.makeAudience(clientId);
        TokenGraph tokenGraph = FixtureFactory.makeImplicitTokenGraph(clientId, audience);
        tokenGraph.getToken().setCreatedAt(OffsetDateTime.now());

        List<String> scopesForIdToken = tokenGraph.getToken().getTokenScopes().stream()
                .map(item -> item.getScope().getName())
                .collect(Collectors.toList());

        ArgumentCaptor<TokenClaims> tcArgumentCaptor = ArgumentCaptor.forClass(TokenClaims.class);

        ProfileNotFoundException pnfe = new ProfileNotFoundException("", null);

        when(mockValidateOpenIdIdImplicitGrant.run(params)).thenReturn(request);
        when(mockLoginResourceOwner.run(userName, password)).thenReturn(resourceOwner);
        when(mockClientRepository.getById(clientId)).thenReturn(audience.get(0));
        when(mockIssueTokenImplicitGrant.run(request.getClientId(), resourceOwner, request.getScopes(), audience, Optional.of(request.getNonce()))).thenReturn(tokenGraph);
        when(mockMakeImplicitIdentityToken.makeForAccessToken(
                eq(tokenGraph.getPlainTextAccessToken()), eq(request.getNonce()), tcArgumentCaptor.capture(), eq(resourceOwner), eq(scopesForIdToken))
        ).thenThrow(pnfe);

        InformClientException expected = null;
        try {
            subject.request(userName, password, params);
        } catch (InformClientException actual) {
            expected = actual;
        }

        assertThat(expected, is(notNullValue()));
        assertThat(expected.getError(), is("server_error"));
        assertThat(expected.getDescription(), is(ErrorCode.PROFILE_NOT_FOUND.getDescription()));
        assertThat(expected.getCode(), is(ErrorCode.PROFILE_NOT_FOUND.getCode()));
        assertThat(expected.getRedirectURI(), is(request.getRedirectURI()));
        assertThat(expected.getState(), is(request.getState()));
        assertThat(expected.getCause(), instanceOf(ProfileNotFoundException.class));

        assertThat(tcArgumentCaptor.getValue().getIssuer(), is("https://sso.tokensmith.net"));
        assertThat(tcArgumentCaptor.getValue().getAudience(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getAudience().size(), is(1));
        assertThat(tcArgumentCaptor.getValue().getAudience().get(0), is(request.getClientId().toString()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getExpirationTime(), is(tokenGraph.getToken().getExpiresAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getAuthTime(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
    }

    @Test
    public void requestWhenKeyNotFoundShouldThrowInformClientException() throws Exception {

        String responseType = "token id_token";
        UUID clientId = UUID.randomUUID();

        String userName = FixtureFactory.makeRandomEmail();
        String password = FixtureFactory.PLAIN_TEXT_PASSWORD;
        Map<String, List<String>> params = FixtureFactory.makeOpenIdParameters(clientId, responseType);

        OpenIdImplicitAuthRequest request = FixtureFactory.makeOpenIdImplicitAuthRequest(clientId);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        List<Client> audience = FixtureFactory.makeAudience(clientId);
        TokenGraph tokenGraph = FixtureFactory.makeImplicitTokenGraph(clientId, audience);
        tokenGraph.getToken().setCreatedAt(OffsetDateTime.now());

        List<String> scopesForIdToken = tokenGraph.getToken().getTokenScopes().stream()
                .map(item -> item.getScope().getName())
                .collect(Collectors.toList());

        ArgumentCaptor<TokenClaims> tcArgumentCaptor = ArgumentCaptor.forClass(TokenClaims.class);

        KeyNotFoundException knfe = new KeyNotFoundException("", null);

        when(mockValidateOpenIdIdImplicitGrant.run(params)).thenReturn(request);
        when(mockLoginResourceOwner.run(userName, password)).thenReturn(resourceOwner);
        when(mockClientRepository.getById(clientId)).thenReturn(audience.get(0));
        when(mockIssueTokenImplicitGrant.run(request.getClientId(), resourceOwner, request.getScopes(), audience, Optional.of(request.getNonce()))).thenReturn(tokenGraph);
        when(mockMakeImplicitIdentityToken.makeForAccessToken(
                eq(tokenGraph.getPlainTextAccessToken()), eq(request.getNonce()), tcArgumentCaptor.capture(), eq(resourceOwner), eq(scopesForIdToken))
        ).thenThrow(knfe);

        InformClientException expected = null;
        try {
            subject.request(userName, password, params);
        } catch (InformClientException actual) {
            expected = actual;
        }

        assertThat(expected, is(notNullValue()));
        assertThat(expected.getError(), is("server_error"));
        assertThat(expected.getDescription(), is(ErrorCode.SIGN_KEY_NOT_FOUND.getDescription()));
        assertThat(expected.getCode(), is(ErrorCode.SIGN_KEY_NOT_FOUND.getCode()));
        assertThat(expected.getRedirectURI(), is(request.getRedirectURI()));
        assertThat(expected.getState(), is(request.getState()));
        assertThat(expected.getCause(), instanceOf(KeyNotFoundException.class));

        assertThat(tcArgumentCaptor.getValue().getIssuer(), is("https://sso.tokensmith.net"));
        assertThat(tcArgumentCaptor.getValue().getAudience(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getAudience().size(), is(1));
        assertThat(tcArgumentCaptor.getValue().getAudience().get(0), is(request.getClientId().toString()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getExpirationTime(), is(tokenGraph.getToken().getExpiresAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getAuthTime(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
    }

    @Test
    public void requestWhenJwtEncodingErrorShouldThrowInformClientException() throws Exception {
        String responseType = "token id_token";
        UUID clientId = UUID.randomUUID();

        String userName = FixtureFactory.makeRandomEmail();
        String password = FixtureFactory.PLAIN_TEXT_PASSWORD;
        Map<String, List<String>> params = FixtureFactory.makeOpenIdParameters(clientId, responseType);

        OpenIdImplicitAuthRequest request = FixtureFactory.makeOpenIdImplicitAuthRequest(clientId);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        List<Client> audience = FixtureFactory.makeAudience(clientId);
        TokenGraph tokenGraph = FixtureFactory.makeImplicitTokenGraph(clientId, audience);
        tokenGraph.getToken().setCreatedAt(OffsetDateTime.now());

        List<String> scopesForIdToken = tokenGraph.getToken().getTokenScopes().stream()
                .map(item -> item.getScope().getName())
                .collect(Collectors.toList());

        ArgumentCaptor<TokenClaims> tcArgumentCaptor = ArgumentCaptor.forClass(TokenClaims.class);

        IdTokenException ide = new IdTokenException("", null);

        when(mockValidateOpenIdIdImplicitGrant.run(params)).thenReturn(request);
        when(mockLoginResourceOwner.run(userName, password)).thenReturn(resourceOwner);
        when(mockClientRepository.getById(clientId)).thenReturn(audience.get(0));
        when(mockIssueTokenImplicitGrant.run(request.getClientId(), resourceOwner, request.getScopes(), audience, Optional.of(request.getNonce()))).thenReturn(tokenGraph);
        when(mockMakeImplicitIdentityToken.makeForAccessToken(
                eq(tokenGraph.getPlainTextAccessToken()), eq(request.getNonce()), tcArgumentCaptor.capture(), eq(resourceOwner), eq(scopesForIdToken))
        ).thenThrow(ide);


        InformClientException expected = null;
        try {
            subject.request(userName, password, params);
        } catch (InformClientException actual) {
            expected = actual;
        }

        assertThat(expected, is(notNullValue()));
        assertThat(expected.getError(), is("server_error"));
        assertThat(expected.getDescription(), is(ErrorCode.JWT_ENCODING_ERROR.getDescription()));
        assertThat(expected.getCode(), is(ErrorCode.JWT_ENCODING_ERROR.getCode()));
        assertThat(expected.getRedirectURI(), is(request.getRedirectURI()));
        assertThat(expected.getState(), is(request.getState()));
        assertThat(expected.getCause(), instanceOf(IdTokenException.class));

        assertThat(tcArgumentCaptor.getValue().getIssuer(), is("https://sso.tokensmith.net"));
        assertThat(tcArgumentCaptor.getValue().getAudience(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getAudience().size(), is(1));
        assertThat(tcArgumentCaptor.getValue().getAudience().get(0), is(request.getClientId().toString()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(notNullValue()));
        assertThat(tcArgumentCaptor.getValue().getIssuedAt(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getExpirationTime(), is(tokenGraph.getToken().getExpiresAt().toEpochSecond()));
        assertThat(tcArgumentCaptor.getValue().getAuthTime(), is(tokenGraph.getToken().getCreatedAt().toEpochSecond()));
    }
}