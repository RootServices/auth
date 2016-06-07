package org.rootservices.authorization.openId.grant.code.authorization.request;

import helper.fixture.FixtureFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.constant.ErrorCode;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.exception.InformClientException;
import org.rootservices.authorization.oauth2.grant.redirect.authorization.request.exception.InformResourceOwnerException;
import org.rootservices.authorization.openId.grant.code.authorization.request.entity.OpenIdAuthRequest;
import org.rootservices.authorization.persistence.entity.Client;
import org.rootservices.authorization.persistence.entity.ConfidentialClient;
import org.rootservices.authorization.persistence.entity.ResponseType;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;
import org.rootservices.authorization.persistence.repository.ConfidentialClientRepository;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.fest.assertions.api.Assertions.assertThat;
import static org.fest.assertions.api.Assertions.fail;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 9/30/15.
 */
public class CompareConfidentialClientToOpenIdAuthRequestImplTest {
    @Mock
    private ConfidentialClientRepository mockConfidentialClientRepository;

    private CompareConfidentialClientToOpenIdAuthRequest subject;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new CompareConfidentialClientToOpenIdAuthRequestImpl(mockConfidentialClientRepository);
    }

    @Test
    public void shouldBeOk() throws URISyntaxException, RecordNotFoundException, InformClientException, InformResourceOwnerException {
        Client client = FixtureFactory.makeCodeClientWithOpenIdScopes();
        ConfidentialClient confidentialClient = FixtureFactory.makeConfidentialClient(client);

        OpenIdAuthRequest openIdAuthRequest = new OpenIdAuthRequest();
        openIdAuthRequest.setClientId(client.getUuid());
        openIdAuthRequest.setResponseType(client.getResponseType());
        openIdAuthRequest.setRedirectURI(client.getRedirectURI());
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        openIdAuthRequest.setScopes(scopes);

        when(mockConfidentialClientRepository.getByClientId(
                openIdAuthRequest.getClientId())
        ).thenReturn(confidentialClient);

        boolean isValid = subject.run(openIdAuthRequest);
        assertThat(isValid).isTrue();
    }

    @Test
    public void runClientNotFoundShouldThrowInformResourceOwnerException() throws RecordNotFoundException {
        UUID uuid = UUID.randomUUID();

        OpenIdAuthRequest openIdAuthRequest = new OpenIdAuthRequest();
        openIdAuthRequest.setClientId(uuid);
        openIdAuthRequest.setResponseType(ResponseType.CODE);
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        openIdAuthRequest.setScopes(scopes);

        when(mockConfidentialClientRepository.getByClientId(
                openIdAuthRequest.getClientId())
        ).thenThrow(RecordNotFoundException.class);

        try {
            subject.run(openIdAuthRequest);
            fail("Expected InformResourceOwnerException");
        } catch (InformResourceOwnerException e) {
            assertThat(e.getCode()).isEqualTo(ErrorCode.CLIENT_NOT_FOUND.getCode());
        } catch (InformClientException e) {
            fail("Expected InformResourceOwnerException");
        }
    }

    @Test
    public void responseTypeMismatchShouldThrowInformClientException() throws RecordNotFoundException, URISyntaxException {
        Client client = FixtureFactory.makeCodeClientWithOpenIdScopes();
        ConfidentialClient confidentialClient = FixtureFactory.makeConfidentialClient(client);

        OpenIdAuthRequest openIdAuthRequest = new OpenIdAuthRequest();
        openIdAuthRequest.setClientId(client.getUuid());
        openIdAuthRequest.setResponseType(ResponseType.CODE);
        openIdAuthRequest.setRedirectURI(client.getRedirectURI());
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        openIdAuthRequest.setScopes(scopes);

        client.setResponseType(ResponseType.TOKEN);

        when(mockConfidentialClientRepository.getByClientId(
                openIdAuthRequest.getClientId())
        ).thenReturn(confidentialClient);

        try {
            subject.run(openIdAuthRequest);
            fail("Expected InformClientException");
        } catch (InformResourceOwnerException e) {
            fail("Expected InformClientException");
        } catch (InformClientException e) {
            assertThat(e.getCode()).isEqualTo(ErrorCode.RESPONSE_TYPE_MISMATCH.getCode());
            assertTrue(e.getError().equals("unauthorized_client"));
            assertTrue(e.getRedirectURI().equals(client.getRedirectURI()));
        }
    }

    @Test
    public void redirectUriMismatchShouldThrowInformResourceOwnerException() throws RecordNotFoundException, URISyntaxException {
        Client client = FixtureFactory.makeCodeClientWithOpenIdScopes();
        ConfidentialClient confidentialClient = FixtureFactory.makeConfidentialClient(client);

        URI requestRedirectUri = new URI("https://rootservices.org/mismatch");

        OpenIdAuthRequest openIdAuthRequest = new OpenIdAuthRequest();
        openIdAuthRequest.setClientId(client.getUuid());
        openIdAuthRequest.setResponseType(ResponseType.CODE);
        openIdAuthRequest.setRedirectURI(requestRedirectUri);
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        openIdAuthRequest.setScopes(scopes);

        when(mockConfidentialClientRepository.getByClientId(
                openIdAuthRequest.getClientId())
        ).thenReturn(confidentialClient);

        try {
            subject.run(openIdAuthRequest);
            fail("Expected InformResourceOwnerException");
        } catch (InformResourceOwnerException e) {
            assertThat(e.getCode()).isEqualTo(ErrorCode.REDIRECT_URI_MISMATCH.getCode());
        } catch (InformClientException e) {
            fail("Expected InformResourceOwnerException");
        }
    }

    @Test
    public void authRequestInvalidScopeShouldThrowInformClientException() throws URISyntaxException, RecordNotFoundException {
        Client client = FixtureFactory.makeCodeClientWithOpenIdScopes();
        ConfidentialClient confidentialClient = FixtureFactory.makeConfidentialClient(client);

        OpenIdAuthRequest openIdAuthRequest = new OpenIdAuthRequest();
        openIdAuthRequest.setClientId(client.getUuid());
        openIdAuthRequest.setResponseType(client.getResponseType());
        openIdAuthRequest.setRedirectURI(client.getRedirectURI());
        List<String> scopes = new ArrayList<>();
        scopes.add("invalid-scope");
        openIdAuthRequest.setScopes(scopes);

        when(mockConfidentialClientRepository.getByClientId(
                openIdAuthRequest.getClientId())
        ).thenReturn(confidentialClient);

        try {
            subject.run(openIdAuthRequest);
            fail("Expected InformClientException");
        } catch (InformResourceOwnerException e) {
            fail("Expected InformClientException");
        } catch (InformClientException e) {
            assertThat(e.getCode()).isEqualTo(ErrorCode.SCOPES_NOT_SUPPORTED.getCode());
            assertTrue(e.getError().equals("invalid_scope"));
            assertTrue(e.getRedirectURI().equals(client.getRedirectURI()));
        }
    }
}