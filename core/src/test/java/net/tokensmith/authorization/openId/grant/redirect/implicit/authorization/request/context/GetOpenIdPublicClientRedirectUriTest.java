package net.tokensmith.authorization.openId.grant.redirect.implicit.authorization.request.context;

import helper.fixture.FixtureFactory;
import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.parser.exception.OptionalException;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.exceptions.RecordNotFoundException;
import net.tokensmith.repository.repo.ClientRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 8/12/16.
 */
public class GetOpenIdPublicClientRedirectUriTest {
    @Mock
    private ClientRepository mockClientRepository;
    private GetOpenIdPublicClientRedirectUri subject;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new GetOpenIdPublicClientRedirectUri(mockClientRepository);
    }

    @Test
    public void clientFoundRedirectMatchesShouldBeOK() throws URISyntaxException, RecordNotFoundException, InformClientException, InformResourceOwnerException {

        Client client = FixtureFactory.makeTokenClientWithOpenIdScopes();

        when(mockClientRepository.getById(client.getId())).thenReturn(client);

        Exception rootCause = new OptionalException();

        boolean actual = subject.run(client.getId(), client.getRedirectURI(), rootCause);
        assertThat(actual, is(true));
    }

    @Test
    public void clientNotFoundShouldThrowInformResourceOwnerException() throws RecordNotFoundException, URISyntaxException {
        UUID clientId = UUID.randomUUID();
        URI redirectURI = new URI("https://tokensmith.net");
        Exception rootCause = new OptionalException();

        when(mockClientRepository.getById(clientId)).thenThrow(RecordNotFoundException.class);

        try {
            subject.run(clientId, redirectURI, rootCause);
            fail("InformResourceOwnerException expected");
        } catch(InformClientException e) {
            fail("InformResourceOwnerException expected");
        } catch(InformResourceOwnerException e) {
            assertThat(e.getCause() instanceof RecordNotFoundException, is(true));
            assertThat(e.getCode(), is(ErrorCode.CLIENT_NOT_FOUND.getCode()));
        }
    }

    @Test
    public void redirectUriMismatchShouldThrowInformResourceOwnerException() throws RecordNotFoundException, URISyntaxException {

        URI redirectURI = new URI("https://tokensmith.net/mismatch");
        Exception rootCause = new OptionalException();

        Client client = FixtureFactory.makeTokenClientWithOpenIdScopes();

        when(mockClientRepository.getById(client.getId())).thenReturn(client);

        try {
            subject.run(client.getId(), redirectURI, rootCause);
            fail("InformResourceOwnerException expected");
        } catch(InformClientException e) {
            fail("InformResourceOwnerException expected");
        } catch(InformResourceOwnerException e) {
            assertThat(e.getCause() instanceof OptionalException, is(true));
            assertThat(e.getCode(), is(ErrorCode.REDIRECT_URI_MISMATCH.getCode()));
        }
    }

}