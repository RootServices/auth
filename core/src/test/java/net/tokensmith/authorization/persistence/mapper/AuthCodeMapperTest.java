package net.tokensmith.authorization.persistence.mapper;

import helper.fixture.FixtureFactory;
import helper.fixture.TestAppConfig;
import helper.fixture.persistence.LoadConfClientTokenReady;
import net.tokensmith.authorization.security.RandomString;
import net.tokensmith.authorization.security.ciphers.HashToken;
import net.tokensmith.repository.entity.AccessRequest;
import net.tokensmith.repository.entity.AuthCode;
import net.tokensmith.repository.entity.AuthCodeToken;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.ResourceOwner;
import net.tokensmith.repository.entity.Token;
import net.tokensmith.repository.exceptions.DuplicateRecordException;
import net.tokensmith.repository.repo.AccessRequestRepository;
import net.tokensmith.repository.repo.AuthCodeTokenRepository;
import net.tokensmith.repository.repo.ClientRepository;
import net.tokensmith.repository.repo.ResourceOwnerRepository;
import net.tokensmith.repository.repo.TokenRepository;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;
import org.springframework.transaction.annotation.Transactional;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 4/10/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= TestAppConfig.class, loader= AnnotationConfigContextLoader.class)
@Transactional
public class AuthCodeMapperTest {

    @Autowired
    private LoadConfClientTokenReady loadConfClientTokenReady;
    @Autowired
    private ClientRepository clientRepository;
    @Autowired
    private ResourceOwnerRepository resourceOwnerRepository;
    @Autowired
    private AccessRequestRepository accessRequestRepository;
    @Autowired
    private RandomString randomString;
    @Autowired
    private TokenRepository tokenRepository;
    @Autowired
    private AuthCodeTokenRepository authCodeTokenRepository;

    @Autowired
    private AuthCodeMapper subject;

    @Test
    public void insert() throws Exception {

        // prepare db for test.
        Client client = FixtureFactory.makeCodeClientWithScopes();
        clientRepository.insert(client);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        resourceOwnerRepository.insert(resourceOwner);

        AccessRequest accessRequest = FixtureFactory.makeAccessRequest(
                resourceOwner.getId(),
                client.getId()
        );
        accessRequestRepository.insert(accessRequest);
        // end prepare db for test.

        String plainTextAuthCode = randomString.run();
        AuthCode authCode = FixtureFactory.makeAuthCode(accessRequest, false, plainTextAuthCode);
        // id, active_code, revoked, access_request_id, expires_at
        subject.insert(authCode);
    }

    @Test
    public void insertDuplicateExpectDuplicateKeyException() throws Exception {

        // prepare db for test.
        Client client = FixtureFactory.makeCodeClientWithScopes();
        clientRepository.insert(client);

        ResourceOwner resourceOwner = FixtureFactory.makeResourceOwner();
        resourceOwnerRepository.insert(resourceOwner);

        AccessRequest accessRequest = FixtureFactory.makeAccessRequest(
                resourceOwner.getId(),
                client.getId()
        );
        accessRequestRepository.insert(accessRequest);
        // end prepare db for test.

        String plainTextAuthCode = randomString.run();
        AuthCode authCode = FixtureFactory.makeAuthCode(accessRequest, false, plainTextAuthCode);
        subject.insert(authCode);

        // insert duplicate.
        authCode.setId(UUID.randomUUID());

        DuplicateKeyException actual = null;
        try {
            subject.insert(authCode);
        } catch(DuplicateKeyException dke) {
            actual = dke;
        }
        assertThat(actual, is(notNullValue()));
        assertThat(actual.getMessage().contains("Detail: Key (active_code)"), is(true));
    }

    @Test
    public void getByClientIdAndAuthCodeShouldBeOk() throws Exception {

        String plainTextAuthCode = randomString.run();
        AuthCode expected = loadConfClientTokenReady.run(true, false, plainTextAuthCode);

        String code = new String(expected.getCode());
        AuthCode actual = subject.getByClientIdAndAuthCode(expected.getAccessRequest().getClientId(), code);

        assertThat(actual, notNullValue());
        assertThat(actual.getId(), is(expected.getId()));
        assertThat(actual.isRevoked(), is(false));

        // access request.
        AccessRequest ar = actual.getAccessRequest();
        assertThat(ar, notNullValue());
        assertThat(ar.getId(), is(expected.getAccessRequest().getId()));
        assertThat(ar.getResourceOwnerId(), is(expected.getAccessRequest().getResourceOwnerId()));

        // scopes
        assertThat(ar.getAccessRequestScopes(), is(notNullValue()));
        assertThat(ar.getAccessRequestScopes().size(), is(1));
        assertThat(ar.getAccessRequestScopes().get(0).getScope(), is(notNullValue()));
        assertThat(ar.getAccessRequestScopes().get(0).getScope().getName(), is("profile"));
        assertThat(ar.getRedirectURI().isPresent(), is(true));
        assertThat(ar.getRedirectURI().get().toString(), is(FixtureFactory.SECURE_REDIRECT_URI));

        assertThat(actual.getToken(), is(nullValue()));
    }

    @Test
    public void getByClientIdAndAuthCodeWhenRedirectURIIsNotPresent() throws Exception {
        String plainTextAuthCode = randomString.run();
        AuthCode expected = loadConfClientTokenReady.run(false, false, plainTextAuthCode);

        String code = new String(expected.getCode());
        AuthCode actual = subject.getByClientIdAndAuthCode(expected.getAccessRequest().getClientId(), code);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(expected.getId()));

        // access request.
        AccessRequest ar = actual.getAccessRequest();
        assertThat(ar, is(notNullValue()));
        assertThat(ar.getId(), is(expected.getAccessRequest().getId()));
        assertThat(ar.getAccessRequestScopes(), is(notNullValue()));
        assertThat(ar.getAccessRequestScopes().size(), is(1));
        assertThat(ar.getAccessRequestScopes().get(0).getScope(), is(notNullValue()));
        assertThat(ar.getAccessRequestScopes().get(0).getScope().getName(), is("profile"));
        assertThat(ar.getRedirectURI().isPresent(), is(false));

        assertThat(actual.getToken(), is(nullValue()));
    }


    @Test
    public void getByClientIdAndAuthCodeWhenCodeIsRevoked() throws URISyntaxException, DuplicateRecordException {
        String plainTextAuthCode = randomString.run();
        AuthCode expected = loadConfClientTokenReady.run(false, true, plainTextAuthCode);

        String code = new String(expected.getCode());
        AuthCode actual = subject.getByClientIdAndAuthCode(expected.getAccessRequest().getClientId(), code);
        assertThat(actual, is(nullValue()));

    }

    @Test
    public void getByClientIdAndAuthCodeWhenTokenIsPresent() throws Exception {
        // begin - prepare db for test.
        String plainTextAuthCode = randomString.run();
        AuthCode authCode = loadConfClientTokenReady.run(false, false, plainTextAuthCode);

        String plainTextToken = randomString.run();
        HashToken hashToken = FixtureFactory.hashToken();
        String accessToken = hashToken.run(plainTextToken);

        Token token = FixtureFactory.makeOpenIdToken(accessToken, authCode.getAccessRequest().getClientId(), new ArrayList<>());
        tokenRepository.insert(token);

        AuthCodeToken authCodeToken = new AuthCodeToken();
        authCodeToken.setId(UUID.randomUUID());
        authCodeToken.setTokenId(token.getId());
        authCodeToken.setAuthCodeId(authCode.getId());

        authCodeTokenRepository.insert(authCodeToken);
        // end - prepare db for test.

        AuthCode actual = subject.getByClientIdAndAuthCode(authCode.getAccessRequest().getClientId(), authCode.getCode());
        assertThat(actual, is(notNullValue()));

        // this test is just to make sure a token is present
        assertThat(actual.getToken(), is(notNullValue()));
        assertThat(actual.getToken().getId(), is(token.getId()));
        assertThat(actual.getToken().isRevoked(), is(false));
        assertThat(actual.getToken().getExpiresAt().toEpochSecond(), is(token.getExpiresAt().toEpochSecond()));
        assertThat(actual.getToken().getCreatedAt(), is(notNullValue()));
    }

    @Test
    public void revokeByIdShouldRevoke() throws Exception{
        String plainTextAuthCode = randomString.run();
        AuthCode authCodeToRevoke = loadConfClientTokenReady.run(false, false, plainTextAuthCode);

        // insert one more auth code to make sure it only updates one and not all of em.
        String plainTextAuthCode2 = randomString.run();
        AuthCode authCodeNotRevoked = loadConfClientTokenReady.run(false, false, plainTextAuthCode2);

        subject.revokeById(authCodeToRevoke.getId());

        AuthCode actual = subject.getById(authCodeToRevoke.getId());

        // the one it should have revoked.
        assertThat(actual.getId(), is(authCodeToRevoke.getId()));
        assertThat(actual.isRevoked(), is(true));

        // the one it should not have revoked.
        AuthCode actualNotRevoked = subject.getById(authCodeNotRevoked.getId());
        assertThat(actualNotRevoked.getId(), is(authCodeNotRevoked.getId()));
        assertThat(actualNotRevoked.isRevoked(), is(false));
    }
}
