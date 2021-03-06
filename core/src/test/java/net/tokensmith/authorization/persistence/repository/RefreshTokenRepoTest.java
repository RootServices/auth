package net.tokensmith.authorization.persistence.repository;

import helper.fixture.FixtureFactory;
import net.tokensmith.authorization.persistence.factory.DuplicateRecordExceptionFactory;
import net.tokensmith.authorization.persistence.mapper.RefreshTokenMapper;
import net.tokensmith.repository.entity.RefreshToken;
import net.tokensmith.repository.entity.Token;
import net.tokensmith.repository.exceptions.DuplicateRecordException;
import net.tokensmith.repository.exceptions.RecordNotFoundException;
import net.tokensmith.repository.repo.RefreshTokenRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.dao.DuplicateKeyException;

import java.util.ArrayList;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class RefreshTokenRepoTest {
    private RefreshTokenRepository subject;
    @Mock
    private RefreshTokenMapper mockRefreshTokenMapper;
    @Mock
    private DuplicateRecordExceptionFactory mockDuplicateRecordExceptionFactory;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new RefreshTokenRepo(mockRefreshTokenMapper, mockDuplicateRecordExceptionFactory);
    }

    @Test
    public void insertShouldBeOk() throws Exception {
        // need to insert a head token.
        UUID clientId = UUID.randomUUID();
        String accessToken = "access-token";
        String refreshAccessToken = "refresh-access-token";

        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId, new ArrayList<>());
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token);

        subject.insert(refreshToken);
        verify(mockRefreshTokenMapper, times(1)).insert(refreshToken);
    }

    @Test
    public void insertShouldThrowDuplicateRecordException() throws Exception {
        UUID clientId = UUID.randomUUID();
        String accessToken = "access-token";
        String refreshAccessToken = "refresh-access-token";

        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId, new ArrayList<>());
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token);

        DuplicateKeyException dke = new DuplicateKeyException("");
        doThrow(dke).when(mockRefreshTokenMapper).insert(any(RefreshToken.class));

        DuplicateRecordException dre = new DuplicateRecordException("message", dke);
        when(mockDuplicateRecordExceptionFactory.make(dke, "refresh_token")).thenReturn(dre);

        DuplicateRecordException actual = null;
        try {
            subject.insert(refreshToken);
        } catch (DuplicateRecordException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(dre));
    }

    @Test
    public void getByClientIdAndAccessTokenShouldBeOk() throws Exception {
        UUID clientId = UUID.randomUUID();
        String accessToken = "access-token";
        String refreshAccessToken = "refresh-access-token";

        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId, new ArrayList<>());
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token);

        String hashedAccessToken = new String(refreshToken.getAccessToken());
        when(mockRefreshTokenMapper.getByClientIdAndAccessToken(clientId, hashedAccessToken)).thenReturn(refreshToken);

        RefreshToken actual = subject.getByClientIdAndAccessToken(clientId, hashedAccessToken);

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(refreshToken));
    }

    @Test(expected = RecordNotFoundException.class)
    public void getByClientIdAndAccessTokenWhenNotFoundShouldThrowRecordNotFoundException() throws Exception {
        UUID clientId = UUID.randomUUID();
        String accessToken = "foo";
        when(mockRefreshTokenMapper.getByClientIdAndAccessToken(clientId, accessToken)).thenReturn(null);

        subject.getByClientIdAndAccessToken(clientId, accessToken);
    }

    @Test
    public void getByTokenIdShouldBeOk() throws Exception {
        UUID clientId = UUID.randomUUID();
        String accessToken = "access-token";
        String refreshAccessToken = "refresh-access-token";

        Token token = FixtureFactory.makeOpenIdToken(accessToken, clientId, new ArrayList<>());
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(refreshAccessToken, token);

        when(mockRefreshTokenMapper.getByTokenId(token.getId())).thenReturn(refreshToken);

        RefreshToken actual = subject.getByTokenId(token.getId());

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(refreshToken));
    }

    @Test(expected = RecordNotFoundException.class)
    public void getByTokenIdWhenNotFoundShouldThrowRecordNotFoundException() throws Exception {
        UUID tokenId = UUID.randomUUID();
        when(mockRefreshTokenMapper.getByTokenId(tokenId)).thenReturn(null);

        subject.getByTokenId(tokenId);
    }

    @Test
    public void revokeByAuthCodeIdShouldBeOk() {
        UUID authCodeId = UUID.randomUUID();

        subject.revokeByAuthCodeId(authCodeId);

        verify(mockRefreshTokenMapper, times(1)).revokeByAuthCodeId(authCodeId);
    }

    @Test
    public void revokeByTokenIdShouldBeOk() {
        UUID tokenId = UUID.randomUUID();

        subject.revokeByTokenId(tokenId);

        verify(mockRefreshTokenMapper, times(1)).revokeByTokenId(tokenId);
    }

    @Test
    public void revokeActiveShouldBeOk() {
        UUID resourceOwnerId = UUID.randomUUID();

        subject.revokeActive(resourceOwnerId);

        verify(mockRefreshTokenMapper, times(1)).revokeActive(resourceOwnerId);
    }
}