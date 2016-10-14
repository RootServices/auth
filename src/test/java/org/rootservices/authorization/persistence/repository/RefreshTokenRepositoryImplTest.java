package org.rootservices.authorization.persistence.repository;

import helper.fixture.FixtureFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.persistence.entity.RefreshToken;
import org.rootservices.authorization.persistence.entity.Token;
import org.rootservices.authorization.persistence.exceptions.DuplicateRecordException;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;
import org.rootservices.authorization.persistence.mapper.RefreshTokenMapper;
import org.springframework.dao.DuplicateKeyException;

import java.util.UUID;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

/**
 * Created by tommackenzie on 10/3/16.
 */
public class RefreshTokenRepositoryImplTest {
    private RefreshTokenRepository subject;
    @Mock
    private RefreshTokenMapper mockRefreshTokenMapper;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new RefreshTokenRepositoryImpl(mockRefreshTokenMapper);
    }

    @Test
    public void insertShouldBeOk() throws Exception {
        // need to insert a head token.
        Token token = FixtureFactory.makeOpenIdToken();
        Token headToken = FixtureFactory.makeOpenIdToken();
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(token, headToken);

        subject.insert(refreshToken);
        verify(mockRefreshTokenMapper, times(1)).insert(refreshToken);
    }

    @Test
    public void insertShouldThrowDuplicateRecordException() throws Exception {
        Token token = FixtureFactory.makeOpenIdToken();
        Token headToken = FixtureFactory.makeOpenIdToken();
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(token, headToken);

        DuplicateKeyException dke = new DuplicateKeyException("");
        doThrow(dke).when(mockRefreshTokenMapper).insert(any(RefreshToken.class));

        DuplicateRecordException actual = null;
        try {
            subject.insert(refreshToken);
        } catch (DuplicateRecordException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getDomainCause(), is(dke));
    }

    @Test
    public void getByClientIdAndAccessTokenShouldBeOk() throws Exception {
        Token token = FixtureFactory.makeOpenIdToken();
        Token headToken = FixtureFactory.makeOpenIdToken();
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(token, headToken);

        UUID clientId = UUID.randomUUID();
        String accessToken = new String(refreshToken.getAccessToken());
        when(mockRefreshTokenMapper.getByClientIdAndAccessToken(clientId, accessToken)).thenReturn(refreshToken);

        RefreshToken actual = subject.getByClientIdAndAccessToken(clientId, accessToken);

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
        Token token = FixtureFactory.makeOpenIdToken();
        Token headToken = FixtureFactory.makeOpenIdToken();
        RefreshToken refreshToken = FixtureFactory.makeRefreshToken(token, headToken);

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
}