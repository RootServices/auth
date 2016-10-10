package org.rootservices.authorization.oauth2.grant.redirect.code.token;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.oauth2.grant.token.MakeRefreshToken;
import org.rootservices.authorization.persistence.entity.RefreshToken;
import org.rootservices.authorization.security.HashTextStaticSalt;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 10/4/16.
 */
public class MakeRefreshTokenTest {

    @Mock
    private HashTextStaticSalt mockHashText;
    private MakeRefreshToken subject;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        MockitoAnnotations.initMocks(this);
        subject = new MakeRefreshToken(mockHashText);
    }

    @Test
    public void runShouldBeOk() throws Exception {
        UUID tokenId = UUID.randomUUID();
        String plainTextToken = "token";
        String hashedToken = "hashedToken";
        when(mockHashText.run(plainTextToken)).thenReturn(hashedToken);

        RefreshToken actual = subject.run(tokenId, plainTextToken);

        assertThat(actual.getId(), is(notNullValue()));
        assertThat(actual.getId(), is(notNullValue()));
        assertThat(actual.getTokenId(), is(tokenId));
        assertThat(actual.getAccessToken(), is(hashedToken.getBytes()));
        assertThat(actual.getExpiresAt(), is(notNullValue()));
    }

}