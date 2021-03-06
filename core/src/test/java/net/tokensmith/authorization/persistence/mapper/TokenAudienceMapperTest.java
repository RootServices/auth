package net.tokensmith.authorization.persistence.mapper;

import helper.fixture.FixtureFactory;
import helper.fixture.TestAppConfig;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.GrantType;
import net.tokensmith.repository.entity.Token;
import net.tokensmith.repository.entity.TokenAudience;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 10/2/16.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= TestAppConfig.class, loader= AnnotationConfigContextLoader.class)
@Transactional
public class TokenAudienceMapperTest {
    @Autowired
    private TokenAudienceMapper subject;
    @Autowired
    private ClientMapper clientMapper;
    @Autowired
    private TokenMapper tokenMapper;

    public UUID loadClient() throws Exception {
        Client client = FixtureFactory.makeTokenClientWithScopes();
        clientMapper.insert(client);
        return client.getId();
    }

    public UUID loadToken(String accessToken, UUID clientId) throws Exception {
        Token token = FixtureFactory.makeOAuthToken(accessToken, clientId, new ArrayList<>());
        token.setGrantType(GrantType.TOKEN);
        tokenMapper.insert(token);
        return token.getId();
    }

    @Test
    public void insertShouldBeOk() throws Exception {
        String accessToken = "access-token";
        UUID clientId = loadClient();
        UUID tokenId = loadToken(accessToken, clientId);

        TokenAudience clientToken = new TokenAudience();
        clientToken.setId(UUID.randomUUID());
        clientToken.setClientId(clientId);
        clientToken.setTokenId(tokenId);

        subject.insert(clientToken);

        TokenAudience actual = subject.getByTokenId(tokenId);
        assertThat(actual.getId(), is(clientToken.getId()));
        assertThat(actual.getClientId(), is(clientId));
        assertThat(actual.getTokenId(), is(tokenId));
        assertThat(actual.getCreatedAt(), is(notNullValue()));
        assertThat(actual.getUpdatedAt(), is(notNullValue()));
    }
}