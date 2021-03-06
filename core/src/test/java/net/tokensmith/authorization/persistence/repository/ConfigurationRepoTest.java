package net.tokensmith.authorization.persistence.repository;

import net.tokensmith.authorization.persistence.mapper.ConfigurationMapper;
import net.tokensmith.repository.entity.Configuration;
import net.tokensmith.repository.repo.ConfigurationRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.UUID;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 11/5/16.
 */
public class ConfigurationRepoTest {
    private ConfigurationRepository subject;

    @Mock
    private ConfigurationMapper mockTokenSizeMapper;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new ConfigurationRepo(mockTokenSizeMapper);
    }

    @Test
    public void getShouldBeOk() {
        Configuration tokenSize = new Configuration();
        when(mockTokenSizeMapper.get()).thenReturn(tokenSize);

        Configuration actual = subject.get();

        assertThat(actual, is(notNullValue()));
    }

    @Test
    public void updateAccessTokenSizeShouldBeOk() {
        UUID id = UUID.randomUUID();
        Integer size = 50;

        subject.updateAccessTokenSize(id, size);
        verify(mockTokenSizeMapper, times(1)).updateAccessTokenSize(id, size);
    }

    @Test
    public void updateAuthorizationCodeSizeShouldBeOk() {
        UUID id = UUID.randomUUID();
        Integer size = 50;

        subject.updateAuthorizationCodeSize(id, size);
        verify(mockTokenSizeMapper, times(1)).updateAuthorizationCodeSize(id, size);
    }

    @Test
    public void updateRefreshTokenSizeShouldBeOk() {
        UUID id = UUID.randomUUID();
        Integer size = 50;

        subject.updateRefreshTokenSize(id, size);
        verify(mockTokenSizeMapper, times(1)).updateRefreshTokenSize(id, size);
    }

}