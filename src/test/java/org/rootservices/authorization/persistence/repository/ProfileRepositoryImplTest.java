package org.rootservices.authorization.persistence.repository;

import helper.fixture.FixtureFactory;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.rootservices.authorization.persistence.entity.Profile;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;
import org.rootservices.authorization.persistence.mapper.ProfileMapper;

import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * Created by tommackenzie on 3/17/16.
 */
public class ProfileRepositoryImplTest {

    @Mock
    private ProfileMapper mockProfileMapper;

    private ProfileRepository subject;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        subject = new ProfileRepositoryImpl(mockProfileMapper);
    }

    @Test
    public void testGetByResourceOwnerIdShouldReturnProfile() throws Exception {
        Profile profile = FixtureFactory.makeProfile(UUID.randomUUID());
        when(mockProfileMapper.getByResourceId(profile.getResourceOwnerId())).thenReturn(profile);

        Profile actual = subject.getByResourceOwnerId(profile.getResourceOwnerId());
        assertThat(actual, is(profile));
    }

    @Test(expected = RecordNotFoundException.class)
    public void testGetByResourceOwnerIdShouldThrowRecordNotFound() throws Exception {
        UUID id = UUID.randomUUID();
        when(mockProfileMapper.getByResourceId(id)).thenReturn(null);

        subject.getByResourceOwnerId(id);
    }

}