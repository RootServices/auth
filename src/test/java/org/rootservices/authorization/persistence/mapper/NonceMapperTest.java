package org.rootservices.authorization.persistence.mapper;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.rootservices.authorization.persistence.entity.Nonce;
import org.rootservices.authorization.persistence.entity.NonceType;
import org.rootservices.authorization.persistence.entity.ResourceOwner;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;
import org.rootservices.authorization.security.RandomString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;


@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(value={"classpath:spring-auth-test.xml"})
@Transactional
public class NonceMapperTest {

    @Autowired
    private RandomString randomString;

    @Autowired
    private NonceTypeMapper nonceTypeMapper;

    @Autowired
    private ResourceOwnerMapper resourceOwnerMapper;

    @Autowired
    private NonceMapper subject;

    public Nonce insertNonce(String type) {

        NonceType nonceType = nonceTypeMapper.getByName(type);

        if (nonceType == null) {
            nonceType = new NonceType(UUID.randomUUID(), type, 120, OffsetDateTime.now());
            nonceTypeMapper.insert(nonceType);
        }

        byte [] password = "plainTextPassword".getBytes();
        ResourceOwner user = new ResourceOwner(UUID.randomUUID(), UUID.randomUUID() + "@rootservices.com", password);

        resourceOwnerMapper.insert(user);

        Nonce nonce = new Nonce();
        nonce.setId(UUID.randomUUID());
        nonce.setNonceType(nonceType);
        nonce.setResourceOwner(user);
        nonce.setCreatedAt(OffsetDateTime.now());
        nonce.setExpiresAt(OffsetDateTime.now().plusMinutes(10));

        String nonceValue = randomString.run();
        nonce.setNonce(nonceValue.getBytes());

        subject.insert(nonce);

        return nonce;
    }

    @Test
    public void insert() throws Exception {
        Nonce nonce = insertNonce("foo");

        Nonce actual = subject.getById(nonce.getId());

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(nonce.getId()));
        assertThat(actual.getNonce(), is("nonce".getBytes()));
        assertThat(actual.getRevoked(), is(false));
        assertThat(actual.getSpent(), is(false));
        assertThat(actual.getExpiresAt(), is(nonce.getExpiresAt()));
        assertThat(actual.getCreatedAt(), is(notNullValue()));

        Assert.assertThat(actual.getNonceType().getId(), is(nonce.getNonceType().getId()));
        Assert.assertThat(actual.getNonceType().getName(), is(nonce.getNonceType().getName()));
        Assert.assertThat(actual.getNonceType().getSecondsToExpiry(), is(86400));
        Assert.assertThat(actual.getNonceType().getCreatedAt(), is(notNullValue()));

        assertThat(actual.getResourceOwner().getId(), is(nonce.getResourceOwner().getId()));
        assertThat(actual.getResourceOwner().getEmail(), is(nonce.getResourceOwner().getEmail()));
        assertThat(actual.getResourceOwner().getPassword(), is(nonce.getResourceOwner().getPassword()));
        assertThat(actual.getResourceOwner().isEmailVerified(), is(false));
        assertThat(actual.getResourceOwner().getCreatedAt(), is(CoreMatchers.notNullValue()));
    }


    @Test
    public void getByTypeAndNonceShouldReturnRecord() throws Exception {
        Nonce nonce = insertNonce("bar");

        Nonce actual = subject.getByTypeAndNonce("bar","nonce");

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(nonce.getId()));
        assertThat(actual.getNonce(), is("nonce".getBytes()));
        assertThat(actual.getRevoked(), is(false));
        assertThat(actual.getSpent(), is(false));
        assertThat(actual.getExpiresAt(), is(nonce.getExpiresAt()));
        assertThat(actual.getCreatedAt(), is(notNullValue()));

        Assert.assertThat(actual.getNonceType().getId(), is(nonce.getNonceType().getId()));
        Assert.assertThat(actual.getNonceType().getName(), is(nonce.getNonceType().getName()));
        Assert.assertThat(actual.getNonceType().getSecondsToExpiry(), is(86400));
        Assert.assertThat(actual.getNonceType().getCreatedAt(), is(notNullValue()));

        assertThat(actual.getResourceOwner().getId(), is(nonce.getResourceOwner().getId()));
        assertThat(actual.getResourceOwner().getEmail(), is(nonce.getResourceOwner().getEmail()));
        assertThat(actual.getResourceOwner().getPassword(), is(nonce.getResourceOwner().getPassword()));
        assertThat(actual.getResourceOwner().isEmailVerified(), is(false));
        assertThat(actual.getResourceOwner().getCreatedAt(), is(CoreMatchers.notNullValue()));
    }

    @Test
    public void getByNonceShouldReturnRecord() throws Exception {
        Nonce nonce = insertNonce("bar");

        Nonce actual = subject.getByNonce("nonce");

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(nonce.getId()));
        assertThat(actual.getNonce(), is("nonce".getBytes()));
        assertThat(actual.getRevoked(), is(false));
        assertThat(actual.getSpent(), is(false));
        assertThat(actual.getExpiresAt(), is(nonce.getExpiresAt()));
        assertThat(actual.getCreatedAt(), is(notNullValue()));

        Assert.assertThat(actual.getNonceType().getId(), is(nonce.getNonceType().getId()));
        Assert.assertThat(actual.getNonceType().getName(), is(nonce.getNonceType().getName()));
        Assert.assertThat(actual.getNonceType().getSecondsToExpiry(), is(86400));
        Assert.assertThat(actual.getNonceType().getCreatedAt(), is(notNullValue()));

        assertThat(actual.getResourceOwner().getId(), is(nonce.getResourceOwner().getId()));
        assertThat(actual.getResourceOwner().getEmail(), is(nonce.getResourceOwner().getEmail()));
        assertThat(actual.getResourceOwner().getPassword(), is(nonce.getResourceOwner().getPassword()));
        assertThat(actual.getResourceOwner().isEmailVerified(), is(false));
        assertThat(actual.getResourceOwner().getCreatedAt(), is(CoreMatchers.notNullValue()));
    }

    @Test
    public void revokeUnSpent() {
        Nonce nonceToNotRevoke = insertNonce("foo");

        Nonce nonceToRevoke = insertNonce("foo");
        nonceToRevoke = subject.getById(nonceToRevoke.getId());

        // should not be spent..
        assertThat(nonceToRevoke.getSpent(), is(false));
        assertThat(nonceToRevoke.getRevoked(), is(false));

        subject.revokeUnSpent("foo", nonceToRevoke.getResourceOwner().getId());

        // should revoke the nonce
        Nonce actual = subject.getById(nonceToRevoke.getId());
        assertThat(actual.getSpent(), is(false));
        assertThat(actual.getRevoked(), is(true));

        // should NOT have revoked..
        Nonce actualNotRevoked = subject.getById(nonceToNotRevoke.getId());
        assertThat(actualNotRevoked.getSpent(), is(false));
        assertThat(actualNotRevoked.getRevoked(), is(false));
    }


    @Test
    public void setSpent() {
        Nonce nonce = insertNonce("foo");
        subject.setSpent(nonce.getId());

        Nonce actual = subject.getById(nonce.getId());

        assertThat(actual.getSpent(), is(true));
    }

}