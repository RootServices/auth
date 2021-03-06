package net.tokensmith.authorization.nonce;

import net.tokensmith.authorization.security.RandomString;
import net.tokensmith.authorization.security.ciphers.HashToken;
import net.tokensmith.repository.entity.Nonce;
import net.tokensmith.repository.entity.NonceName;
import net.tokensmith.repository.entity.NonceType;
import net.tokensmith.repository.entity.ResourceOwner;
import net.tokensmith.repository.repo.NonceRepository;
import net.tokensmith.repository.repo.NonceTypeRepository;
import net.tokensmith.repository.repo.ResourceOwnerRepository;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class InsertNonceTest {
    private InsertNonce subject;
    @Mock
    private ResourceOwnerRepository mockResourceOwnerRepository;
    @Mock
    private RandomString mockRandomString;
    @Mock
    private HashToken mockHashToken;
    @Mock
    private NonceTypeRepository mockNonceTypeRepository;
    @Mock
    private NonceRepository mockNonceRepository;

    @Before
    public void setUp() {

        MockitoAnnotations.initMocks(this);
        subject = new InsertNonce(mockResourceOwnerRepository, mockRandomString, mockHashToken, mockNonceTypeRepository, mockNonceRepository);
    }

    @Test
    public void insertByEmailShouldInsertNonce() throws Exception {
        String email = "obi-wan@tokensmith.net";
        String nonce = "nonce";
        String hashedNonce = "hashedNonce";

        ResourceOwner ro = new ResourceOwner();
        when(mockResourceOwnerRepository.getByEmail(email)).thenReturn(ro);

        when(mockRandomString.run()).thenReturn(nonce);
        when(mockHashToken.run(nonce)).thenReturn(hashedNonce);

        NonceType nonceType = new NonceType(UUID.randomUUID(), "welcome", 120, OffsetDateTime.now());
        when(mockNonceTypeRepository.getByName(NonceName.WELCOME)).thenReturn(nonceType);

        String actual = subject.insert(email, NonceName.WELCOME);

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(nonce));

        ArgumentCaptor<Nonce> nonceCaptor = ArgumentCaptor.forClass(Nonce.class);
        verify(mockNonceRepository).insert(nonceCaptor.capture());

        assertThat(nonceCaptor.getValue().getId(), is(notNullValue()));
        assertThat(nonceCaptor.getValue().getResourceOwner(), is(ro));
        assertThat(nonceCaptor.getValue().getNonceType(), is(nonceType));
        assertThat(nonceCaptor.getValue().getNonce(), is(hashedNonce));
        assertThat(nonceCaptor.getValue().getExpiresAt(), is(notNullValue()));

    }

    @Test
    public void insertByResourceOwnerShouldInsertNonce() throws Exception {
        String nonce = "nonce";
        String hashedNonce = "hashedNonce";

        ResourceOwner ro = new ResourceOwner();

        when(mockRandomString.run()).thenReturn(nonce);
        when(mockHashToken.run(nonce)).thenReturn(hashedNonce);

        NonceType nonceType = new NonceType(UUID.randomUUID(), "welcome", 120, OffsetDateTime.now());
        when(mockNonceTypeRepository.getByName(NonceName.WELCOME)).thenReturn(nonceType);

        String actual = subject.insert(ro, NonceName.WELCOME);

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(nonce));

        ArgumentCaptor<Nonce> nonceCaptor = ArgumentCaptor.forClass(Nonce.class);
        verify(mockNonceRepository).insert(nonceCaptor.capture());

        assertThat(nonceCaptor.getValue().getId(), is(notNullValue()));
        assertThat(nonceCaptor.getValue().getResourceOwner(), is(ro));
        assertThat(nonceCaptor.getValue().getNonceType(), is(nonceType));
        assertThat(nonceCaptor.getValue().getNonce(), is(hashedNonce));
        assertThat(nonceCaptor.getValue().getExpiresAt(), is(notNullValue()));
    }
}