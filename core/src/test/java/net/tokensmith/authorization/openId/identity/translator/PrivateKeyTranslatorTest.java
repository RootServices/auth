package net.tokensmith.authorization.openId.identity.translator;

import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.Use;
import net.tokensmith.repository.entity.KeyUse;
import net.tokensmith.repository.entity.RSAPrivateKey;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 2/12/16.
 */
public class PrivateKeyTranslatorTest {

    private PrivateKeyTranslator subject;

    @Before
    public void setUp() {
        subject = new PrivateKeyTranslator();
    }

    @Test
    public void toShouldTranslate() throws Exception {
        RSAKeyPair keyPair = new RSAKeyPair(
                Optional.empty(),
                Use.SIGNATURE,
                new BigInteger("1"),
                new BigInteger("2"),
                new BigInteger("3"),
                new BigInteger("4"),
                new BigInteger("5"),
                new BigInteger("6"),
                new BigInteger("7"),
                new BigInteger("8")
        );

        RSAPrivateKey actual = subject.to(keyPair);

        assertThat(actual.getId(), is(nullValue()));
        assertThat(actual.getUse(), is(KeyUse.SIGNATURE));
        assertThat(actual.getModulus(), is(keyPair.getN()));
        assertThat(actual.getPublicExponent(), is(keyPair.getE()));
        assertThat(actual.getPrivateExponent(), is(keyPair.getD()));
        assertThat(actual.getPrimeP(), is(keyPair.getP()));
        assertThat(actual.getPrimeQ(), is(keyPair.getQ()));
        assertThat(actual.getPrimeExponentP(), is(keyPair.getDp()));
        assertThat(actual.getPrimeExponentQ(), is(keyPair.getDq()));
        assertThat(actual.getCrtCoefficient(), is(keyPair.getQi()));
    }

    @Test
    public void fromShouldTranslate() throws Exception {

        RSAPrivateKey privateKey = new RSAPrivateKey();
        privateKey.setId(UUID.randomUUID());
        privateKey.setUse(KeyUse.SIGNATURE);
        privateKey.setModulus(new BigInteger("1"));
        privateKey.setPublicExponent(new BigInteger("2"));
        privateKey.setPrivateExponent(new BigInteger("3"));
        privateKey.setPrimeP(new BigInteger("4"));
        privateKey.setPrimeQ(new BigInteger("5"));
        privateKey.setPrimeExponentP(new BigInteger("6"));
        privateKey.setPrimeExponentQ(new BigInteger("7"));
        privateKey.setCrtCoefficient(new BigInteger("8"));

        RSAKeyPair actual = subject.from(privateKey);

        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getN(), is(privateKey.getModulus()));
        assertThat(actual.getE(), is(privateKey.getPublicExponent()));
        assertThat(actual.getD(), is(privateKey.getPrivateExponent()));
        assertThat(actual.getP(), is(privateKey.getPrimeP()));
        assertThat(actual.getQ(), is(privateKey.getPrimeQ()));
        assertThat(actual.getDp(), is(privateKey.getPrimeExponentP()));
        assertThat(actual.getDq(), is(privateKey.getPrimeExponentQ()));
        assertThat(actual.getQi(), is(privateKey.getCrtCoefficient()));
    }
}