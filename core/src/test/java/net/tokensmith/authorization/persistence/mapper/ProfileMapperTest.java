package net.tokensmith.authorization.persistence.mapper;

import helper.fixture.FixtureFactory;
import helper.fixture.TestAppConfig;
import net.tokensmith.repository.entity.Address;
import net.tokensmith.repository.entity.Gender;
import net.tokensmith.repository.entity.Name;
import net.tokensmith.repository.entity.Profile;
import net.tokensmith.repository.entity.ResourceOwner;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.AnnotationConfigContextLoader;
import org.springframework.transaction.annotation.Transactional;

import java.net.URISyntaxException;
import java.util.UUID;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 2/27/16.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes= TestAppConfig.class, loader= AnnotationConfigContextLoader.class)
@Transactional
public class ProfileMapperTest {

    @Autowired
    private ResourceOwnerMapper resourceOwnerMapper;

    @Autowired
    private AddressMapper addressMapper;

    @Autowired
    private GivenNameMapper givenNameMapper;

    @Autowired
    private FamilyNameMapper familyNameMapper;

    @Autowired
    private ProfileMapper subject;

    @Test
    public void insertShouldInsertProfile() throws URISyntaxException {
        ResourceOwner ro = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(ro);

        Profile profile = FixtureFactory.makeProfile(ro.getId());
        subject.insert(profile);
    }

    @Test
    public void insertEmptyValuesShouldInsertProfile() throws URISyntaxException {
        ResourceOwner ro = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(ro);

        Profile profile = new Profile();
        profile.setId(UUID.randomUUID());
        profile.setResourceOwnerId(ro.getId());
        profile.setPhoneNumberVerified(false);
        subject.insert(profile);
    }

    @Test
    public void getByIdShouldGetProfile() throws URISyntaxException {
        ResourceOwner ro = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(ro);

        Profile profile = FixtureFactory.makeProfile(ro.getId());
        subject.insert(profile);

        Profile actual = subject.getById(profile.getId());

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(notNullValue()));
        assertThat(actual.getResourceOwnerId(), is(notNullValue()));

        assertThat(actual.getName().isPresent(), is(true));
        assertThat(actual.getName().get(), is("Obi-Wan Kenobi"));
        assertThat(actual.getMiddleName().isPresent(), is(false));
        assertThat(actual.getNickName().isPresent(), is(true));
        assertThat(actual.getNickName().get(), is("Ben"));
        assertThat(actual.getPreferredUserName().isPresent(), is(true));
        assertThat(actual.getPreferredUserName().get(), is("Ben Kenobi"));
        assertThat(actual.getProfile().isPresent(), is(true));
        assertThat(actual.getProfile().get().toString(), is("http://starwars.wikia.com/wiki/Obi-Wan_Kenobi"));
        assertThat(actual.getPicture().isPresent(), is(true));
        assertThat(actual.getPicture().get().toString(), is("http://vignette1.wikia.nocookie.net/starwars/images/2/25/Kenobi_Maul_clash.png/revision/latest?cb=20130120033039"));
        assertThat(actual.getWebsite().isPresent(), is(true));
        assertThat(actual.getWebsite().get().toString(), is("http://starwars.wikia.com"));
        assertThat(actual.getGender().isPresent(), is(true));
        assertThat(actual.getGender().get(), is(Gender.MALE));
        assertThat(actual.getBirthDate().isPresent(), is(false));
        assertThat(actual.getZoneInfo().isPresent(), is(false));
        assertThat(actual.getLocale().isPresent(), is(false));
        assertThat(actual.getPhoneNumber().isPresent(), is(false));
        assertThat(actual.isPhoneNumberVerified(), is(false));
        assertThat(actual.getAddresses(), is(notNullValue()));
        assertThat(actual.getAddresses().size(), is(0));
        assertThat(actual.getGivenNames(), is(notNullValue()));
        assertThat(actual.getGivenNames().size(), is(0));
        assertThat(actual.getFamilyNames(), is(notNullValue()));
        assertThat(actual.getFamilyNames().size(), is(0));
        assertThat(actual.getUpdatedAt(), is(notNullValue()));
        assertThat(actual.getCreatedAt(), is(notNullValue()));
    }


    @Test
    public void getByResourceOwnerIdShouldGetProfile() throws URISyntaxException {
        ResourceOwner ro = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(ro);

        Profile profile = FixtureFactory.makeProfile(ro.getId());
        subject.insert(profile);

        Name givenName = FixtureFactory.makeGivenName(profile.getId());
        givenNameMapper.insert(givenName);

        Name familyName = FixtureFactory.makeFamilyName(profile.getId());
        familyNameMapper.insert(familyName);

        Address address = FixtureFactory.makeAddress(profile.getId());
        addressMapper.insert(address);

        Profile actual = subject.getByResourceId(ro.getId());

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(notNullValue()));
        assertThat(actual.getResourceOwnerId(), is(notNullValue()));

        assertThat(actual.getName().isPresent(), is(true));
        assertThat(actual.getName().get(), is("Obi-Wan Kenobi"));
        assertThat(actual.getMiddleName().isPresent(), is(false));
        assertThat(actual.getNickName().isPresent(), is(true));
        assertThat(actual.getNickName().get(), is("Ben"));
        assertThat(actual.getPreferredUserName().isPresent(), is(true));
        assertThat(actual.getPreferredUserName().get(), is("Ben Kenobi"));
        assertThat(actual.getProfile().isPresent(), is(true));
        assertThat(actual.getProfile().get().toString(), is("http://starwars.wikia.com/wiki/Obi-Wan_Kenobi"));
        assertThat(actual.getPicture().isPresent(), is(true));
        assertThat(actual.getPicture().get().toString(), is("http://vignette1.wikia.nocookie.net/starwars/images/2/25/Kenobi_Maul_clash.png/revision/latest?cb=20130120033039"));
        assertThat(actual.getWebsite().isPresent(), is(true));
        assertThat(actual.getWebsite().get().toString(), is("http://starwars.wikia.com"));
        assertThat(actual.getGender().isPresent(), is(true));
        assertThat(actual.getGender().get(), is(Gender.MALE));
        assertThat(actual.getBirthDate().isPresent(), is(false));
        assertThat(actual.getZoneInfo().isPresent(), is(false));
        assertThat(actual.getLocale().isPresent(), is(false));
        assertThat(actual.getPhoneNumber().isPresent(), is(false));
        assertThat(actual.isPhoneNumberVerified(), is(false));

        assertThat(actual.getAddresses(), is(notNullValue()));
        assertThat(actual.getAddresses().size(), is(1));
        assertThat(actual.getAddresses().get(0).getId(), is(address.getId()));
        assertThat(actual.getAddresses().get(0).getStreetAddress(), is(address.getStreetAddress()));
        assertThat(actual.getAddresses().get(0).getStreetAddress2(), is(address.getStreetAddress2()));
        assertThat(actual.getAddresses().get(0).getLocality(), is(address.getLocality()));
        assertThat(actual.getAddresses().get(0).getRegion(), is(address.getRegion()));
        assertThat(actual.getAddresses().get(0).getPostalCode(), is(address.getPostalCode()));
        assertThat(actual.getAddresses().get(0).getCountry(), is(address.getCountry()));
        assertThat(actual.getAddresses().get(0).getUpdatedAt(), is(notNullValue()));
        assertThat(actual.getAddresses().get(0).getCreatedAt(), is(notNullValue()));

        assertThat(actual.getGivenNames(), is(notNullValue()));
        assertThat(actual.getGivenNames().size(), is(1));
        assertThat(actual.getGivenNames().get(0).getId(), is(givenName.getId()));
        assertThat(actual.getGivenNames().get(0).getName(), is(givenName.getName()));
        assertThat(actual.getGivenNames().get(0).getCreatedAt(), is(notNullValue()));
        assertThat(actual.getGivenNames().get(0).getCreatedAt(), is(notNullValue()));

        assertThat(actual.getFamilyNames(), is(notNullValue()));
        assertThat(actual.getFamilyNames().size(), is(1));
        assertThat(actual.getFamilyNames().get(0).getId(), is(familyName.getId()));
        assertThat(actual.getFamilyNames().get(0).getName(), is(familyName.getName()));
        assertThat(actual.getFamilyNames().get(0).getCreatedAt(), is(notNullValue()));
        assertThat(actual.getFamilyNames().get(0).getCreatedAt(), is(notNullValue()));

        assertThat(actual.getUpdatedAt(), is(notNullValue()));
        assertThat(actual.getCreatedAt(), is(notNullValue()));
    }


    @Test
    public void updateWhenUpdateResourceOwnerIdShouldNotDoIt() throws Exception {
        ResourceOwner legit = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(legit);

        // the one that tries to steal it.
        ResourceOwner stealer = FixtureFactory.makeResourceOwner();
        resourceOwnerMapper.insert(stealer);

        Profile profile = FixtureFactory.makeProfile(legit.getId());
        subject.insert(profile);

        // try to re-assign to a different resource owner.
        profile.setResourceOwnerId(stealer.getId());

        subject.update(profile.getResourceOwnerId(), profile);

        Profile actual = subject.getById(profile.getId());

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getId(), is(notNullValue()));

        // make sure it did not happen.
        assertThat(actual.getResourceOwnerId(), is(legit.getId()));

    }
}