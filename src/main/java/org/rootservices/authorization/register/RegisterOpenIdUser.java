package org.rootservices.authorization.register;

import org.rootservices.authorization.persistence.entity.Address;
import org.rootservices.authorization.persistence.entity.FamilyName;
import org.rootservices.authorization.persistence.entity.GivenName;
import org.rootservices.authorization.persistence.entity.ResourceOwner;
import org.rootservices.authorization.persistence.exceptions.DuplicateRecordException;
import org.rootservices.authorization.persistence.repository.*;
import org.rootservices.authorization.register.request.UserInfo;
import org.rootservices.authorization.register.translator.UserInfoTranslator;
import org.rootservices.authorization.security.HashTextRandomSalt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


@Component
public class RegisterOpenIdUser {
    private UserInfoTranslator userInfoTranslator;
    private ResourceOwnerRepository resourceOwnerRepository;
    private ProfileRepository profileRepository;
    private GivenNameRepository givenNameRepository;
    private FamilyNameRepository familyNameRepository;
    private AddressRepository addressRepository;
    private HashTextRandomSalt hashTextRandomSalt;

    private static String EMAIL_REQUIRED = "Email is empty or null";
    private static String PASSWORD_REQUIRED = "Password is empty or null";
    private static String EMPTY = "";
    private static String EMAIL_FIELD = "email";
    private static String REGISTER_ERROR = "Could not insert resource_owner";

    @Autowired
    public RegisterOpenIdUser(UserInfoTranslator userInfoTranslator, ResourceOwnerRepository resourceOwnerRepository, ProfileRepository profileRepository, GivenNameRepository givenNameRepository, FamilyNameRepository familyNameRepository, AddressRepository addressRepository, HashTextRandomSalt hashTextRandomSalt) {
        this.userInfoTranslator = userInfoTranslator;
        this.resourceOwnerRepository = resourceOwnerRepository;
        this.profileRepository = profileRepository;
        this.givenNameRepository = givenNameRepository;
        this.familyNameRepository = familyNameRepository;
        this.addressRepository = addressRepository;
        this.hashTextRandomSalt = hashTextRandomSalt;
    }


    public void run(UserInfo userInfo) throws RegisterException {

        validate(userInfo);

        byte[] hashedPassword = hashTextRandomSalt.run(userInfo.getPassword()).getBytes();
        ResourceOwner resourceOwner = userInfoTranslator.from(userInfo);
        resourceOwner.setPassword(hashedPassword);

        try {
            resourceOwnerRepository.insert(resourceOwner);
        } catch (DuplicateRecordException e) {
            RegisterError registerError = makeRegisterError(e);
            throw new RegisterException(REGISTER_ERROR, registerError, e);
        }

        profileRepository.insert(resourceOwner.getProfile());

        for(GivenName givenName: resourceOwner.getProfile().getGivenNames()) {
            givenNameRepository.insert(givenName);
        }

        for(FamilyName familyName: resourceOwner.getProfile().getFamilyNames()) {
            familyNameRepository.insert(familyName);
        }

        for(Address address: resourceOwner.getProfile().getAddresses()) {
            addressRepository.insert(address);
        }

        // TODO: send off the welcome/confirmation email.
    }

    protected RegisterError makeRegisterError(DuplicateRecordException e) {
        RegisterError registerError = RegisterError.UNKNOWN;
        if (e.getKey().isPresent() && EMAIL_FIELD.equals(e.getKey().get())) {
            registerError = RegisterError.EMAIL_TAKEN;
        }
        return registerError;
    }

    protected void validate(UserInfo userInfo) throws RegisterException {
        if (!hasValue(userInfo.getEmail())) {
            throw new RegisterException(EMAIL_REQUIRED, RegisterError.EMAIL_MISSING);
        }

        if (!hasValue(userInfo.getPassword())) {
            throw new RegisterException(PASSWORD_REQUIRED, RegisterError.PASSWORD_MISSING);
        }
    }

    protected Boolean hasValue(String value) {
        if (value == null || EMPTY.equals(value)) {
            return false;
        }
        return true;
    }
}