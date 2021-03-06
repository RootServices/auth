package net.tokensmith.repository.entity;

import java.net.URI;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Created by tommackenzie on 2/24/16.
 */
public class Profile {
    private UUID id;
    private UUID resourceOwnerId;
    private Optional<String> name;
    private Optional<String> middleName;
    private Optional<String> nickName;
    private Optional<String> preferredUserName;
    private Optional<URI> profile;
    private Optional<URI> picture;
    private Optional<URI> website;
    private Optional<Gender> gender;
    private Optional<LocalDate> birthDate;
    private Optional<String> zoneInfo;
    private Optional<String> locale;
    private Optional<String> phoneNumber;
    private Boolean phoneNumberVerified;
    
    private List<Address> addresses = new ArrayList<>();
    private List<Name> givenNames = new ArrayList<>();
    private List<Name> familyNames = new ArrayList<>();

    private OffsetDateTime updatedAt;
    private OffsetDateTime createdAt;

    public Profile() {
        this.name = Optional.empty();
        middleName = Optional.empty();
        nickName = Optional.empty();
        preferredUserName = Optional.empty();
        profile = Optional.empty();
        picture = Optional.empty();
        website = Optional.empty();
        gender = Optional.empty();
        birthDate = Optional.empty();
        zoneInfo = Optional.empty();
        locale = Optional.empty();
        phoneNumber = Optional.empty();
    }

    public Profile(UUID id, UUID resourceOwnerId) {
        this.id = id;
        this.resourceOwnerId = resourceOwnerId;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getResourceOwnerId() {
        return resourceOwnerId;
    }

    public void setResourceOwnerId(UUID resourceOwnerId) {
        this.resourceOwnerId = resourceOwnerId;
    }

    public Optional<String> getName() {
        return name;
    }

    public void setName(Optional<String> name) {
        this.name = name;
    }

    public Optional<String> getMiddleName() {
        return middleName;
    }

    public void setMiddleName(Optional<String> middleName) {
        this.middleName = middleName;
    }

    public Optional<String> getNickName() {
        return nickName;
    }

    public void setNickName(Optional<String> nickName) {
        this.nickName = nickName;
    }

    public Optional<String> getPreferredUserName() {
        return preferredUserName;
    }

    public void setPreferredUserName(Optional<String> preferredUserName) {
        this.preferredUserName = preferredUserName;
    }

    public Optional<URI> getProfile() {
        return profile;
    }

    public void setProfile(Optional<URI> profile) {
        this.profile = profile;
    }

    public Optional<URI> getPicture() {
        return picture;
    }

    public void setPicture(Optional<URI> picture) {
        this.picture = picture;
    }

    public Optional<URI> getWebsite() {
        return website;
    }

    public void setWebsite(Optional<URI> website) {
        this.website = website;
    }

    public Optional<Gender> getGender() {
        return gender;
    }

    public void setGender(Optional<Gender> gender) {
        this.gender = gender;
    }

    public Optional<LocalDate> getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(Optional<LocalDate> birthDate) {
        this.birthDate = birthDate;
    }

    public Optional<String> getZoneInfo() {
        return zoneInfo;
    }

    public void setZoneInfo(Optional<String> zoneInfo) {
        this.zoneInfo = zoneInfo;
    }

    public Optional<String> getLocale() {
        return locale;
    }

    public void setLocale(Optional<String> locale) {
        this.locale = locale;
    }

    public Optional<String> getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(Optional<String> phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public Boolean isPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public void setPhoneNumberVerified(Boolean phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
    }

    public List<Address> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<Address> addresses) {
        this.addresses = addresses;
    }

    public List<Name> getGivenNames() {
        return givenNames;
    }

    public void setGivenNames(List<Name> givenNames) {
        this.givenNames = givenNames;
    }

    public List<Name> getFamilyNames() {
        return familyNames;
    }

    public void setFamilyNames(List<Name> names) {
        this.familyNames = names;
    }

    public OffsetDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(OffsetDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
