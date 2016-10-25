package org.rootservices.authorization.openId.identity;

import org.rootservices.authorization.oauth2.grant.token.entity.TokenClaims;
import org.rootservices.authorization.openId.grant.redirect.implicit.authorization.response.entity.IdentityClaims;
import org.rootservices.authorization.openId.identity.entity.IdToken;
import org.rootservices.authorization.openId.identity.exception.IdTokenException;
import org.rootservices.authorization.openId.identity.exception.KeyNotFoundException;
import org.rootservices.authorization.openId.identity.exception.ProfileNotFoundException;
import org.rootservices.authorization.openId.identity.factory.IdTokenFactory;
import org.rootservices.authorization.openId.identity.translator.PrivateKeyTranslator;
import org.rootservices.authorization.persistence.entity.Profile;
import org.rootservices.authorization.persistence.entity.RSAPrivateKey;
import org.rootservices.authorization.persistence.entity.Scope;
import org.rootservices.authorization.persistence.entity.TokenScope;
import org.rootservices.authorization.persistence.exceptions.RecordNotFoundException;
import org.rootservices.authorization.persistence.repository.ProfileRepository;
import org.rootservices.authorization.persistence.repository.RsaPrivateKeyRepository;
import org.rootservices.jwt.SecureJwtEncoder;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Created by tommackenzie on 8/31/16.
 */
@Component
public class MakeImplicitIdentityToken {
    private static String PROFILE_ERROR_MESSAGE = "Profile was not found";
    private static String KEY_ERROR_MESSAGE = "No key available to sign id token";
    private static String ALG_ERROR_MESSAGE = "Algorithm to sign with is invalid";
    private static String JWK_ERROR_MESSAGE = "key is invalid";
    private static String SERIALIZE_ERROR_MESSAGE = "Could not serialize id token";

    private ProfileRepository profileRepository;
    private MakeAccessTokenHash makeAccessTokenHash;
    private IdTokenFactory idTokenFactory;
    private RsaPrivateKeyRepository rsaPrivateKeyRepository;
    private PrivateKeyTranslator privateKeyTranslator;
    private AppFactory jwtAppFactory;

    @Autowired
    public MakeImplicitIdentityToken(ProfileRepository profileRepository, MakeAccessTokenHash makeAccessTokenHash, IdTokenFactory idTokenFactory, RsaPrivateKeyRepository rsaPrivateKeyRepository, PrivateKeyTranslator privateKeyTranslator, AppFactory jwtAppFactory) {
        this.profileRepository = profileRepository;
        this.makeAccessTokenHash = makeAccessTokenHash;
        this.idTokenFactory = idTokenFactory;
        this.rsaPrivateKeyRepository = rsaPrivateKeyRepository;
        this.privateKeyTranslator = privateKeyTranslator;
        this.jwtAppFactory = jwtAppFactory;
    }

    /**
     * Creates a id token for the implicit grant flow, "token id_token".
     * http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     *
     * @param plainTextAccessToken
     * @param nonce
     * @param resourceOwnerId
     * @param scopesForIdToken
     * @return a secure (signed) and encoded jwt
     * @throws ProfileNotFoundException
     * @throws KeyNotFoundException
     * @throws IdTokenException
     */
    public String makeForAccessToken(String plainTextAccessToken, String nonce, TokenClaims tokenClaims, UUID resourceOwnerId, List<String> scopesForIdToken) throws ProfileNotFoundException, KeyNotFoundException, IdTokenException {

        Profile profile = null;
        try {
            profile = profileRepository.getByResourceOwnerId(resourceOwnerId);
        } catch (RecordNotFoundException e) {
            throw new ProfileNotFoundException(PROFILE_ERROR_MESSAGE, e);
        }

        String accessTokenHash = makeAccessTokenHash.makeEncodedHash(plainTextAccessToken);
        IdToken idToken = idTokenFactory.make(accessTokenHash, nonce, tokenClaims, scopesForIdToken, profile);

        RSAPrivateKey key = null;
        try {
            key = rsaPrivateKeyRepository.getMostRecentAndActiveForSigning();
        } catch (RecordNotFoundException e) {
            throw new KeyNotFoundException(KEY_ERROR_MESSAGE, e);
        }

        RSAKeyPair rsaKeyPair = privateKeyTranslator.from(key);
        String encodedJwt = translateIdTokenToEncodedJwt(rsaKeyPair, idToken);

        return encodedJwt;
    }

    /**
     * Creates a id token for the implicit grant flow, "id_token".
     * http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
     *
     * @param nonce
     * @param resourceOwnerId
     * @param scopes
     * @return a secure (signed) and encoded jwt
     * @throws ProfileNotFoundException
     * @throws KeyNotFoundException
     * @throws IdTokenException
     */
    public String makeIdentityOnly(String nonce, IdentityClaims identityClaims, UUID resourceOwnerId, List<String> scopes) throws ProfileNotFoundException, KeyNotFoundException, IdTokenException {

        Profile profile = null;
        try {
            profile = profileRepository.getByResourceOwnerId(resourceOwnerId);
        } catch (RecordNotFoundException e) {
            throw new ProfileNotFoundException(PROFILE_ERROR_MESSAGE, e);
        }

        IdToken idToken = idTokenFactory.make(nonce, identityClaims, scopes, profile);

        RSAPrivateKey key = null;
        try {
            key = rsaPrivateKeyRepository.getMostRecentAndActiveForSigning();
        } catch (RecordNotFoundException e) {
            throw new KeyNotFoundException(KEY_ERROR_MESSAGE, e);
        }

        RSAKeyPair rsaKeyPair = privateKeyTranslator.from(key);
        String encodedJwt = translateIdTokenToEncodedJwt(rsaKeyPair, idToken);

        return encodedJwt;
    }

    protected String translateIdTokenToEncodedJwt(RSAKeyPair rsaKeyPair, IdToken idToken) throws IdTokenException {

        SecureJwtEncoder secureJwtEncoder;
        try {
            secureJwtEncoder = jwtAppFactory.secureJwtEncoder(Algorithm.RS256, rsaKeyPair);
        } catch (InvalidAlgorithmException e) {
            throw new IdTokenException(ALG_ERROR_MESSAGE, e);
        } catch (InvalidJsonWebKeyException e) {
            throw new IdTokenException(JWK_ERROR_MESSAGE, e);
        }

        String encodedJwt = null;
        try {
            encodedJwt = secureJwtEncoder.encode(idToken);
        } catch (JwtToJsonException e) {
            throw new IdTokenException(SERIALIZE_ERROR_MESSAGE, e);
        }

        return encodedJwt;
    }
}
