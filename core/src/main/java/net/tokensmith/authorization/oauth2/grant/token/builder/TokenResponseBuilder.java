package net.tokensmith.authorization.oauth2.grant.token.builder;

import net.tokensmith.authorization.oauth2.grant.token.entity.Extension;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenClaims;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenResponse;
import net.tokensmith.authorization.oauth2.grant.token.entity.TokenType;

import java.util.List;
import java.util.Optional;

/**
 * Created by tommackenzie on 10/20/16.
 */
public class TokenResponseBuilder {
    private String accessToken;
    private String refreshAccessToken;
    private Long expiresIn;
    private TokenType tokenType;
    private Extension extension;
    private String issuer;
    private List<String> audience;
    private Long issuedAt;
    private Long expirationTime;
    private Long authTime;
    private Optional<String> nonce = Optional.empty();

    public TokenResponseBuilder setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public TokenResponseBuilder setRefreshAccessToken(String refreshAccessToken) {
        this.refreshAccessToken = refreshAccessToken;
        return this;
    }

    public TokenResponseBuilder setExpiresIn(Long expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }

    public TokenResponseBuilder setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    public TokenResponseBuilder setExtension(Extension extension) {
        this.extension = extension;
        return this;
    }

    public TokenResponseBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public TokenResponseBuilder setAudience(List<String> audience) {
        this.audience = audience;
        return this;
    }

    public TokenResponseBuilder setIssuedAt(Long issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public TokenResponseBuilder setExpirationTime(Long expirationTime) {
        this.expirationTime = expirationTime;
        return this;
    }

    public TokenResponseBuilder setAuthTime(Long authTime) {
        this.authTime = authTime;
        return this;
    }

    public TokenResponseBuilder nonce(Optional<String> nonce) {
        this.nonce = nonce;
        return this;
    }

    public TokenResponse build() {
        TokenResponse tr = new TokenResponse();
        tr.setAccessToken(this.accessToken);
        tr.setRefreshAccessToken(this.refreshAccessToken);
        tr.setExpiresIn(this.expiresIn);
        tr.setTokenType(this.tokenType);
        tr.setExtension(this.extension);

        TokenClaims tc = new TokenClaims();
        tc.setIssuer(this.issuer);
        tc.setAudience(this.audience);
        tc.setIssuedAt(this.issuedAt);
        tc.setExpirationTime(this.expirationTime);
        tc.setAuthTime(this.authTime);
        tc.setNonce(this.nonce);
        tr.setTokenClaims(tc);

        return tr;
    }
}
