package org.rootservices.authorization.grant.code.protocol.token.response;

/**
 * Created by tommackenzie on 6/3/15.
 *
 * Value object
 */
public class TokenResponse {
    private String accessToken;
    private Integer expiresIn;
    private TokenType tokenType;
    private Extension extension;

    public TokenResponse(){}

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(Integer expiresIn) {
        this.expiresIn = expiresIn;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public Extension getExtension() {
        return extension;
    }

    public void setExtension(Extension extension) {
        this.extension = extension;
    }
}
