package org.rootservices.authorization.grant.code.protocol.token;

import java.net.URI;
import java.util.UUID;

/**
 * Created by tommackenzie on 6/26/15.
 */
public class TokenRequest {
    private UUID clientUUID;
    private String clientPassword;
    private String grantType;
    private String code;
    private URI redirectUri;

    public UUID getClientUUID() {
        return clientUUID;
    }

    public void setClientUUID(UUID clientUUID) {
        this.clientUUID = clientUUID;
    }

    public String getClientPassword() {
        return clientPassword;
    }

    public void setClientPassword(String clientPassword) {
        this.clientPassword = clientPassword;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(URI redirectUri) {
        this.redirectUri = redirectUri;
    }
}
