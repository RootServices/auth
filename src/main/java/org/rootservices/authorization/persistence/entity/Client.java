package org.rootservices.authorization.persistence.entity;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Created by tommackenzie on 11/15/14.
 */
public class Client {
    private UUID uuid;
    private ResponseType responseType;
    private URI redirectURI;
    private List<Scope> scopes;
    private Date createdAt;

    public Client() {};

    public Client(UUID uuid, ResponseType responseType, URI redirectURI) {
        this.uuid = uuid;
        this.responseType = responseType;
        this.redirectURI = redirectURI;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public void setResponseType(ResponseType responseType) {
        this.responseType = responseType;
    }

    public URI getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(URI redirectURI) {
        this.redirectURI = redirectURI;
    }

    public List<Scope> getScopes() {
        return scopes;
    }

    public void setScopes(List<Scope> scopes) {
        this.scopes = scopes;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }


}
