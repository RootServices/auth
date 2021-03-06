package net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request;

import net.tokensmith.authorization.constant.ErrorCode;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.entity.AuthRequest;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformClientException;
import net.tokensmith.authorization.oauth2.grant.redirect.shared.authorization.request.exception.InformResourceOwnerException;
import net.tokensmith.repository.entity.Client;
import net.tokensmith.repository.entity.ResponseType;
import net.tokensmith.repository.entity.Scope;
import net.tokensmith.repository.exceptions.RecordNotFoundException;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Created by tommackenzie on 11/19/14.
 */
public abstract class CompareClientToAuthRequest {

    public boolean run(AuthRequest authRequest) throws InformResourceOwnerException, InformClientException {
        Client client;

        try {
            client = getClient(authRequest.getClientId());
        } catch (RecordNotFoundException e) {
            throw new InformResourceOwnerException("The Client was not found", e, ErrorCode.CLIENT_NOT_FOUND.getCode());
        }

        if ( redirectMismatch(authRequest.getRedirectURI(), client.getRedirectURI()) ) {
            throw new InformResourceOwnerException(
                    "Redirect URI requested doesn't match client's redirect uri",
                    ErrorCode.REDIRECT_URI_MISMATCH.getCode()
            );
        }

        if ( ! hasResponseTypes(authRequest.getResponseTypes(), client.getResponseTypes()) ) {
            throw new InformClientException(
                    "Response Type requested doesn't match client's response type",
                    "unauthorized_client",
                    ErrorCode.RESPONSE_TYPE_MISMATCH.getDescription(),
                    ErrorCode.RESPONSE_TYPE_MISMATCH.getCode(),
                    client.getRedirectURI(),
                    authRequest.getState()
            );
        }

        if (! hasScopes(authRequest.getScopes(), client.getScopes())) {
            throw new InformClientException(
                    "Scope is not supported for this client.",
                    "invalid_scope",
                    ErrorCode.SCOPES_NOT_SUPPORTED.getDescription(),
                    ErrorCode.SCOPES_NOT_SUPPORTED.getCode(),
                    client.getRedirectURI(),
                    authRequest.getState()
            );
        }
        return true;
    }

    private boolean hasResponseTypes(List<String> requestedResponseTypes, List<ResponseType> clientResponseTypes) {
        boolean hasScopes = true;
        for(String responseType: requestedResponseTypes) {
            if (! clientResponseTypes.stream().filter(o -> o.getName().equals(responseType)).findFirst().isPresent()) {
                hasScopes = false;
                break;
            }
        }
        return hasScopes;
    }

    private boolean hasScopes(List<String> requestedScopes, List<Scope> clientScopes) {
        boolean hasScopes = true;
        for(String scope: requestedScopes) {
            if (! clientScopes.stream().filter(o -> o.getName().equals(scope)).findFirst().isPresent()) {
                hasScopes = false;
                break;
            }
        }
        return hasScopes;
    }
    /**
     * returns true if the redirect does not match client's redirect,
     * otherwise returns false
     */
    private boolean redirectMismatch(Optional<URI> redirect, URI clientRedirect) {
        boolean matches = false;
        if ( redirect.isPresent()) {
            matches = !clientRedirect.equals(redirect.get());
        }
        return matches;
    }

    public abstract Client getClient(UUID clientId) throws RecordNotFoundException;
}
