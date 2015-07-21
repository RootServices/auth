package org.rootservices.authorization.grant.code.protocol.token.exception;

import org.rootservices.authorization.exception.BaseInformException;

/**
 * Created by tommackenzie on 7/21/15.
 */
public class CompromisedCodeException extends BaseInformException {
    private String error;

    public CompromisedCodeException(String message, String error, Throwable domainCause, int code) {
        super(message, domainCause, code);
        this.error = error;
    }

    public String getError() {
        return error;
    }
}
