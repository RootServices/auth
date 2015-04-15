package org.rootservices.authorization.grant.code.authenticate;

import org.rootservices.authorization.grant.code.authenticate.exception.UnauthorizedException;
import org.rootservices.authorization.persistence.entity.ResourceOwner;

import java.util.UUID;

/**
 * Created by tommackenzie on 4/12/15.
 */
public interface LoginResourceOwner {
    public UUID run(String userName, String plainTextPassword) throws UnauthorizedException;
}
