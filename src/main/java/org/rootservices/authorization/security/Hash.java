package org.rootservices.authorization.security;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Created by tommackenzie on 4/13/15.
 */
public interface Hash {
    public String run(String plainText);
}
