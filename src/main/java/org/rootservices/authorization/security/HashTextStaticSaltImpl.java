package org.rootservices.authorization.security;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Created by tommackenzie on 6/6/15.
 */
@Component
public class HashTextStaticSaltImpl implements HashTextStaticSalt {

    private String salt;

    @Autowired
    public HashTextStaticSaltImpl(String salt) {
        this.salt = salt;
    }

    @Override
    public String run(String plainText) {
        return BCrypt.hashpw(plainText, salt);
    }
}
