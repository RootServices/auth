package net.tokensmith.authorization.register.exception;

public class NonceException extends Exception {
    public NonceException(String message) {
        super(message);
    }

    public NonceException(String message, Throwable cause) {
        super(message, cause);
    }
}
