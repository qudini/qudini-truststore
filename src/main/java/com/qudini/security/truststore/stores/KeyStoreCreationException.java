package com.qudini.security.truststore.stores;

public class KeyStoreCreationException extends RuntimeException {
    public KeyStoreCreationException(final Throwable cause) {
        super(cause);
    }

    public KeyStoreCreationException(final String message) {
        super(message);
    }

    public KeyStoreCreationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
