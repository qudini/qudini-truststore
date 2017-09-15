package com.qudini.security.truststore.contexts;

public final class ContextManagementException extends RuntimeException {
    public ContextManagementException(final Throwable cause) {
        super(cause);
    }

    public ContextManagementException(final String message) {
        super(message);
    }

    public ContextManagementException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
