package com.qudini.security.truststore.stores;

public final class CertificateEnumerationException extends RuntimeException {
    public CertificateEnumerationException(final Throwable cause) {
        super(cause);
    }

    public CertificateEnumerationException(final String message) {
        super(message);
    }

    public CertificateEnumerationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}