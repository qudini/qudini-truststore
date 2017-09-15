package com.qudini.security.truststore.certificates;

public final class CertificatesCreationException extends RuntimeException {
    public CertificatesCreationException(final Throwable cause) {
        super(cause);
    }

    public CertificatesCreationException(final String message) {
        super(message);
    }

    public CertificatesCreationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
