package com.qudini.security.truststore.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Utilities for certificate creation and loading.
 */
public class Certificates {
    private final CertificateFactory factory;

    private static final Certificates defaultInstance;

    static {
        try {
            defaultInstance = from(CertificateFactory.getInstance("X.509"));
        } catch (CertificateException e) {
            throw new CertificatesCreationException(e);
        }
    }

    private Certificates(CertificateFactory factory) {
        this.factory = factory;
    }

    public static Certificates from(CertificateFactory factory) {
        return new Certificates(factory);
    }

    public static Certificates getDefault() {
        return defaultInstance;
    }

    public Certificate fromBytes(byte[] bytes) {
        try {
            return factory.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            throw new CertificatesCreationException(e);
        }
    }

    public Certificate at(Path path) {
        try {
            return fromBytes(Files.readAllBytes(path));
        } catch (IOException e) {
            throw new CertificatesCreationException(e);
        }
    }

    public Certificate fromString(String content) {
        return fromBytes(content.getBytes(StandardCharsets.UTF_8));
    }
}
