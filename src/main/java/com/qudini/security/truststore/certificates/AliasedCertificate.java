package com.qudini.security.truststore.certificates;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import java.security.cert.Certificate;
import java.util.Optional;

/**
 * A certificate with an alias, as often seen in key stores.
 */
@Immutable
public final class AliasedCertificate {
    private final String alias;
    private final Certificate certificate;

    private AliasedCertificate(String alias, Certificate certificate) {
        this.alias = alias;
        this.certificate = certificate;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Nonnull
    public String getAlias() {
        return alias;
    }

    @Nonnull
    public Certificate getCertificate() {
        return certificate;
    }

    public static final class Builder {
        private Optional<String> alias = Optional.empty();
        private Optional<Certificate> certificate = Optional.empty();

        private Builder() {
        }

        public Builder alias(String alias) {
            this.alias = Optional.of(alias);
            return this;
        }

        public Builder certificate(Certificate certificate) {
            this.certificate = Optional.of(certificate);
            return this;
        }

        public AliasedCertificate build() {
            return new AliasedCertificate(alias.get(), certificate.get());
        }
    }
}
