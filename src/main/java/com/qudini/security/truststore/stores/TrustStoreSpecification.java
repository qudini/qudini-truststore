package com.qudini.security.truststore.stores;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

/**
 * Specifies a description of a truststore, leaving it up to the {@link TrustStore} implementation to interpret.
 * {@code A} is anything that can point out a location of a store to the implementation, such as a path or a
 * URI.
 */
@Immutable
public final class TrustStoreSpecification<A> {
    private final A path;
    private final Optional<char[]> passphrase;

    private TrustStoreSpecification(A path, Optional<char[]> passphrase) {
        this.path = path;
        this.passphrase = passphrase;
    }

    /**
     * Builds a TrustStoreSpecification.
     */
    public static <A> Builder<A> builder() {
        return new Builder<>();
    }

    /**
     * The trust store's location.
     */
    public A getPath() {
        return path;
    }

    /**
     * The trust store's passphrase. A {@link TrustStore} implementation can choose how to handle empty cases, such as
     * throwing an exception or falling back to a default value.
     */
    public Optional<char[]> getPassword() {
        return passphrase;
    }

    public static final class Builder<A> {
        private Optional<A> path = Optional.empty();
        private Optional<char[]> passphrase = Optional.empty();

        private Builder() {
        }

        public Builder<A> path(A path) {
            this.path = Optional.of(path);
            return this;
        }

        public Builder<A> passphrase(char[] passphrase) {
            this.passphrase = Optional.of(passphrase);
            return this;
        }

        public TrustStoreSpecification<A> build() {
            return new TrustStoreSpecification<>(path.get(), passphrase);
        }
    }
}
