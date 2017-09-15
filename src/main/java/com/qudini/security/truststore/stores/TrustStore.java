package com.qudini.security.truststore.stores;

import com.qudini.security.truststore.certificates.AliasedCertificate;

import javax.annotation.concurrent.Immutable;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;

/**
 * An certificate trust store designed to be stateless. Stateless here means always deriving from base trust stores
 * and diverging from them only temporarily to complete certain operations, for example adding a certificate to ensure a
 * single TLS operation using a non-standard certificate works.
 * <p>
 * {@code A} is the type of the underlying store that is exposed to the user as disposable snapshots.
 * <p>
 * <em>There should be no operations that permanently alter truststores across the whole JVM or OS.</em>
 */
@Immutable
public interface TrustStore<A> {

    /**
     * Creates a new {@link TrustStore}, as the current one with {@code certificate} added.
     */
    TrustStore add(AliasedCertificate certificate);

    /**
     * Creates a new {@link TrustStore}, as the current one combined with {@code store}.
     */
    TrustStore addAllFrom(TrustStore<A> store);


    /**
     * Turns the TrustStore into a concrete store of type {@code A}. That store is temporary is must be disposed once
     * {@code f} has finished running, and must have no effect on system-wide stores.
     */
    <B> B withDisposableSnapshot(Function<A, B> f);

    Map<String, Certificate> getCertificates();

    /**
     * @see #add(AliasedCertificate)
     */
    default TrustStore<A> add(Stream<AliasedCertificate> certificates) {
        return certificates.reduce(this, TrustStore<A>::add, TrustStore<A>::addAllFrom);
    }

    /**
     * @see #add(AliasedCertificate)
     */
    default TrustStore<A> add(AliasedCertificate... certificates) {
        return add(Stream.of(certificates));
    }

    /**
     * @see #addAllFrom(TrustStore)
     */
    default TrustStore<A> addAllFrom(Stream<TrustStore<A>> stores) {
        return stores.reduce(this, TrustStore::addAllFrom);
    }

    /**
     * @see #withDisposableSnapshot(Function)
     */
    default void withDisposableSnapshot(Consumer<A> f) {

        // The only place that should ignore `#withDisposableSnapshot`'s `@CheckReturnValue` annotation.
        withDisposableSnapshot(store -> {
            f.accept(store);
            return (Void) null;
        });
    }
}
