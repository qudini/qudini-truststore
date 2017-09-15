package com.qudini.security.truststore.stores;

/**
 * A {@link TrustStore} that also carries a passphrase.
 * <p>
 *
 * @see TrustStore
 */
public interface PassphraseProtectedTrustStore<A> extends TrustStore<A> {
    char[] getPassphrase();
}
