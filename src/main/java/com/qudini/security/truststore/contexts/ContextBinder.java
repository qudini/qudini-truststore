package com.qudini.security.truststore.contexts;

import com.qudini.security.truststore.stores.TrustStore;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Binds a trust store to an {@code A}. {@code A} is a context that utilises the trust store, such as a pending TLS
 * request or a Java-API-to-protocol system like JAX-WS. Code passed to {@link #withStore(B, Function)} can assume
 * that the specified trust store is active, but the previous trust store state is restored after {@code apply} has
 * finished executing.
 * <p>
 * Applying the trust store context should never be system-wide side-effect, but instead must be entirely local to
 * the {@code A} passed into {@code apply}.
 */
public abstract class ContextBinder<A, B extends TrustStore> {
    private final A context;

    protected ContextBinder(A context) {
        this.context = context;
    }

    protected A getContext() {
        return context;
    }

    /**
     * Perform an operation during which the TrustStore {@code B} is actualised and temporarily made active just for
     * the duration of executing {@code contextualAction}. No observable side-effects outside of
     * {@code contextualAction} should occur.
     */
    public abstract <C> C withStore(B store, Function<A, C> contextualAction);

    public void withStore(B store, Consumer<A> contextualAction) {

        // The only place where `#withStore`'s `@CheckReturnValue` should be ignored.
        withStore(store, contextualStore -> {
            contextualAction.accept(contextualStore);
            return (Void) null;
        });
    }
}
