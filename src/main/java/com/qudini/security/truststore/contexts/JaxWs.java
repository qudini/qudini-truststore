package com.qudini.security.truststore.contexts;

import com.qudini.security.truststore.stores.PassphraseProtectedTrustStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Service;
import java.security.*;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A ContextBinder for JAX-WS, which is uses the Java's KeyStore to authenticate TLS.
 */
public class JaxWs<A extends KeyStore, B extends PassphraseProtectedTrustStore<A>> extends ContextBinder<Service, B> {

    private static final String SSL_SOCKET_FACTORY_KEY
            = "com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory";

    private JaxWs(Service context) {
        super(context);
    }

    public static <A extends KeyStore, B extends PassphraseProtectedTrustStore<A>> JaxWs<A, B> from(Service context) {
        return new JaxWs<>(context);
    }

    @Override
    public <C> C withStore(B store, Function<Service, C> contextualAction) {
        Map<String, Object> requestContext = ((BindingProvider) getContext()).getRequestContext();
        Object previousSSLSocketFactory = requestContext.get(SSL_SOCKET_FACTORY_KEY);
        putTemporarySocketFactory(store, x -> requestContext.put(SSL_SOCKET_FACTORY_KEY, x));
        try {
            return contextualAction.apply(getContext());
        } finally {
            requestContext.put(SSL_SOCKET_FACTORY_KEY, previousSSLSocketFactory);
        }
    }

    private void putTemporarySocketFactory(B store, Consumer<Object> trustStorePutter) {
        trustStorePutter.accept(createTemporarySSLContext(store));
    }

    private SSLContext createTemporarySSLContext(B store) {
        return store.withDisposableSnapshot(keyStore -> {
            try {
                SSLContext sslContext = SSLContext.getDefault();
                KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm()
                );
                keyManagerFactory.init(keyStore, store.getPassphrase());
                sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
                return sslContext;
            } catch (
                    NoSuchAlgorithmException
                            | KeyStoreException
                            | UnrecoverableKeyException
                            | KeyManagementException e
            ) {
                throw new ContextManagementException(e);
            }
        });
    }
}
