package com.qudini.security.truststore.stores;

import com.qudini.security.truststore.certificates.AliasedCertificate;

import javax.annotation.concurrent.Immutable;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A Java keystore implementation of {@link TrustStore}.
 */
@Immutable
public class JavaKeyStore implements PassphraseProtectedTrustStore<KeyStore> {
    private static final char[] DEFAULT_JAVA_TRUST_STORE_PASSWORD = "changeit".toCharArray();

    private final CertificateFactory certificateFactory;
    private final Path keyStorePath;
    private final KeyStore baseKeyStore;
    private final Map<String, Certificate> storeAddenda;
    private final char[] passphrase;

    private JavaKeyStore(
            CertificateFactory certificateFactory,
            TrustStoreSpecification<Path> specification,
            Map<String, Certificate> storeAddenda
    ) {
        this.certificateFactory = certificateFactory;
        keyStorePath = specification.getPath();
        passphrase = specification.getPassword().orElse(DEFAULT_JAVA_TRUST_STORE_PASSWORD);
        baseKeyStore = createKeyStore(keyStorePath, passphrase, Collections.emptyMap());
        this.storeAddenda = Collections.unmodifiableMap(new HashMap<>(storeAddenda));
    }

    /**
     * Derive a {@link JavaKeyStore} from a specification and a Java CertificateFactory.
     */
    public static JavaKeyStore from(
            CertificateFactory certificateFactory,
            TrustStoreSpecification<Path> specification
    ) {
        return new JavaKeyStore(certificateFactory, specification, Collections.emptyMap());
    }

    /**
     * Derive a {@link JavaKeyStore} from a specification and a X.509 certificate factory.
     */
    public static JavaKeyStore from(TrustStoreSpecification<Path> specification) {
        try {
            return from(CertificateFactory.getInstance("X.509"), specification);
        } catch (CertificateException e) {
            throw new KeyStoreCreationException(e);
        }
    }

    /**
     * Get the current system store, which is looked up via {@code javax.net.ssl.trustStore}.
     */
    public static JavaKeyStore fromCurrentDefaultStore() {
        String property = Objects.requireNonNull(System.getProperty("javax.net.ssl.trustStore"));
        return from(TrustStoreSpecification
                .<Path>builder()
                .path(Paths.get(property))
                .build()
        );
    }

    @Override
    public JavaKeyStore add(AliasedCertificate certificate) {
        return updateStoreAddenda(map -> map.put(certificate.getAlias(), certificate.getCertificate()));
    }

    @Override
    public JavaKeyStore addAllFrom(TrustStore<KeyStore> store) {
        return updateStoreAddenda(map -> map.putAll(store.getCertificates()));
    }

    @Override
    public Map<String, Certificate> getCertificates() {
        try {
            Map<String, Certificate> result = Collections
                    .list(baseKeyStore.aliases())
                    .stream()
                    .collect(Collectors.toMap(Function.identity(), this::certificateFor));
            result.putAll(storeAddenda);
            return Collections.unmodifiableMap(result);
        } catch (KeyStoreException e) {
            throw new CertificateEnumerationException(e);
        }
    }

    @Override
    public <A> A withDisposableSnapshot(Function<KeyStore, A> f) {
        return f.apply(createKeyStore(keyStorePath, passphrase, storeAddenda));
    }

    @Override
    public char[] getPassphrase() {
        return passphrase;
    }

    private KeyStore createKeyStore(Path path, char[] passphrase, Map<String, Certificate> certificatesAddenda) {
        try (FileInputStream storeStream = new FileInputStream(path.toFile())) {
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(storeStream, passphrase);
            addCertificatesTo(store, certificatesAddenda);
            return store;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreCreationException(e);
        }
    }

    private Certificate certificateFor(String alias) {
        try {
            return baseKeyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new CertificateEnumerationException(e);
        }
    }

    private JavaKeyStore updateStoreAddenda(Consumer<Map<String, Certificate>> temporaryMapUpdater) {
        Map<String, Certificate> newStoreAddenda = new HashMap<>(storeAddenda);
        temporaryMapUpdater.accept(newStoreAddenda);
        return new JavaKeyStore(
                certificateFactory,
                TrustStoreSpecification
                        .<Path>builder()
                        .path(keyStorePath)
                        .passphrase(passphrase)
                        .build(),
                Collections.unmodifiableMap(newStoreAddenda)
        );
    }

    private void addCertificatesTo(KeyStore store, Map<String, Certificate> certificatesAddenda) {
        certificatesAddenda.forEach((alias, certificate) -> {
            try {
                store.setCertificateEntry(alias, certificate);
            } catch (KeyStoreException e) {
                throw new KeyStoreCreationException(e);
            }
        });
    }
}
