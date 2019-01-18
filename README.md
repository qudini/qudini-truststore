# com.qudini.security.truststore

[![CircleCI](https://circleci.com/gh/qudini/qudini-truststore.svg?style=svg)](https://circleci.com/gh/qudini/qudini-truststore)

*Warning:* this is an unstable prototype still being built; don't use for real environments. In particular, it does
not yet have tests.

Create and modify truststores, and apply them in temporary contexts without system-wide side-effects. Implement custom
stores and custom context handlers. Easily create and load certificates.

```
JavaKeyStore store = JavaKeyStore
        .from(TrustStoreSpecification
                .<Path>builder()
                .path(Paths.get("my-store.jks"))
                .passphrase("changeme".toCharArray())
                .build()
        )
        .add(AliasedCertificate
                .builder()
                .alias("custom-third-party")
                .certificate(Certificates.getDefault().at(Paths.get("custom-third-party.cer")))
                .build()
        )
        .addAllFrom(JavaKeyStore.fromCurrentDefaultStore());

com.qudini.truststore.contexts.JaxWs
        .from(customThirdPartyService)
        .withStore(store, service -> {
            service.doHttpsRequestNeedingCustomCertificate();
            doSomethingElseNeedingCertificateFromDefaultStore();
        });
```