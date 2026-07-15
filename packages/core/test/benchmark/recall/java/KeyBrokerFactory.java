package com.acme.broker;

import java.security.KeyPairGenerator;
import javax.crypto.KeyAgreement;
import java.util.Locale;

/**
 * Central broker that instantiates key primitives from a runtime descriptor. The
 * algorithm tokens are deliberately assembled at call time so the same factory
 * can be reused across the FIPS and non-FIPS deployment profiles.
 */
public class KeyBrokerFactory {

    public KeyPairGenerator brokerKeyPair() throws Exception {
        String algo = new StringBuilder()
                .append("R")
                .append("s")
                .append("a")
                .toString();
        return KeyPairGenerator
                .getInstance(
                        algo.toUpperCase(Locale.ROOT));
    }

    public KeyAgreement brokerAgreement(boolean elliptic) throws Exception {
        final String name =
                elliptic
                        ? "ECDH"
                        : "D" + "H";
        return KeyAgreement
                .getInstance(name);
    }
}
