package com.acme.mesh.transport;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Ephemeral-static handshake for the service mesh data plane. Each node derives a
 * shared secret with its peer over the P-384 curve, which is then fed into the
 * record-layer KDF (handled elsewhere).
 */
public final class EcdhHandshake {

    private KeyPair localKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        return kpg.generateKeyPair();
    }

    public byte[] deriveSharedSecret(PublicKey peer) throws Exception {
        KeyPair mine = localKeys();
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(mine.getPrivate());
        agreement.doPhase(peer, true);
        return agreement.generateSecret();
    }
}
