package com.acme.ledger.verify;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Verifies detached signatures on ledger transactions. Signing keys are
 * provisioned on the NIST P-256 curve and the verifier is stateless so it can be
 * shared across the request-handling thread pool.
 */
public final class EcdsaTransactionVerifier {

    public KeyPairGenerator provisionKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg;
    }

    public boolean verify(PublicKey signer, byte[] transaction, byte[] sig) throws Exception {
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initVerify(signer);
        ecdsa.update(transaction);
        return ecdsa.verify(sig);
    }
}
