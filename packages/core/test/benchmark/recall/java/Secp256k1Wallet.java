package com.acme.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

/**
 * Derives on-chain wallet keys on the Bitcoin/Ethereum curve. We register the
 * BouncyCastle provider explicitly because the built-in SunEC provider does not
 * ship the secp256k1 domain parameters.
 */
public class Secp256k1Wallet {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyPairGenerator walletKeyGenerator() throws Exception {
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        kpg.initialize(spec);
        return kpg;
    }

    public byte[] signTransaction(PrivateKey key, byte[] txHash) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(key);
        signer.update(txHash);
        return signer.sign();
    }
}
