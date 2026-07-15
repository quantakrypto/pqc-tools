package com.acme.legacy.audit;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Signs audit records for the pre-2015 archival pipeline. The algorithm names are
 * pinned as constants in one place so the compliance team has a single source of
 * truth (and so a future migration only needs to touch these two fields).
 */
public class DsaLegacySigner {

    private static final String KEY_ALGORITHM = "DSA";
    private static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
    private static final int KEY_SIZE = 1024;

    public byte[] seal(PrivateKey key, byte[] record) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        kpg.initialize(KEY_SIZE);

        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(key);
        signer.update(record);
        return signer.sign();
    }
}
