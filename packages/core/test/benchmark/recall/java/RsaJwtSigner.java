package com.acme.auth.token;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Issues signed access tokens for the API gateway. A fresh key pair is minted at
 * boot and rotated daily by {@code KeyRotationJob}; the public half is published
 * to the JWKS endpoint so downstream services can verify.
 */
public final class RsaJwtSigner {

    private final KeyPair keyPair;

    public RsaJwtSigner() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        this.keyPair = generator.generateKeyPair();
    }

    /** Produces the base64url-encoded signature over {@code header.payload}. */
    public String sign(byte[] header, byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign((PrivateKey) keyPair.getPrivate());
        signature.update(header);
        signature.update((byte) '.');
        signature.update(payload);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }
}
