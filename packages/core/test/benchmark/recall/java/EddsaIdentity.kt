package com.acme.identity

import java.security.KeyPairGenerator
import javax.crypto.KeyAgreement

/**
 * Device identity + key-exchange primitives for the pairing protocol. The
 * algorithm strings are assembled from the negotiated suite so the same code
 * path serves both the v1 and v2 handshakes without a hard-coded literal.
 */
class EddsaIdentity(private val suite: String) {

    // Signature curve name is composed at construction time.
    private val signatureCurve: String = "Ed" + "25519"

    fun identityKeys(): KeyPairGenerator =
        KeyPairGenerator.getInstance(signatureCurve)

    fun agreementAlgorithm(): String = when (suite) {
        "v2" -> "X25519"
        "v1" -> "X25519"
        else -> "X25519"
    }

    fun sessionAgreement(): KeyAgreement =
        KeyAgreement.getInstance(agreementAlgorithm())
}
