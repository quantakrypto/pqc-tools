package com.acme.mesh.migration

import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters
import org.bouncycastle.crypto.agreement.X448Agreement
import java.security.SecureRandom

/**
 * Long-form key exchange + signing for the mesh control plane, built on the
 * BouncyCastle lightweight (non-JCA) API so we can drive the raw agreement and
 * feed the output straight into the transcript hash.
 */
class Curve448Exchange {

    fun exchangeKeys(): X448KeyPairGenerator {
        val gen = X448KeyPairGenerator()
        gen.init(X448KeyGenerationParameters(SecureRandom()))
        return gen
    }

    fun agreement(): X448Agreement = X448Agreement()

    fun signingKeys(): Ed448KeyPairGenerator {
        val gen = Ed448KeyPairGenerator()
        gen.init(Ed448KeyGenerationParameters(SecureRandom()))
        return gen
    }
}
