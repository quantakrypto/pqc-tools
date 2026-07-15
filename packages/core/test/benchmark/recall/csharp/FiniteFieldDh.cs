using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Acme.KeyExchange
{
    /// <summary>
    /// Classical finite-field (MODP) Diffie-Hellman, 2048-bit. This is the
    /// non-elliptic DH used by the legacy VPN gateway. Parameters are
    /// generated once and cached; each peer then does a basic agreement.
    /// </summary>
    public sealed class FiniteFieldDh
    {
        public DHParameters BuildParameters()
        {
            var paramGen = new DHParametersGenerator();
            paramGen.Init(size: 2048, certainty: 20, new SecureRandom());
            return paramGen.GenerateParameters();
        }

        public AsymmetricCipherKeyPair GenerateKeyPair(DHParameters parameters)
        {
            var keyGen = new DHBasicKeyPairGenerator();
            keyGen.Init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
            return keyGen.GenerateKeyPair();
        }

        public BigInteger DeriveSharedSecret(
            DHPrivateKeyParameters ourPrivate,
            DHPublicKeyParameters theirPublic)
        {
            var agreement = new DHBasicAgreement();
            agreement.Init(ourPrivate);
            return agreement.CalculateAgreement(theirPublic);
        }
    }
}
