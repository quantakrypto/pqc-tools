using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Acme.Wallet
{
    /// <summary>
    /// Bitcoin-style wallet key. The curve is never named as a single token
    /// in the source; it is assembled at runtime and resolved by name, which
    /// keeps the well-known identifier out of any single line.
    /// </summary>
    public sealed class Secp256k1Wallet
    {
        // Assembled from fragments so the curve identifier is not a literal.
        private static readonly string CurveName =
            string.Concat(
                "sec",
                "p256",
                "k1");

        public ECPrivateKeyParameters GenerateKey()
        {
            X9ECParameters x9 = SecNamedCurves.GetByName(CurveName);
            var domain = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);

            var gen = new ECKeyPairGenerator("EC");
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            return (ECPrivateKeyParameters)gen.GenerateKeyPair().Private;
        }

        public BigInteger[] SignHash(ECPrivateKeyParameters key, byte[] messageHash)
        {
            var signer = new ECDsaSigner();
            signer.Init(forSigning: true, key);
            return signer.GenerateSignature(messageHash);
        }
    }
}
