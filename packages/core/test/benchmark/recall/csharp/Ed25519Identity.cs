using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Acme.Identity
{
    /// <summary>
    /// Modern-curve identity primitives implemented with BouncyCastle:
    /// Ed25519 for signatures and X25519 / X448 for key agreement. These are
    /// the curves .NET's built-in <c>System.Security.Cryptography</c> does not
    /// expose directly.
    /// </summary>
    public sealed class Ed25519Identity
    {
        public AsymmetricCipherKeyPair GenerateSigningKeyPair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return gen.GenerateKeyPair();
        }

        public byte[] Sign(Ed25519PrivateKeyParameters key, byte[] message)
        {
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        public byte[] AgreeX25519(X25519PrivateKeyParameters ours, X25519PublicKeyParameters theirs)
        {
            var agreement = new X25519Agreement();
            agreement.Init(ours);
            var secret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(theirs, secret, 0);
            return secret;
        }

        public byte[] AgreeX448(X448PrivateKeyParameters ours, X448PublicKeyParameters theirs)
        {
            var agreement = new X448Agreement();
            agreement.Init(ours);
            var secret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(theirs, secret, 0);
            return secret;
        }
    }
}
