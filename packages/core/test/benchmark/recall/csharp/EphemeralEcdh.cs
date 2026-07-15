using System.Security.Cryptography;

namespace Acme.KeyExchange
{
    /// <summary>
    /// Ephemeral ECDH over NIST P-384. Each session derives a fresh shared
    /// secret from the peer's public key, which then seeds the symmetric
    /// channel key.
    /// </summary>
    public sealed class EphemeralEcdh
    {
        public byte[] DeriveSharedSecret(ECDiffieHellmanPublicKey peerPublicKey)
        {
            using ECDiffieHellman alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            return alice.DeriveKeyFromHash(peerPublicKey, HashAlgorithmName.SHA384);
        }

        public byte[] ExportOwnPublicKey()
        {
            using ECDiffieHellman alice = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            return alice.PublicKey.ExportSubjectPublicKeyInfo();
        }
    }
}
