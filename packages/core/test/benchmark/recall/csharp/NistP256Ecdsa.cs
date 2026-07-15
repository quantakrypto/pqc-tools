using System.Security.Cryptography;

namespace Acme.Signing
{
    /// <summary>
    /// ECDSA signing over the NIST P-256 curve. This backs the webhook
    /// signature header so downstream services can authenticate callbacks.
    /// </summary>
    public static class NistP256Ecdsa
    {
        public static byte[] Sign(byte[] payload)
        {
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            return ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        }

        public static bool Verify(byte[] payload, byte[] signature, ECParameters publicParameters)
        {
            using ECDsa ecdsa = ECDsa.Create(publicParameters);
            return ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);
        }
    }
}
