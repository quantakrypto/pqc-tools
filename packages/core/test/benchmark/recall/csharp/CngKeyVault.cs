using System.Security.Cryptography;

namespace Acme.Vault
{
    /// <summary>
    /// Windows CNG-backed key material. Uses the persisted-key CNG surface
    /// (ECDsaCng / ECDiffieHellmanCng / RSACng) rather than the portable
    /// <c>*.Create()</c> factories, so keys live in the OS key storage
    /// provider and can be marked non-exportable.
    /// </summary>
    public sealed class CngKeyVault
    {
        public ECDsaCng CreateEcdsaSigningKey()
        {
            CngKey key = CngKey.Create(
                CngAlgorithm.ECDsaP384,
                keyName: "acme-signing",
                new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None });

            return new ECDsaCng(key);
        }

        public ECDiffieHellmanCng CreateAgreementKey()
        {
            return new ECDiffieHellmanCng(521)
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };
        }

        public RSACng CreateKeyWrappingKey()
        {
            return new RSACng(2048);
        }
    }
}
