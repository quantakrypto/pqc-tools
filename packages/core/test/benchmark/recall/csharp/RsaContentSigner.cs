using System.Security.Cryptography;
using System.Text;

namespace Acme.Signing
{
    /// <summary>
    /// Signs release manifests with a 2048-bit RSA key. Used by the build
    /// pipeline to produce a detached signature that clients verify before
    /// applying an update.
    /// </summary>
    public sealed class RsaContentSigner
    {
        public byte[] SignManifest(string manifest)
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            byte[] data = Encoding.UTF8.GetBytes(manifest);
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public string ExportPublicKey()
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            return rsa.ToXmlString(includePrivateParameters: false);
        }
    }
}
