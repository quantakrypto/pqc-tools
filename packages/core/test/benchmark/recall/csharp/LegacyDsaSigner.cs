using System.Security.Cryptography;

// The concrete provider type is hidden behind a `using` alias so the call
// site reads like a generic "Signer" rather than a DSA-specific one.
using Signer = System.Security.Cryptography.DSACryptoServiceProvider;

namespace Acme.Legacy
{
    /// <summary>
    /// Legacy 1024-bit DSA signing path, retained only for interop with a
    /// handful of old on-prem clients that never migrated. New code should
    /// not call this.
    /// </summary>
    public sealed class LegacyDsaSigner
    {
        public byte[] Sign(byte[] data)
        {
            using var provider = new Signer(1024);
            return provider.SignData(data);
        }

        public string ExportParameters()
        {
            using var provider = new Signer();
            return provider.ToXmlString(includePrivateParameters: false);
        }
    }
}
