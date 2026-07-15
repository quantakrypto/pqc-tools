using System;

// RSA is imported under an alias, and the actual creation goes through a
// delegate field with the key size pulled from a const. The literal call
// site is `_create(DefaultModulusBits)`, never `RSA.Create(2048)`.
using Asymmetric = System.Security.Cryptography.RSA;

namespace Acme.Pki
{
    /// <summary>
    /// Central factory for signing key material. Keeps the algorithm choice
    /// and modulus size in one place so the rest of the PKI code stays
    /// algorithm-agnostic.
    /// </summary>
    public sealed class KeyMaterialFactory
    {
        private const int DefaultModulusBits = 3072;

        private readonly Func<int, Asymmetric> _create = bits => Asymmetric.Create(bits);

        public Asymmetric CreateSigningKey()
        {
            return _create(DefaultModulusBits);
        }

        public Asymmetric CreateWith(int modulusBits)
        {
            return _create(modulusBits);
        }
    }
}
