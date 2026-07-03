using System.Security.Cryptography;

class Crypto {
    void Keys() {
        var rsa = RSA.Create(2048);
        var ecdsa = ECDsa.Create();
        var ecdh = ECDiffieHellman.Create();
        var dsa = new DSACryptoServiceProvider();
        var aes = Aes.Create();
    }
}
