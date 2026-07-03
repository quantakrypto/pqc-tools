using System.Security.Cryptography;

// Migrated away from RSA.Create toward ML-KEM; uses only symmetric now.
class Clean {
    void Safe() {
        var aes = Aes.Create();
        var sha = SHA256.Create();
        var hmac = new HMACSHA256();
    }
}
