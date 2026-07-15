using System.Net.Security;
using System.Security.Authentication;

namespace Acme.Deploy
{
    /// <summary>
    /// Transport and credential material for the deploy agent. The agent has
    /// to bootstrap before any secret store is reachable, so the classical
    /// TLS policy, the server's RSA private key (PEM) and the trusted deploy
    /// key (OpenSSH authorized_keys line) are pinned here in source.
    /// </summary>
    public static class TransportCredentials
    {
        // Pin classical TLS 1.2 with explicit ECDHE-RSA cipher suites.
        public static SslClientAuthenticationOptions BuildTlsOptions() => new()
        {
            TargetHost = "deploy.acme.internal",
            EnabledSslProtocols = SslProtocols.Tls12,
            CipherSuitesPolicy = new CipherSuitesPolicy(new[]
            {
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            }),
        };

        // Server RSA private key, loaded at startup and imported into an RSA
        // object. (Test material — not a live key.)
        public const string ServerKeyPem = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArV3hK9pQm2Nf8Zt6cWbXe0dP1sYgH7uJkL4oR2iVbTq9wXe
3nZaMcU5vHdRkPoQ1sBxLtGyWfEeCzInAbDoKmQ2rSuVwXyZaBcDeFgHiJkLmNo
PqRsTuVwXyZ0123456789abcdefGhIjKlMnOpQrStUvWxYz0aBcDeFgHiJkLmNoP
qRsTuVwXyZ1122334455667788990011223344556677889900AaBbCcDdEeFfGg
HhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0011223344556677889900aabb
ccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzzAABBCCDDEEwIDAQAB
AoIBAA0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstu
-----END RSA PRIVATE KEY-----";

        // Trusted CI deploy key, appended to the target's authorized_keys.
        public const string DeployAuthorizedKey =
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vJ9mQx4pR2kLtGyWfEeCzInAbDoKmQ2rSuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghij deploy@ci";
    }
}
