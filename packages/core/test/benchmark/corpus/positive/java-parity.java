// Positive: Java parity fixture for the extended JCA/BouncyCastle detector.
// Exercises the F8 fix (RSASSA-PSS keygen is a signature, not a KEM), the new
// BouncyCastle agreement/engine classes, and the new insecure-TLS rules.
import java.security.KeyPairGenerator;
import javax.net.ssl.*;
import org.bouncycastle.crypto.agreement.*;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.encodings.*;
import org.apache.http.conn.ssl.*;

public class Parity {
  void parity() throws Exception {
    // F8: RSA signature scheme — must classify as java-rsa-sign (hndl:false),
    // not java-rsa (kem/hndl:true).
    KeyPairGenerator pss = KeyPairGenerator.getInstance("RSASSA-PSS");

    // BouncyCastle lightweight-API agreement / engine classes.
    ECDHBasicAgreement ecdh = new ECDHBasicAgreement();
    DHBasicAgreement dh = new DHBasicAgreement();
    X25519KeyPairGenerator xdh = new X25519KeyPairGenerator();
    Ed25519KeyPairGenerator ed = new Ed25519KeyPairGenerator();
    RSAEngine rsa = new RSAEngine();
    OAEPEncoding oaep = new OAEPEncoding(rsa);

    // Insecure TLS configuration.
    SSLContext ctx = SSLContext.getInstance("TLSv1");
    HostnameVerifier noop = new NoopHostnameVerifier();
    HostnameVerifier all = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
  }
}
