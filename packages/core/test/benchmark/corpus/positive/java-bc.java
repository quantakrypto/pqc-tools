import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.signers.*;

public class Bc {
  void keys() throws Exception {
    ECDSASigner signer = new ECDSASigner();
    X25519Agreement agreement = new X25519Agreement();
    KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
    KeyPairGenerator dh = KeyPairGenerator.getInstance("DiffieHellman");
  }
}
