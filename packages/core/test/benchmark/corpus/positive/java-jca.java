import java.security.*;
import javax.crypto.*;

public class Crypto {
  void keys() throws Exception {
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    Signature sig = Signature.getInstance("SHA256withECDSA");
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
  }
}
