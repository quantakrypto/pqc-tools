import java.security.MessageDigest;
import javax.crypto.*;

public class Clean {
  // Once used KeyPairGenerator.getInstance for RSA, now migrated away.
  void safe() throws Exception {
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    Mac mac = Mac.getInstance("HmacSHA256");
    KeyGenerator kg = KeyGenerator.getInstance("AES");
  }
}
