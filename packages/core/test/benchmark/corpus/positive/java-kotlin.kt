import java.security.*
import javax.crypto.*

fun keys() {
    val rsaSig = Signature.getInstance("SHA256withRSA")
    val ed = KeyPairGenerator.getInstance("Ed25519")
    val xdh = KeyAgreement.getInstance("X25519")
}
