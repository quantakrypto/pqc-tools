import io.jsonwebtoken.SignatureAlgorithm;

// Identifier-form JWT alg (jjwt): the algorithm is a Java IDENTIFIER, not a
// quoted string literal, so only the java-jwt-alg rule should fire here.
public class JwtAlg {
  SignatureAlgorithm alg() {
    return SignatureAlgorithm.RS256;
  }
}
