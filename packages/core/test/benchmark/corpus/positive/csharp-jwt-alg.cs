using Microsoft.IdentityModel.Tokens;

// Identifier-form JWT alg (Microsoft.IdentityModel): the algorithm is a C#
// IDENTIFIER, not a quoted string literal, so only the csharp-jwt-alg rule
// should fire here.
class JwtAlg {
    string Alg() {
        return SecurityAlgorithms.RsaSha256;
    }
}
