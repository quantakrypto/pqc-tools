using System.Net.Http;

// Insecure .NET TLS: the custom validation callback accepts ANY server
// certificate, disabling certificate verification (man-in-the-middle risk).
class InsecureTls {
    void Configure() {
        var handler = new HttpClientHandler();
        handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true;
    }
}
