import * as tls from "@pulumi/tls";
const caKey = new tls.PrivateKey("ca", { algorithm: "RSA", rsaBits: 4096 });
