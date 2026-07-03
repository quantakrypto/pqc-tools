import { createRequire as __cr } from 'module'; const require = __cr(import.meta.url);

// src/main.ts
import { mkdir, readFile as readFile3, writeFile as writeFile2 } from "node:fs/promises";
import { dirname as dirname3, isAbsolute, resolve, sep as sep2 } from "node:path";
import { pathToFileURL } from "node:url";

// ../core/dist/version.js
var VERSION = "0.4.0";

// ../core/dist/scan.js
import { readFile, stat as stat2 } from "node:fs/promises";
import * as path2 from "node:path";

// ../core/dist/walk.js
import { readdir, stat } from "node:fs/promises";
import * as path from "node:path";

// ../core/dist/remediation.js
var REMEDIATIONS = {
  RSA: {
    algorithm: "RSA",
    recommendation: "ML-KEM-768 for encryption/KEM; ML-DSA-65 for signatures",
    detail: "RSA is broken by Shor's algorithm. For key transport / encryption move to ML-KEM-768 (FIPS 203), ideally as the hybrid X25519MLKEM768. For digital signatures move to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)."
  },
  ECDH: {
    algorithm: "ECDH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm and is exposed to harvest-now-decrypt-later. Adopt the hybrid X25519MLKEM768 key exchange so confidentiality survives even if one component is broken."
  },
  ECDSA: {
    algorithm: "ECDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "ECDSA signatures can be forged by a quantum attacker via Shor's algorithm. Migrate to ML-DSA (Dilithium, FIPS 204) or SLH-DSA (SPHINCS+, FIPS 205) for long-lived signatures."
  },
  EdDSA: {
    algorithm: "EdDSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "Ed25519 / Ed448 (EdDSA) are classical signatures broken by Shor's algorithm. Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) for forgery resistance."
  },
  DH: {
    algorithm: "DH",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "Finite-field Diffie-Hellman is broken by Shor's algorithm and exposed to harvest-now-decrypt-later. Move to a hybrid PQC KEM such as X25519MLKEM768."
  },
  DSA: {
    algorithm: "DSA",
    recommendation: "ML-DSA-65 (FIPS 204)",
    detail: "DSA is a classical, quantum-broken signature scheme (and already deprecated). Replace with ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)."
  },
  X25519: {
    algorithm: "X25519",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "X25519 is a modern, well-built classical key-agreement primitive but is still broken by Shor's algorithm. Wrap it in the hybrid X25519MLKEM768 construction so it stays useful during the PQC transition."
  },
  X448: {
    algorithm: "X448",
    recommendation: "hybrid X25519MLKEM768 (ML-KEM-768)",
    detail: "X448 (Goldilocks curve) is a modern classical key-agreement primitive at a higher classical security level, but it is still broken by Shor's algorithm. Adopt a hybrid PQC KEM (X25519MLKEM768 / ML-KEM-768) during the transition."
  },
  ECIES: {
    algorithm: "ECIES",
    recommendation: "ML-KEM-768 hybrid encryption",
    detail: "ECIES relies on classical ECDH for its key encapsulation and is exposed to harvest-now-decrypt-later. Replace the KEM step with ML-KEM-768 (FIPS 203), preferably in a hybrid construction."
  },
  unknown: {
    algorithm: "unknown",
    recommendation: "review for post-quantum migration",
    detail: "This usage involves classical public-key cryptography. Audit it and plan a migration to NIST PQC standards (ML-KEM / FIPS 203, ML-DSA / FIPS 204)."
  }
};
function remediationText(algorithm) {
  return REMEDIATIONS[algorithm].recommendation;
}

// ../core/dist/detect-utils.js
function offsetToLineCol(content, offset) {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: offset - lastNewline };
}
function lineAt(content, offset) {
  let start = offset;
  while (start > 0 && content.charCodeAt(start - 1) !== 10)
    start--;
  let end = offset;
  while (end < content.length && content.charCodeAt(end) !== 10)
    end++;
  return content.slice(start, end).replace(/\r$/, "").trim();
}
function makeFinding(spec) {
  const { line, column } = offsetToLineCol(spec.content, spec.index);
  const snippet = lineAt(spec.content, spec.index);
  const remediation = spec.remediation ?? (spec.algorithm ? remediationText(spec.algorithm) : void 0);
  const location = {
    file: spec.file,
    line,
    column,
    snippet: snippet.length > 200 ? `${snippet.slice(0, 197)}...` : snippet
  };
  if (spec.matchLength && spec.matchLength > 0) {
    const matched = spec.content.slice(spec.index, spec.index + spec.matchLength);
    const extraLines = (matched.match(/\n/g) ?? []).length;
    if (extraLines > 0)
      location.endLine = line + extraLines;
  }
  const finding = {
    ruleId: spec.ruleId,
    title: spec.title,
    category: spec.category,
    severity: spec.severity,
    confidence: spec.confidence,
    hndl: spec.hndl,
    message: spec.message,
    location
  };
  if (spec.algorithm)
    finding.algorithm = spec.algorithm;
  if (remediation)
    finding.remediation = remediation;
  if (spec.cwe)
    finding.cwe = spec.cwe;
  if (spec.sensitive)
    finding.sensitive = true;
  return finding;
}
function findingFromRule(rule, at, overrides) {
  return makeFinding({
    ruleId: rule.id,
    title: overrides?.title ?? rule.title,
    category: overrides?.category ?? rule.category,
    severity: overrides?.severity ?? rule.severity,
    confidence: overrides?.confidence ?? rule.confidence,
    algorithm: overrides?.algorithm ?? rule.algorithm,
    hndl: overrides?.hndl ?? rule.hndl,
    cwe: overrides?.cwe ?? rule.cwe,
    remediation: overrides?.remediation ?? rule.remediation,
    sensitive: rule.sensitive,
    message: overrides?.message ?? rule.message,
    file: at.file,
    content: at.content,
    index: at.index,
    matchLength: at.matchLength
  });
}
function hasExtension(filePath, exts) {
  const lower = filePath.toLowerCase();
  return exts.some((e) => lower.endsWith(e));
}
var JS_TS_EXTENSIONS = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".vue",
  ".svelte"
];
var PYTHON_EXTENSIONS = [".py", ".pyi", ".pyw"];
var GO_EXTENSIONS = [".go"];
var JAVA_EXTENSIONS = [".java", ".kt", ".kts"];
var CSHARP_EXTENSIONS = [".cs"];
var RUST_EXTENSIONS = [".rs"];
var RUBY_EXTENSIONS = [".rb"];
var C_EXTENSIONS = [".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"];
var JWT_HOST_EXTENSIONS = [...JS_TS_EXTENSIONS, ...PYTHON_EXTENSIONS];
var ANALYZABLE_SOURCE_EXTENSIONS = [
  ...JS_TS_EXTENSIONS,
  ...PYTHON_EXTENSIONS,
  ...GO_EXTENSIONS,
  ...JAVA_EXTENSIONS,
  ...CSHARP_EXTENSIONS,
  ...RUST_EXTENSIONS,
  ...RUBY_EXTENSIONS,
  ...C_EXTENSIONS
];
var ANALYZABLE_LANGUAGES_LABEL = "JS/TS, Python, Go, Java, C#, Rust, Ruby, C/C++";
function isAnalyzableSource(filePath) {
  return hasExtension(filePath, ANALYZABLE_SOURCE_EXTENSIONS);
}
function nearSortedCall(sortedCalls, idx, window) {
  let lo = 0;
  let hi = sortedCalls.length - 1;
  let best = -1;
  while (lo <= hi) {
    const mid = lo + hi >>> 1;
    if (sortedCalls[mid] <= idx) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  if (best < 0)
    return false;
  return idx - sortedCalls[best] < window;
}
function eachMatch(re, content, onMatch) {
  const g = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  g.lastIndex = 0;
  let m;
  while ((m = g.exec(content)) !== null) {
    onMatch(m);
    if (m.index === g.lastIndex)
      g.lastIndex++;
  }
}

// ../core/dist/cwe.js
var CWE_BROKEN_CRYPTO = "CWE-327";
var CWE_WEAK_STRENGTH = "CWE-326";
var CWE_CERT_VALIDATION = "CWE-295";
var CWE_HARDCODED_KEY = "CWE-798";

// ../core/dist/dependencies.js
var vulnerableDependencies = [
  {
    name: "node-forge",
    ecosystem: "npm",
    reason: "Pure-JS implementation of RSA, RSA-OAEP, and X.509 PKI.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    reason: "Elliptic-curve ECDSA/ECDH (secp256k1, p256, ed25519).",
    algorithms: ["ECDSA", "ECDH", "EdDSA"],
    severity: "high"
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    reason: "RSA/ECDSA/DSA signing, JWT, and X.509 in pure JS.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high"
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    reason: "Classical RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "ursa",
    ecosystem: "npm",
    reason: "OpenSSL-backed RSA encryption and signing bindings.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    reason: "Parses/handles SSH and PEM keys (RSA, ECDSA, Ed25519, DSA).",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium"
  },
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    reason: "JWTs commonly signed with RS256/ES256 (classical RSA/ECDSA).",
    algorithms: ["RSA", "ECDSA"],
    severity: "high"
  },
  {
    name: "jose",
    ecosystem: "npm",
    reason: "JWS/JWE with classical RSA-OAEP, RSA-PSS, ECDH-ES and ECDSA.",
    algorithms: ["RSA", "ECDH", "ECDSA", "EdDSA"],
    severity: "high"
  },
  {
    name: "jws",
    ecosystem: "npm",
    reason: "JSON Web Signatures using classical RS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "high"
  },
  {
    name: "eccrypto",
    ecosystem: "npm",
    reason: "ECIES (ECDH-based) encryption and ECDSA signatures.",
    algorithms: ["ECIES", "ECDH", "ECDSA"],
    severity: "high"
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH bindings (blockchain keys).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    reason: "X25519 key exchange and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low"
  },
  {
    name: "ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures (classical).",
    algorithms: ["EdDSA"],
    severity: "low"
  },
  {
    name: "@noble/curves",
    ecosystem: "npm",
    reason: "Audited classical curves: ECDSA, ECDH, Ed25519, X25519, secp256k1.",
    algorithms: ["ECDSA", "ECDH", "EdDSA", "X25519"],
    severity: "medium"
  },
  {
    name: "@noble/secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH (classical).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "medium"
  },
  {
    name: "@noble/ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "low"
  },
  {
    name: "paseto",
    ecosystem: "npm",
    reason: "PASETO public tokens signed with classical Ed25519 (v2/v4) or RSA.",
    algorithms: ["EdDSA", "RSA"],
    severity: "medium"
  },
  {
    name: "bcrypto",
    ecosystem: "npm",
    reason: "Broad classical crypto suite: RSA, ECDSA, ECDH, Ed25519, DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA", "DSA"],
    severity: "high"
  },
  {
    name: "ecpair",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA key pairs for Bitcoin.",
    algorithms: ["ECDSA"],
    severity: "medium"
  },
  {
    name: "keypair",
    ecosystem: "npm",
    reason: "Pure-JS RSA key pair generation.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "ethers",
    ecosystem: "npm",
    reason: "Ethereum library built on secp256k1 ECDSA signing and key derivation.",
    algorithms: ["ECDSA"],
    severity: "high"
  },
  {
    name: "web3",
    ecosystem: "npm",
    reason: "Ethereum library using secp256k1 ECDSA for accounts and signing.",
    algorithms: ["ECDSA"],
    severity: "high"
  },
  {
    name: "bitcoinjs-lib",
    ecosystem: "npm",
    reason: "Bitcoin library built on secp256k1 ECDSA/Schnorr keys and signatures.",
    algorithms: ["ECDSA"],
    severity: "high"
  },
  {
    name: "ethereumjs-util",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA utilities for Ethereum keys and signatures.",
    algorithms: ["ECDSA"],
    severity: "medium"
  },
  {
    name: "openpgp",
    ecosystem: "npm",
    reason: "OpenPGP.js: RSA, ECDSA, ECDH, and EdDSA public-key crypto.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA"],
    severity: "high"
  },
  {
    name: "node-jose",
    ecosystem: "npm",
    reason: "JOSE (JWS/JWE/JWK) with classical RSA and EC algorithms.",
    algorithms: ["RSA", "ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "jwa",
    ecosystem: "npm",
    reason: "JSON Web Algorithms: RSA (RS/PS) and EC (ES) signatures.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "jwk-to-pem",
    ecosystem: "npm",
    reason: "Converts RSA/EC JWKs to PEM \u2014 classical public keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "fast-jwt",
    ecosystem: "npm",
    reason: "JWT signing/verification with classical RS/PS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "ssh2",
    ecosystem: "npm",
    reason: "SSH client/server using classical RSA/ECDSA/Ed25519 host and user keys.",
    algorithms: ["RSA", "ECDSA", "EdDSA"],
    severity: "high"
  },
  {
    name: "@peculiar/x509",
    ecosystem: "npm",
    reason: "X.509 certificate library over classical RSA/EC keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "pkijs",
    ecosystem: "npm",
    reason: "PKI (X.509/CMS) built on classical RSA and EC public-key crypto.",
    algorithms: ["RSA", "ECDSA", "ECDH"],
    severity: "medium"
  },
  {
    name: "http-signature",
    ecosystem: "npm",
    reason: "HTTP request signing with classical RSA/ECDSA keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "libsodium-wrappers",
    ecosystem: "npm",
    reason: "libsodium: Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "medium"
  },
  {
    name: "ecdsa-sig-formatter",
    ecosystem: "npm",
    reason: "Formats ECDSA signatures \u2014 a marker of classical EC signing.",
    algorithms: ["ECDSA"],
    severity: "low"
  },
  // --- PyPI (Python) ---
  {
    name: "pycryptodome",
    ecosystem: "pypi",
    reason: "RSA / ECC / DSA public-key crypto for Python.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high"
  },
  {
    name: "pycryptodomex",
    ecosystem: "pypi",
    reason: "RSA / ECC / DSA public-key crypto (the `Cryptodome` namespace).",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high"
  },
  {
    name: "rsa",
    ecosystem: "pypi",
    reason: "Pure-Python RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "ecdsa",
    ecosystem: "pypi",
    reason: "Pure-Python ECDSA/ECDH over NIST + secp256k1 curves.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "cryptography",
    ecosystem: "pypi",
    reason: "General crypto library exposing classical RSA/EC/DH/DSA (also symmetric/PQC).",
    algorithms: ["RSA", "ECDH", "ECDSA", "DSA"],
    severity: "medium"
  },
  {
    name: "pyjwt",
    ecosystem: "pypi",
    reason: "JWT signing with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "python-jose",
    ecosystem: "pypi",
    reason: "JOSE/JWT with classical RSA/ECDSA algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "paramiko",
    ecosystem: "pypi",
    reason: "SSH client/server with classical RSA/ECDSA/Ed25519/DSA host + user keys.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium"
  },
  {
    name: "pyopenssl",
    ecosystem: "pypi",
    reason: "OpenSSL bindings for classical RSA/EC X.509 + TLS.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "pynacl",
    ecosystem: "pypi",
    reason: "libsodium bindings \u2014 X25519 key agreement and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low"
  },
  // --- crates.io (Rust) ---
  {
    name: "rsa",
    ecosystem: "cargo",
    reason: "Pure-Rust RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high"
  },
  {
    name: "ring",
    ecosystem: "cargo",
    reason: "RSA / ECDSA / Ed25519 / ECDH primitives.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "ECDH"],
    severity: "medium"
  },
  {
    name: "openssl",
    ecosystem: "cargo",
    reason: "OpenSSL bindings for classical RSA/EC crypto.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "p256",
    ecosystem: "cargo",
    reason: "NIST P-256 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "p384",
    ecosystem: "cargo",
    reason: "NIST P-384 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "k256",
    ecosystem: "cargo",
    reason: "secp256k1 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high"
  },
  {
    name: "ed25519-dalek",
    ecosystem: "cargo",
    reason: "Ed25519 signatures (modern but classical).",
    algorithms: ["EdDSA"],
    severity: "low"
  },
  {
    name: "x25519-dalek",
    ecosystem: "cargo",
    reason: "X25519 key agreement (modern but classical).",
    algorithms: ["X25519"],
    severity: "low"
  },
  // --- Go modules ---
  {
    name: "golang.org/x/crypto",
    ecosystem: "go",
    reason: "SSH, OpenPGP, and classical curve helpers on top of the Go stdlib.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "ECDH"],
    severity: "medium"
  },
  // --- Maven (Java) ---
  {
    name: "bcprov-jdk18on",
    ecosystem: "maven",
    reason: "BouncyCastle provider \u2014 full classical RSA/ECDSA/ECDH/DSA suite.",
    algorithms: ["RSA", "ECDSA", "ECDH", "DSA"],
    severity: "high"
  },
  {
    name: "bcprov-jdk15on",
    ecosystem: "maven",
    reason: "BouncyCastle provider (JDK 1.5+) \u2014 classical RSA/ECDSA/ECDH/DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "DSA"],
    severity: "high"
  },
  {
    name: "bcpkix-jdk18on",
    ecosystem: "maven",
    reason: "BouncyCastle PKIX \u2014 classical X.509 / CMS with RSA/ECDSA.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "java-jwt",
    ecosystem: "maven",
    reason: "Auth0 JWT with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  // --- RubyGems ---
  {
    name: "jwt",
    ecosystem: "rubygems",
    reason: "Ruby JWT with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium"
  },
  {
    name: "rbnacl",
    ecosystem: "rubygems",
    reason: "libsodium bindings \u2014 X25519 key agreement and Ed25519 signatures.",
    algorithms: ["X25519", "EdDSA"],
    severity: "low"
  },
  {
    name: "ed25519",
    ecosystem: "rubygems",
    reason: "Ed25519 signatures (modern but classical).",
    algorithms: ["EdDSA"],
    severity: "low"
  }
];
function normalizeName(ecosystem, name) {
  const n = name.trim();
  if (ecosystem === "pypi")
    return n.toLowerCase().replace(/[-_.]+/g, "-");
  if (ecosystem === "npm" || ecosystem === "go")
    return n;
  return n.toLowerCase();
}
var BY_ECOSYSTEM = (() => {
  const m = /* @__PURE__ */ new Map();
  for (const d of vulnerableDependencies) {
    let em = m.get(d.ecosystem);
    if (!em) {
      em = /* @__PURE__ */ new Map();
      m.set(d.ecosystem, em);
    }
    em.set(normalizeName(d.ecosystem, d.name), d);
  }
  return m;
})();
var KEY_REGEX_BY_NAME = new Map(vulnerableDependencies.filter((d) => d.ecosystem === "npm").map((d) => {
  const escaped = d.name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  return [d.name, new RegExp(`"${escaped}"\\s*:`)];
}));
var CONFIDENTIALITY_FAMILIES = /* @__PURE__ */ new Set([
  "RSA",
  "ECDH",
  "DH",
  "ECIES",
  "X25519",
  "X448"
]);
function multiFamilyRemediation(algorithms) {
  const parts = /* @__PURE__ */ new Set();
  for (const a of algorithms)
    parts.add(remediationText(a));
  return [...parts].join("; ");
}
function manifestEcosystem(file) {
  const base = (file.split("/").pop() ?? file).toLowerCase();
  if (base === "package.json" || base === "package-lock.json")
    return "npm";
  if (base === "requirements.txt" || /^requirements[\w.-]*\.txt$/.test(base))
    return "pypi";
  if (base === "pyproject.toml" || base === "pipfile")
    return "pypi";
  if (base === "cargo.toml")
    return "cargo";
  if (base === "go.mod")
    return "go";
  if (base === "pom.xml" || base === "build.gradle" || base === "build.gradle.kts")
    return "maven";
  if (base === "gemfile" || base.endsWith(".gemspec"))
    return "rubygems";
  return null;
}
function isManifestFile(file) {
  return manifestEcosystem(file) !== null;
}
function candidateNames(ecosystem, content) {
  const names = [];
  const lines = content.split("\n");
  switch (ecosystem) {
    case "pypi": {
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#") || line.startsWith("-"))
          continue;
        const lead = /^["']?([A-Za-z][A-Za-z0-9._-]+)/.exec(line);
        if (lead)
          names.push(lead[1]);
        for (const m of line.matchAll(/["']([A-Za-z][A-Za-z0-9._-]+)/g))
          names.push(m[1]);
      }
      break;
    }
    case "cargo": {
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#"))
          continue;
        const key = /^([A-Za-z0-9][A-Za-z0-9_-]+)\s*=/.exec(line);
        if (key)
          names.push(key[1]);
        const table = /^\[[\w.-]*dependencies\.([A-Za-z0-9][A-Za-z0-9_-]+)\]/.exec(line);
        if (table)
          names.push(table[1]);
      }
      break;
    }
    case "go": {
      for (const m of content.matchAll(/(?:^|\s)([a-z0-9][\w.\-/]+)\s+v\d/gm))
        names.push(m[1]);
      break;
    }
    case "maven": {
      for (const m of content.matchAll(/<artifactId>\s*([\w.-]+)\s*<\/artifactId>/g)) {
        names.push(m[1]);
      }
      for (const m of content.matchAll(/["']([\w.-]+):([\w.-]+):[\w.$-]+["']/g))
        names.push(m[2]);
      break;
    }
    case "rubygems": {
      for (const m of content.matchAll(/\bgem\s+["']([\w.-]+)["']/g))
        names.push(m[1]);
      for (const m of content.matchAll(/add(?:_runtime|_development)?_dependency\s+["']([\w.-]+)["']/g)) {
        names.push(m[1]);
      }
      break;
    }
    case "npm":
      break;
  }
  return names;
}
function offsetOfName(content, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  const m = new RegExp(`(?<![\\w./-])${escaped}(?![\\w-])`).exec(content);
  return m ? m.index : 0;
}
function dependencyFinding(dep, file, content, index) {
  const algorithm = dep.algorithms[0] ?? "unknown";
  return makeFinding({
    ruleId: "dep-vulnerable",
    title: `Quantum-vulnerable dependency: ${dep.name}`,
    category: "dependency",
    severity: dep.severity,
    confidence: "high",
    algorithm,
    // Confidentiality libs are HNDL-exposed; signature-only ones are not.
    hndl: dep.algorithms.some((a) => CONFIDENTIALITY_FAMILIES.has(a)),
    cwe: CWE_BROKEN_CRYPTO,
    message: `${dep.name} \u2014 ${dep.reason}`,
    remediation: multiFamilyRemediation(dep.algorithms),
    file,
    content,
    index
  });
}
function offsetOfKey(content, name) {
  const re = KEY_REGEX_BY_NAME.get(name);
  if (!re)
    return 0;
  const m = re.exec(content);
  return m ? m.index : 0;
}
function sortByTitle(findings) {
  findings.sort((a, b) => a.title < b.title ? -1 : a.title > b.title ? 1 : 0);
  return findings;
}
function scanManifest(file, content) {
  const ecosystem = manifestEcosystem(file);
  if (!ecosystem)
    return [];
  const db = BY_ECOSYSTEM.get(ecosystem);
  if (!db)
    return [];
  if (ecosystem === "npm")
    return scanNpmManifest(content, file, db);
  const found = /* @__PURE__ */ new Map();
  for (const raw of candidateNames(ecosystem, content)) {
    const dep = db.get(normalizeName(ecosystem, raw));
    if (dep)
      found.set(dep.name, dep);
  }
  const findings = [];
  for (const dep of found.values()) {
    findings.push(dependencyFinding(dep, file, content, offsetOfName(content, dep.name)));
  }
  return sortByTitle(findings);
}
function scanNpmManifest(content, file, db) {
  let json;
  try {
    json = JSON.parse(content);
  } catch {
    return [];
  }
  if (json === null || typeof json !== "object")
    return [];
  const found = /* @__PURE__ */ new Set();
  const obj = json;
  const collectFromRecord = (rec) => {
    if (rec === null || typeof rec !== "object")
      return;
    for (const key of Object.keys(rec)) {
      if (db.has(key))
        found.add(key);
    }
  };
  collectFromRecord(obj.dependencies);
  collectFromRecord(obj.devDependencies);
  collectFromRecord(obj.peerDependencies);
  collectFromRecord(obj.optionalDependencies);
  const packages = obj.packages;
  if (packages !== null && typeof packages === "object") {
    for (const key of Object.keys(packages)) {
      if (!key)
        continue;
      const marker = "node_modules/";
      const idx = key.lastIndexOf(marker);
      const name = idx >= 0 ? key.slice(idx + marker.length) : key;
      if (db.has(name))
        found.add(name);
    }
  }
  const findings = [];
  for (const name of found) {
    const dep = db.get(name);
    if (!dep)
      continue;
    findings.push(dependencyFinding(dep, file, content, offsetOfKey(content, name)));
  }
  return sortByTitle(findings);
}

// ../core/dist/walk.js
var DEFAULT_IGNORES = [
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "out",
  "coverage",
  "vendor",
  ".turbo",
  ".cache"
];
var DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;
var BINARY_EXTENSIONS = /* @__PURE__ */ new Set([
  // images
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".tiff",
  ".avif",
  // fonts
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  // archives / compressed
  ".zip",
  ".gz",
  ".tgz",
  ".bz2",
  ".xz",
  ".7z",
  ".rar",
  ".tar",
  // media
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".mkv",
  ".wav",
  ".flac",
  ".ogg",
  ".webm",
  // documents / binaries
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ppt",
  ".pptx",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".o",
  ".a",
  ".class",
  ".wasm",
  // data blobs / db
  ".db",
  ".sqlite",
  ".sqlite3",
  ".dat",
  ".pack",
  ".idx",
  // misc
  ".lock",
  ".map",
  ".min.js",
  ".node"
]);
function toPosix(p) {
  return p.split(path.sep).join("/");
}
function matchesAny(rel, patterns) {
  for (const pattern of patterns) {
    if (!pattern)
      continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    if (rel.includes(p))
      return true;
    if (rel === p || rel.startsWith(`${p}/`))
      return true;
  }
  return false;
}
function isExcluded(rel, exclude) {
  return matchesAny(rel, exclude);
}
function isIncluded(rel, include) {
  if (include.length === 0)
    return true;
  return matchesAny(rel, include);
}
function isBinaryPath(rel) {
  const lower = rel.toLowerCase();
  if (lower.endsWith(".min.js"))
    return true;
  const ext = path.posix.extname(lower);
  return BINARY_EXTENSIONS.has(ext);
}
var GENERATED_PATH_RE = /(?:\.min\.[mc]?js|[.-]min\.[mc]?js|\.bundle\.[mc]?js|\.chunk\.[mc]?js|\.generated\.[jt]sx?|_pb\.js|\.pb\.go)$/i;
function isGeneratedPath(rel) {
  return GENERATED_PATH_RE.test(rel.toLowerCase());
}
function looksMinified(content) {
  const sample = content.length > 65536 ? content.slice(0, 65536) : content;
  if (sample.length === 0)
    return false;
  let maxLine = 0;
  let cur = 0;
  let lines = 1;
  for (let i = 0; i < sample.length; i++) {
    if (sample.charCodeAt(i) === 10) {
      if (cur > maxLine)
        maxLine = cur;
      cur = 0;
      lines++;
    } else {
      cur++;
    }
  }
  if (cur > maxLine)
    maxLine = cur;
  if (maxLine > 5e4)
    return true;
  const avgLine = sample.length / lines;
  return avgLine > 1e3;
}
async function* walkFiles(root, options = {}) {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const ignores = options.noDefaultIgnores ? [] : DEFAULT_IGNORES;
  const rootStat = await stat(root);
  if (rootStat.isFile()) {
    const name = toPosix(path.basename(root));
    if (!isBinaryPath(name) && isIncluded(name, include) && passesSizeLimit(name, rootStat.size, maxFileSize)) {
      yield name;
    }
    return;
  }
  yield* walkDir(root, "", { include, exclude, maxFileSize, ignores });
}
function passesSizeLimit(rel, size, maxFileSize) {
  if (isManifestFile(rel))
    return true;
  return size <= maxFileSize;
}
async function* walkDir(absDir, relDir, ctx) {
  let entries;
  try {
    entries = await readdir(absDir, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const entry of entries) {
    const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
    const abs = path.join(absDir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      if (ctx.ignores.includes(entry.name))
        continue;
      if (isExcluded(rel, ctx.exclude))
        continue;
      yield* walkDir(abs, rel, ctx);
      continue;
    }
    if (!entry.isFile())
      continue;
    if (isExcluded(rel, ctx.exclude))
      continue;
    if (!isIncluded(rel, ctx.include))
      continue;
    if (isBinaryPath(rel))
      continue;
    if (isGeneratedPath(rel))
      continue;
    try {
      const s = await stat(abs);
      if (!passesSizeLimit(rel, s.size, ctx.maxFileSize))
        continue;
    } catch {
      continue;
    }
    yield rel;
  }
}

// ../core/dist/detectors/source.js
var RE_GENERATE_KEYPAIR = /generateKeyPair(?:Sync)?\s*\(\s*['"`](rsa-pss|rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"`]/g;
var RE_CREATE_SIGN_VERIFY = /create(?:Sign|Verify)\s*\(/g;
var RE_ONESHOT_SIGN_VERIFY = /(?<![.\w])(?:crypto\.)?(sign|verify)\s*\(\s*(?:['"`][\w.-]+['"`]|null)\s*,/g;
var RE_CREATE_DH = /createDiffieHellman(?:Group)?\s*\(/g;
var RE_GET_DH = /getDiffieHellman\s*\(\s*['"`](modp\d+)['"`]\s*\)/g;
var RE_CREATE_ECDH = /createECDH\s*\(/g;
var RE_RSA_ENCRYPT = /(?:crypto\.)?(?:publicEncrypt|privateDecrypt)\s*\(/g;
var RE_DH_KEYOBJECT = /(?:crypto\.)?diffieHellman\s*\(\s*\{/g;
var RE_WEBCRYPTO_ALGO = /\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDH|ECDSA|Ed25519|Ed448|X25519|X448)\b/gi;
var RE_SUBTLE_CALL = /subtle\s*\.\s*(generateKey|importKey|exportKey|deriveKey|deriveBits|sign|verify|encrypt|decrypt|wrapKey|unwrapKey)\s*\(/g;
var RE_FORGE_RSA = /pki\.rsa\.generateKeyPair\s*\(/g;
var RE_FORGE_ED25519 = /forge\.ed25519\b/g;
var RE_ELLIPTIC_EC = /new\s+(?:elliptic\.)?ec\s*\(/gi;
var RE_JSRSASIGN_KEYGEN = /KEYUTIL\.generateKeypair\s*\(/g;
var RE_JSRSASIGN_SIGN = /KJUR\.crypto\.(?:Signature|ECDSA)\b/g;
var RE_NODE_RSA = /new\s+NodeRSA\s*\(/g;
var RE_SECP256K1 = /\b(?:secp(?:256k1)?|secp)\s*\.\s*(?:sign|verify|getPublicKey|getSharedSecret|ecdh|recoverPublicKey)\s*\(/g;
var RE_JWT_ALG = /['"`](RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)['"`]/g;
var RE_JOSE_ECDH = /['"`](ECDH-ES(?:\+A(?:128|192|256)KW)?)['"`]/g;
var RE_TLS_LEGACY_VERSION = /(?:minVersion|maxVersion)\s*:\s*['"`]TLSv1(?:\.1)?['"`]|secureProtocol\s*:\s*['"`]TLSv1(?:_1)?_method['"`]/g;
var RE_TLS_REJECT = /rejectUnauthorized\s*:\s*false/g;
var RE_TLS_WEAK_CIPHER = /ciphers\s*:\s*['"`][^'"`\n]{0,256}?\b(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`\n]{0,256}?['"`]/gi;
var RULE_NODE_KEYGEN = {
  id: "node-crypto-keygen",
  title: "Classical key generation",
  description: "crypto.generateKeyPair(Sync)('rsa'|'ec'|'dsa'|'dh'|\u2026)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical asymmetric key pair, which is not quantum-safe."
};
var RULE_NODE_SIGN = {
  id: "node-crypto-sign",
  title: "Classical signature (createSign/createVerify)",
  description: "crypto.createSign / crypto.createVerify",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Uses createSign/createVerify, typically RSA, ECDSA or DSA \u2014 all forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_NODE_SIGN_ONESHOT = {
  id: "node-crypto-sign-oneshot",
  title: "Classical one-shot signature (crypto.sign/verify)",
  description: "one-shot crypto.sign / crypto.verify (Node \u2265 12)",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Uses the one-shot crypto.sign/crypto.verify API, typically RSA/ECDSA/EdDSA \u2014 forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_NODE_DH = {
  id: "node-crypto-dh",
  title: "Diffie-Hellman key exchange",
  description: "crypto.createDiffieHellman(Group)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_NODE_DH_MODP = {
  id: "node-crypto-dh-modp",
  title: "Diffie-Hellman MODP group",
  description: "crypto.getDiffieHellman('modpN')",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Named finite-field DH MODP group is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_NODE_ECDH = {
  id: "node-crypto-ecdh",
  title: "ECDH key exchange",
  description: "crypto.createECDH",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_NODE_RSA_ENCRYPT = {
  id: "node-crypto-rsa-encrypt",
  title: "RSA public-key encryption",
  description: "crypto.publicEncrypt / crypto.privateDecrypt",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "RSA public-key encryption is broken by Shor's algorithm and exposed to harvest-now-decrypt-later."
};
var RULE_NODE_DH_KEYOBJECT = {
  id: "node-crypto-dh-keyobject",
  title: "Diffie-Hellman (KeyObject) key exchange",
  description: "crypto.diffieHellman({ privateKey, publicKey })",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "crypto.diffieHellman() performs a classical (EC)DH agreement (harvest-now-decrypt-later)."
};
var nodeCryptoDetector = {
  id: "node-crypto",
  description: "Classical asymmetric crypto via the Node.js `crypto` module",
  scope: "source",
  language: "js",
  rules: [
    RULE_NODE_KEYGEN,
    RULE_NODE_SIGN,
    RULE_NODE_SIGN_ONESHOT,
    RULE_NODE_DH,
    RULE_NODE_DH_MODP,
    RULE_NODE_ECDH,
    RULE_NODE_RSA_ENCRYPT,
    RULE_NODE_DH_KEYOBJECT
  ],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_GENERATE_KEYPAIR, content, (m) => {
      const type = m[1].toLowerCase();
      const map = {
        rsa: { algo: "RSA", cat: "kem", sev: "high", hndl: true, label: "RSA" },
        // RSA-PSS is signature-only, so classify it as a (forgeable) signature
        // rather than a KEM — no HNDL confidentiality exposure.
        "rsa-pss": {
          algo: "RSA",
          cat: "signature",
          sev: "high",
          hndl: false,
          label: "RSA-PSS",
          message: "Generates a classical RSA-PSS signing key, which is forgeable by a quantum attacker.",
          remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
        },
        // EC keys feed BOTH ECDSA (sign) and ECDH (key agreement). ECDH is
        // HNDL-exposed, so classify conservatively as key-exchange-capable and
        // surface both concerns rather than asserting signature-only (P0-4).
        ec: {
          algo: "ECDH",
          cat: "key-exchange",
          sev: "high",
          hndl: true,
          label: "EC (ECDSA/ECDH)",
          message: "Generates a classical EC key pair. EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
          remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
        },
        dsa: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
        dh: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
        x25519: { algo: "X25519", cat: "key-exchange", sev: "low", hndl: true, label: "X25519" },
        x448: { algo: "X448", cat: "key-exchange", sev: "low", hndl: true, label: "X448" },
        ed25519: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed25519" },
        ed448: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed448" }
      };
      const info2 = map[type];
      findings.push(findingFromRule(RULE_NODE_KEYGEN, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `${info2.label} key generation`,
        category: info2.cat,
        severity: info2.sev,
        algorithm: info2.algo,
        hndl: info2.hndl,
        message: info2.message ?? `Generates a classical ${info2.label} key pair, which is not quantum-safe.`,
        ...info2.remediation ? { remediation: info2.remediation } : {}
      }));
    });
    eachMatch(RE_CREATE_SIGN_VERIFY, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_SIGN, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_ONESHOT_SIGN_VERIFY, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_SIGN_ONESHOT, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_CREATE_DH, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_DH, { file, content, index: m.index, matchLength: m[0].length }));
    });
    eachMatch(RE_GET_DH, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_DH_MODP, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `Diffie-Hellman MODP group (${m[1]})`,
        message: `Named finite-field DH MODP group "${m[1]}" is broken by Shor's algorithm (harvest-now-decrypt-later).`
      }));
    });
    eachMatch(RE_CREATE_ECDH, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_ECDH, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_RSA_ENCRYPT, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_RSA_ENCRYPT, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_DH_KEYOBJECT, content, (m) => {
      findings.push(findingFromRule(RULE_NODE_DH_KEYOBJECT, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    return findings;
  }
};
var RULE_WEBCRYPTO = {
  id: "webcrypto-classical",
  title: "WebCrypto classical algorithm",
  description: "classical asymmetric algorithm passed to SubtleCrypto",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "A classical asymmetric WebCrypto algorithm is used, which is not quantum-safe."
};
var webCryptoDetector = {
  id: "webcrypto",
  description: "Classical asymmetric algorithms via WebCrypto SubtleCrypto",
  scope: "source",
  language: "js",
  rules: [RULE_WEBCRYPTO],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const callIndexes = [];
    eachMatch(RE_SUBTLE_CALL, content, (m) => callIndexes.push(m.index));
    if (callIndexes.length === 0)
      return findings;
    eachMatch(RE_WEBCRYPTO_ALGO, content, (m) => {
      if (!nearSortedCall(callIndexes, m.index, 400))
        return;
      const name = m[1].toUpperCase();
      let algorithm;
      let category;
      let hndl;
      let severity;
      if (name.startsWith("RSA")) {
        algorithm = "RSA";
        const isKem = name === "RSA-OAEP";
        category = isKem ? "kem" : "signature";
        hndl = isKem;
      } else if (name === "ECDH") {
        algorithm = "ECDH";
        category = "key-exchange";
        hndl = true;
      } else if (name === "X25519" || name === "X448") {
        algorithm = name === "X448" ? "X448" : "X25519";
        category = "key-exchange";
        hndl = true;
        severity = "low";
      } else if (name === "ED25519" || name === "ED448") {
        algorithm = "EdDSA";
        category = "signature";
        hndl = false;
        severity = "low";
      } else {
        algorithm = "ECDSA";
        category = "signature";
        hndl = false;
      }
      findings.push(findingFromRule(RULE_WEBCRYPTO, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `WebCrypto ${m[1]}`,
        category,
        algorithm,
        hndl,
        ...severity ? { severity } : {},
        message: `WebCrypto algorithm "${m[1]}" is classical asymmetric crypto and not quantum-safe.`
      }));
    });
    return findings;
  }
};
var RULE_FORGE_RSA = {
  id: "forge-rsa-keygen",
  title: "node-forge RSA key generation",
  description: "node-forge pki.rsa.generateKeyPair",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-forge generates a classical RSA key pair, which is not quantum-safe."
};
var RULE_FORGE_ED25519 = {
  id: "forge-ed25519",
  title: "node-forge Ed25519 usage",
  description: "node-forge forge.ed25519.*",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-forge Ed25519 is a modern but still classical signature scheme."
};
var RULE_ELLIPTIC_EC = {
  id: "elliptic-ec",
  title: "elliptic curve instantiation",
  description: "the `elliptic` library \u2014 new EC(...)",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "The `elliptic` library implements classical ECDSA/ECDH, both broken by Shor's algorithm."
};
var RULE_SECP256K1 = {
  id: "secp256k1-usage",
  title: "secp256k1 ECDSA/ECDH usage",
  description: "direct @noble/secp256k1-style API usage",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Direct secp256k1 usage (ECDSA signatures / ECDH agreement) is classical and broken by Shor's algorithm.",
  remediation: "ML-DSA-65 (FIPS 204) for signatures; hybrid X25519MLKEM768 for key agreement."
};
var RULE_JSRSASIGN_KEYGEN = {
  id: "jsrsasign-keygen",
  title: "jsrsasign key generation",
  description: "jsrsasign KEYUTIL.generateKeypair",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "jsrsasign generates classical RSA/EC key pairs, which are not quantum-safe.",
  remediation: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"
};
var RULE_JSRSASIGN_SIGN = {
  id: "jsrsasign-sign",
  title: "jsrsasign signature",
  description: "jsrsasign KJUR.crypto.Signature / ECDSA",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "jsrsasign signing uses classical RSA/ECDSA signatures, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204)"
};
var RULE_NODE_RSA_LIB = {
  id: "node-rsa",
  title: "node-rsa key/usage",
  description: "the `node-rsa` library \u2014 new NodeRSA(...)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-rsa wraps classical RSA encryption/signing, which is not quantum-safe."
};
var libraryDetector = {
  id: "crypto-libs",
  description: "Classical asymmetric crypto via node-forge, elliptic, jsrsasign, node-rsa",
  scope: "source",
  language: "js",
  rules: [
    RULE_FORGE_RSA,
    RULE_FORGE_ED25519,
    RULE_ELLIPTIC_EC,
    RULE_SECP256K1,
    RULE_JSRSASIGN_KEYGEN,
    RULE_JSRSASIGN_SIGN,
    RULE_NODE_RSA_LIB
  ],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_FORGE_RSA, RULE_FORGE_RSA);
    add(RE_FORGE_ED25519, RULE_FORGE_ED25519);
    add(RE_ELLIPTIC_EC, RULE_ELLIPTIC_EC);
    add(RE_SECP256K1, RULE_SECP256K1);
    add(RE_JSRSASIGN_KEYGEN, RULE_JSRSASIGN_KEYGEN);
    add(RE_JSRSASIGN_SIGN, RULE_JSRSASIGN_SIGN);
    add(RE_NODE_RSA, RULE_NODE_RSA_LIB);
    return findings;
  }
};
var RULE_JWT_ALG = {
  id: "jwt-classical-alg",
  title: "Classical JWT/JOSE algorithm",
  description: "JWS alg tokens (RS/PS/ES/EdDSA)",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "A classical JWT/JOSE signature algorithm is used, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204); track IETF PQC JOSE/COSE algorithms"
};
var RULE_JOSE_ECDH = {
  id: "jose-ecdh-es",
  title: "JOSE ECDH-ES key agreement",
  description: "JOSE ECDH-ES / ECDH-ES+A*KW key agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "JOSE ECDH-ES performs classical ECDH key agreement \u2014 harvest-now-decrypt-later exposed.",
  remediation: "Track IETF PQC JOSE/COSE; adopt hybrid X25519MLKEM768 KEM-based encryption."
};
var jwtDetector = {
  id: "jwt-jose",
  description: "Classical JWT/JOSE algorithms (RS/PS/ES/EdDSA) and ECDH-ES key agreement",
  scope: "source",
  // Language-agnostic evidence: a quoted "RS256"/"ES256" alg token is the same
  // signal in JS/TS or Python (e.g. PyJWT `algorithm="RS256"`), so this detector
  // is un-gated from JS-only to the JWT host surfaces.
  language: "any",
  rules: [RULE_JWT_ALG, RULE_JOSE_ECDH],
  appliesTo: (f) => hasExtension(f, JWT_HOST_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_JWT_ALG, content, (m) => {
      const alg = m[1];
      let algorithm;
      if (alg.startsWith("RS") || alg.startsWith("PS"))
        algorithm = "RSA";
      else if (alg === "EdDSA")
        algorithm = "EdDSA";
      else
        algorithm = "ECDSA";
      findings.push(findingFromRule(RULE_JWT_ALG, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `JWT/JOSE algorithm ${alg}`,
        algorithm,
        message: `JWT/JOSE algorithm "${alg}" is a classical signature, forgeable by a quantum attacker.`
      }));
    });
    eachMatch(RE_JOSE_ECDH, content, (m) => {
      findings.push(findingFromRule(RULE_JOSE_ECDH, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `JOSE key agreement ${m[1]}`,
        message: `JOSE "${m[1]}" performs classical ECDH key agreement \u2014 harvest-now-decrypt-later exposed.`
      }));
    });
    return findings;
  }
};
var RULE_TLS_LEGACY = {
  id: "tls-legacy-version",
  title: "Legacy TLS version pinned",
  description: "minVersion/maxVersion/secureProtocol pinned to TLS 1.0/1.1",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "TLS 1.0/1.1 are deprecated and insecure; require TLS 1.3.",
  remediation: "Set minVersion: 'TLSv1.3' and prefer PQC-hybrid key exchange."
};
var RULE_TLS_REJECT = {
  id: "tls-reject-unauthorized",
  title: "TLS certificate verification disabled",
  description: "rejectUnauthorized: false",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "rejectUnauthorized:false disables TLS certificate verification (MITM risk).",
  remediation: "Remove rejectUnauthorized:false; verify certificates properly."
};
var RULE_TLS_WEAK_CIPHER = {
  id: "tls-weak-cipher",
  title: "Weak TLS cipher configured",
  description: "weak/export cipher in a `ciphers` string",
  category: "tls",
  severity: "medium",
  confidence: "medium",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "A weak cipher is configured in the TLS ciphers list.",
  remediation: "Use a modern AEAD cipher suite (TLS 1.3 defaults)."
};
var tlsDetector = {
  id: "tls-config",
  description: "Legacy / insecure TLS configuration in JS objects",
  scope: "config",
  language: "js",
  rules: [RULE_TLS_LEGACY, RULE_TLS_REJECT, RULE_TLS_WEAK_CIPHER],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_TLS_LEGACY_VERSION, content, (m) => {
      findings.push(findingFromRule(RULE_TLS_LEGACY, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_TLS_REJECT, content, (m) => {
      findings.push(findingFromRule(RULE_TLS_REJECT, {
        file,
        content,
        index: m.index,
        matchLength: m[0].length
      }));
    });
    eachMatch(RE_TLS_WEAK_CIPHER, content, (m) => {
      findings.push(findingFromRule(RULE_TLS_WEAK_CIPHER, { file, content, index: m.index, matchLength: m[0].length }, { message: `Weak cipher (${m[1]}) configured in the TLS ciphers list.` }));
    });
    return findings;
  }
};
var RE_SSH_PUBKEY = /\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\b/g;
var RE_CERT_SIG_ALG = /\b(sha(?:1|256|384|512)WithRSAEncryption|ecdsa-with-SHA(?:1|256|384|512)|rsassaPss|dsaWithSHA(?:1|256))\b/g;
var RULE_SSH_PUBKEY = {
  id: "ssh-public-key",
  title: "Classical SSH public key",
  description: "ssh-rsa / ssh-ed25519 / ssh-dss / ecdsa-sha2-* public keys",
  category: "certificate",
  severity: "low",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  sensitive: true,
  message: "A classical SSH public key is forgeable by a quantum attacker.",
  remediation: "Plan migration to PQC-capable SSH (e.g. sntrup761x25519 KEX, PQC host keys)."
};
var RULE_CERT_SIG_ALG = {
  id: "cert-signature-algorithm",
  title: "Classical certificate signature algorithm",
  description: "X.509/TLS certificate signature-algorithm identifiers",
  category: "certificate",
  severity: "low",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "A classical certificate signature algorithm (RSA/ECDSA/DSA) is a quantum forgery surface.",
  remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature."
};
var sshCertDetector = {
  id: "ssh-cert",
  description: "SSH public keys and TLS/X.509 certificate signature algorithms in config",
  scope: "config",
  language: "any",
  rules: [RULE_SSH_PUBKEY, RULE_CERT_SIG_ALG],
  appliesTo: () => true,
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_SSH_PUBKEY, content, (m) => {
      const tok = m[1];
      const algorithm = tok.startsWith("ssh-rsa") ? "RSA" : tok === "ssh-ed25519" ? "EdDSA" : tok === "ssh-dss" ? "DSA" : "ECDSA";
      findings.push(findingFromRule(RULE_SSH_PUBKEY, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `Classical SSH public key (${tok})`,
        algorithm,
        message: `SSH public key type "${tok}" is a classical key forgeable by a quantum attacker.`
      }));
    });
    eachMatch(RE_CERT_SIG_ALG, content, (m) => {
      const tok = m[1];
      const algorithm = /RSA|rsassa/i.test(tok) ? "RSA" : tok.startsWith("ecdsa") ? "ECDSA" : "DSA";
      findings.push(findingFromRule(RULE_CERT_SIG_ALG, { file, content, index: m.index, matchLength: m[0].length }, {
        title: `Classical certificate signature algorithm (${tok})`,
        algorithm,
        message: `Certificate signature algorithm "${tok}" is classical (RSA/ECDSA/DSA) \u2014 a quantum forgery surface.`
      }));
    });
    return findings;
  }
};
var sourceDetectors = [
  nodeCryptoDetector,
  webCryptoDetector,
  libraryDetector,
  jwtDetector,
  tlsDetector,
  sshCertDetector
];

// ../core/dist/detectors/python.js
var RE_PY_RSA_KEYGEN = /\brsa\.generate_private_key\s*\(|\bRSA\.generate\s*\(|\bparamiko\.RSAKey\b|\bRSAKey\.generate\s*\(/g;
var RE_PY_RSA_ENCRYPT = /\bpadding\.OAEP\s*\(|\bPKCS1_OAEP\.new\s*\(/g;
var RE_PY_EC_KEYGEN = /\bec\.generate_private_key\s*\(|\bECC\.generate\s*\(/g;
var RE_PY_ECDSA = /\bec\.ECDSA\s*\(|\bparamiko\.ECDSAKey\b|\bECDSAKey\.generate\s*\(/g;
var RE_PY_DSA = /\bDSA\.generate\s*\(|\bparamiko\.DSSKey\b|\bDSSKey\.generate\s*\(/g;
var RE_PY_DH = /\bdh\.generate_parameters\s*\(|\bdh\.DHParameterNumbers\s*\(/g;
var RE_PY_X25519 = /\bX25519PrivateKey\.generate\s*\(/g;
var RE_PY_X448 = /\bX448PrivateKey\.generate\s*\(/g;
var RE_PY_EDDSA = /\b(?:Ed25519|Ed448)PrivateKey\.generate\s*\(|\bparamiko\.Ed25519Key\b/g;
var RULE_PY_RSA_KEYGEN = {
  id: "python-rsa-keygen",
  title: "Python RSA key generation",
  description: "cryptography rsa.generate_private_key / PyCryptodome RSA.generate / paramiko RSAKey",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (Python), which is not quantum-safe."
};
var RULE_PY_RSA_ENCRYPT = {
  id: "python-rsa-encrypt",
  title: "Python RSA public-key encryption",
  description: "RSA-OAEP / PKCS1_OAEP encryption padding",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "RSA public-key encryption (OAEP) is broken by Shor's algorithm and exposed to harvest-now-decrypt-later."
};
var RULE_PY_EC_KEYGEN = {
  id: "python-ec-keygen",
  title: "Python EC key generation",
  description: "cryptography ec.generate_private_key / PyCryptodome ECC.generate",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical EC key pair (Python). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
};
var RULE_PY_ECDSA = {
  id: "python-ecdsa",
  title: "Python ECDSA signature",
  description: "cryptography ec.ECDSA / paramiko ECDSAKey",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Python) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_PY_DSA = {
  id: "python-dsa",
  title: "Python DSA key/usage",
  description: "PyCryptodome DSA.generate / paramiko DSSKey",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Python) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var RULE_PY_DH = {
  id: "python-dh",
  title: "Python Diffie-Hellman key exchange",
  description: "cryptography dh.generate_parameters / DHParameterNumbers",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman (Python) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_PY_X25519 = {
  id: "python-x25519",
  title: "Python X25519 key exchange",
  description: "cryptography X25519PrivateKey.generate",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X25519 (Python) is modern but still classical key agreement \u2014 harvest-now-decrypt-later."
};
var RULE_PY_X448 = {
  id: "python-x448",
  title: "Python X448 key exchange",
  description: "cryptography X448PrivateKey.generate",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X448",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X448 (Python) is modern but still classical key agreement \u2014 harvest-now-decrypt-later."
};
var RULE_PY_EDDSA = {
  id: "python-eddsa",
  title: "Python Ed25519/Ed448 signature",
  description: "cryptography Ed25519/Ed448 PrivateKey.generate / paramiko Ed25519Key",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519/Ed448 (Python) is a modern but still classical signature scheme."
};
var pythonDetector = {
  id: "python-crypto",
  description: "Classical asymmetric crypto in Python (cryptography, PyCryptodome, paramiko)",
  scope: "source",
  language: "python",
  rules: [
    RULE_PY_RSA_KEYGEN,
    RULE_PY_RSA_ENCRYPT,
    RULE_PY_EC_KEYGEN,
    RULE_PY_ECDSA,
    RULE_PY_DSA,
    RULE_PY_DH,
    RULE_PY_X25519,
    RULE_PY_X448,
    RULE_PY_EDDSA
  ],
  appliesTo: (f) => hasExtension(f, PYTHON_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_PY_RSA_KEYGEN, RULE_PY_RSA_KEYGEN);
    add(RE_PY_RSA_ENCRYPT, RULE_PY_RSA_ENCRYPT);
    add(RE_PY_EC_KEYGEN, RULE_PY_EC_KEYGEN);
    add(RE_PY_ECDSA, RULE_PY_ECDSA);
    add(RE_PY_DSA, RULE_PY_DSA);
    add(RE_PY_DH, RULE_PY_DH);
    add(RE_PY_X25519, RULE_PY_X25519);
    add(RE_PY_X448, RULE_PY_X448);
    add(RE_PY_EDDSA, RULE_PY_EDDSA);
    return findings;
  }
};

// ../core/dist/detectors/go.js
var RE_GO_RSA_KEYGEN = /\brsa\.GenerateKey\s*\(|\brsa\.GenerateMultiPrimeKey\s*\(/g;
var RE_GO_RSA_ENCRYPT = /\brsa\.EncryptOAEP\s*\(|\brsa\.EncryptPKCS1v15\s*\(/g;
var RE_GO_RSA_SIGN = /\brsa\.SignPKCS1v15\s*\(|\brsa\.SignPSS\s*\(/g;
var RE_GO_ECDSA = /\becdsa\.GenerateKey\s*\(|\becdsa\.SignASN1\s*\(|\becdsa\.Sign\s*\(/g;
var RE_GO_ECDH = /\becdh\.(?:P256|P384|P521|X25519)\s*\(/g;
var RE_GO_ED25519 = /\bed25519\.GenerateKey\s*\(|\bed25519\.Sign\s*\(/g;
var RE_GO_DSA = /\bdsa\.GenerateKey\s*\(|\bdsa\.GenerateParameters\s*\(/g;
var RULE_GO_RSA_KEYGEN = {
  id: "go-rsa-keygen",
  title: "Go RSA key generation",
  description: "crypto/rsa GenerateKey / GenerateMultiPrimeKey",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (Go), which is not quantum-safe."
};
var RULE_GO_RSA_ENCRYPT = {
  id: "go-rsa-encrypt",
  title: "Go RSA public-key encryption",
  description: "crypto/rsa EncryptOAEP / EncryptPKCS1v15",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "RSA public-key encryption (Go) is broken by Shor's algorithm and exposed to harvest-now-decrypt-later."
};
var RULE_GO_RSA_SIGN = {
  id: "go-rsa-sign",
  title: "Go RSA signature",
  description: "crypto/rsa SignPKCS1v15 / SignPSS",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA signing (Go) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_GO_ECDSA = {
  id: "go-ecdsa",
  title: "Go ECDSA key/signature",
  description: "crypto/ecdsa GenerateKey / Sign / SignASN1",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA (Go) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_GO_ECDH = {
  id: "go-ecdh",
  title: "Go ECDH key exchange",
  description: "crypto/ecdh P256/P384/P521/X25519 key agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman (Go crypto/ecdh) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_GO_ED25519 = {
  id: "go-ed25519",
  title: "Go Ed25519 signature",
  description: "crypto/ed25519 GenerateKey / Sign",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519 (Go) is a modern but still classical signature scheme."
};
var RULE_GO_DSA = {
  id: "go-dsa",
  title: "Go DSA key/usage",
  description: "crypto/dsa GenerateKey / GenerateParameters",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Go) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var goDetector = {
  id: "go-crypto",
  description: "Classical asymmetric crypto in Go (crypto/rsa, ecdsa, ecdh, ed25519, dsa)",
  scope: "source",
  language: "go",
  rules: [
    RULE_GO_RSA_KEYGEN,
    RULE_GO_RSA_ENCRYPT,
    RULE_GO_RSA_SIGN,
    RULE_GO_ECDSA,
    RULE_GO_ECDH,
    RULE_GO_ED25519,
    RULE_GO_DSA
  ],
  appliesTo: (f) => hasExtension(f, GO_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_GO_RSA_KEYGEN, RULE_GO_RSA_KEYGEN);
    add(RE_GO_RSA_ENCRYPT, RULE_GO_RSA_ENCRYPT);
    add(RE_GO_RSA_SIGN, RULE_GO_RSA_SIGN);
    add(RE_GO_ECDSA, RULE_GO_ECDSA);
    add(RE_GO_ECDH, RULE_GO_ECDH);
    add(RE_GO_ED25519, RULE_GO_ED25519);
    add(RE_GO_DSA, RULE_GO_DSA);
    return findings;
  }
};

// ../core/dist/detectors/java.js
var RE_JAVA_GETINSTANCE = /\b(KeyPairGenerator|Signature|Cipher|KeyAgreement|KeyFactory)\s*\.\s*getInstance\s*\(\s*"([^"]+)"/g;
var RE_JAVA_BC = /\bnew\s+(RSAKeyPairGenerator|DSAKeyPairGenerator|ECKeyPairGenerator|ECDSASigner|Ed25519Signer|Ed448Signer|X25519Agreement|X448Agreement)\s*\(/g;
var RULE_JAVA_RSA = {
  id: "java-rsa",
  title: "Java RSA key/encryption",
  description: "JCA RSA KeyPairGenerator / Cipher / KeyFactory",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Java/JCA) is not quantum-safe and RSA encryption is HNDL-exposed."
};
var RULE_JAVA_RSA_SIGN = {
  id: "java-rsa-sign",
  title: "Java RSA signature",
  description: 'JCA Signature.getInstance("\u2026withRSA")',
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA signing (Java/JCA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_JAVA_EC_KEYGEN = {
  id: "java-ec-keygen",
  title: "Java EC key generation",
  description: 'JCA KeyPairGenerator.getInstance("EC")',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical EC key pair (Java/JCA). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
};
var RULE_JAVA_ECDSA_SIGN = {
  id: "java-ecdsa-sign",
  title: "Java ECDSA signature",
  description: 'JCA Signature.getInstance("\u2026withECDSA")',
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Java/JCA) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_JAVA_ECDH = {
  id: "java-ecdh",
  title: "Java ECDH key agreement",
  description: 'JCA KeyAgreement.getInstance("ECDH")',
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman (Java/JCA) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_JAVA_DSA = {
  id: "java-dsa",
  title: "Java DSA key/signature",
  description: "JCA DSA KeyPairGenerator / Signature",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Java/JCA) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var RULE_JAVA_DH = {
  id: "java-dh",
  title: "Java Diffie-Hellman key exchange",
  description: "JCA DiffieHellman KeyPairGenerator / KeyAgreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman (Java/JCA) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_JAVA_XDH = {
  id: "java-xdh",
  title: "Java X25519/X448 key agreement",
  description: "JCA XDH / X25519 / X448 (KeyPairGenerator / KeyAgreement)",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X25519/X448 (Java/JCA) is modern but still classical key agreement \u2014 harvest-now-decrypt-later."
};
var RULE_JAVA_EDDSA = {
  id: "java-eddsa",
  title: "Java Ed25519/Ed448 signature",
  description: "JCA EdDSA / Ed25519 / Ed448",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519/Ed448 (Java/JCA) is a modern but still classical signature scheme."
};
function classifyGetInstance(factory, rawAlg) {
  const alg = rawAlg.split("/")[0].trim().toUpperCase();
  const isSignature = factory === "Signature";
  if (alg.includes("ECDSA"))
    return RULE_JAVA_ECDSA_SIGN;
  if (alg.includes("ECDH"))
    return RULE_JAVA_ECDH;
  if (alg === "EC")
    return isSignature ? RULE_JAVA_ECDSA_SIGN : RULE_JAVA_EC_KEYGEN;
  if (alg.includes("ED25519") || alg.includes("ED448") || alg.includes("EDDSA"))
    return RULE_JAVA_EDDSA;
  if (alg.includes("X25519") || alg.includes("X448") || alg === "XDH")
    return RULE_JAVA_XDH;
  if (alg.includes("RSA"))
    return isSignature ? RULE_JAVA_RSA_SIGN : RULE_JAVA_RSA;
  if (alg.includes("DSA"))
    return RULE_JAVA_DSA;
  if (alg.includes("DH") || alg.includes("DIFFIEHELLMAN"))
    return RULE_JAVA_DH;
  return null;
}
var BC_CLASS_RULES = {
  RSAKeyPairGenerator: RULE_JAVA_RSA,
  DSAKeyPairGenerator: RULE_JAVA_DSA,
  ECKeyPairGenerator: RULE_JAVA_EC_KEYGEN,
  ECDSASigner: RULE_JAVA_ECDSA_SIGN,
  Ed25519Signer: RULE_JAVA_EDDSA,
  Ed448Signer: RULE_JAVA_EDDSA,
  X25519Agreement: RULE_JAVA_XDH,
  X448Agreement: RULE_JAVA_XDH
};
var javaDetector = {
  id: "java-crypto",
  description: "Classical asymmetric crypto in Java/Kotlin (JCA getInstance + BouncyCastle)",
  scope: "source",
  language: "java",
  rules: [
    RULE_JAVA_RSA,
    RULE_JAVA_RSA_SIGN,
    RULE_JAVA_EC_KEYGEN,
    RULE_JAVA_ECDSA_SIGN,
    RULE_JAVA_ECDH,
    RULE_JAVA_DSA,
    RULE_JAVA_DH,
    RULE_JAVA_XDH,
    RULE_JAVA_EDDSA
  ],
  appliesTo: (f) => hasExtension(f, JAVA_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    eachMatch(RE_JAVA_GETINSTANCE, content, (m) => {
      const rule = classifyGetInstance(m[1], m[2]);
      if (!rule)
        return;
      findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }));
    });
    eachMatch(RE_JAVA_BC, content, (m) => {
      const rule = BC_CLASS_RULES[m[1]];
      if (!rule)
        return;
      findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }));
    });
    return findings;
  }
};

// ../core/dist/detectors/csharp.js
var RE_CS_RSA = /\bRSA\.Create\s*\(|\bnew\s+RSACryptoServiceProvider\s*\(|\bnew\s+RSACng\s*\(|\bnew\s+RSAOpenSsl\s*\(/g;
var RE_CS_ECDSA = /\bECDsa\.Create\s*\(|\bnew\s+ECDsaCng\s*\(|\bnew\s+ECDsaOpenSsl\s*\(/g;
var RE_CS_ECDH = /\bECDiffieHellman\.Create\s*\(|\bnew\s+ECDiffieHellmanCng\s*\(|\bnew\s+ECDiffieHellmanOpenSsl\s*\(/g;
var RE_CS_DSA = /\bDSA\.Create\s*\(|\bnew\s+DSACryptoServiceProvider\s*\(|\bnew\s+DSACng\s*\(/g;
var RULE_CS_RSA = {
  id: "csharp-rsa",
  title: "C# RSA key/usage",
  description: "System.Security.Cryptography RSA.Create / RSACryptoServiceProvider / RSACng",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (.NET) is not quantum-safe and RSA encryption is HNDL-exposed."
};
var RULE_CS_ECDSA = {
  id: "csharp-ecdsa",
  title: "C# ECDSA signature",
  description: "System.Security.Cryptography ECDsa.Create / ECDsaCng",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (.NET) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_CS_ECDH = {
  id: "csharp-ecdh",
  title: "C# ECDH key agreement",
  description: "System.Security.Cryptography ECDiffieHellman.Create / ECDiffieHellmanCng",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman (.NET) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_CS_DSA = {
  id: "csharp-dsa",
  title: "C# DSA key/signature",
  description: "System.Security.Cryptography DSA.Create / DSACryptoServiceProvider",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (.NET) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var csharpDetector = {
  id: "csharp-crypto",
  description: "Classical asymmetric crypto in C#/.NET (System.Security.Cryptography)",
  scope: "source",
  language: "csharp",
  rules: [RULE_CS_RSA, RULE_CS_ECDSA, RULE_CS_ECDH, RULE_CS_DSA],
  appliesTo: (f) => hasExtension(f, CSHARP_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_CS_ECDSA, RULE_CS_ECDSA);
    add(RE_CS_ECDH, RULE_CS_ECDH);
    add(RE_CS_RSA, RULE_CS_RSA);
    add(RE_CS_DSA, RULE_CS_DSA);
    return findings;
  }
};

// ../core/dist/detectors/rust.js
var RE_RUST_RSA = /\b(?:RsaPrivateKey|RsaPublicKey|RsaKeyPair)::/g;
var RE_RUST_ECDSA = /\becdsa::SigningKey\b|\bEcdsaKeyPair::/g;
var RE_RUST_ECDH = /\becdh::EphemeralSecret\b|\bagreement::ECDH_P(?:256|384)\b/g;
var RE_RUST_ED25519 = /\bed25519_dalek::(?:SigningKey|Keypair|SecretKey)\b|\bEd25519KeyPair::/g;
var RE_RUST_X25519 = /\bx25519_dalek::(?:EphemeralSecret|StaticSecret)\b/g;
var RULE_RUST_RSA = {
  id: "rust-rsa",
  title: "Rust RSA key/usage",
  description: "the `rsa` crate / ring RsaKeyPair",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Rust) is not quantum-safe and RSA encryption is HNDL-exposed."
};
var RULE_RUST_ECDSA = {
  id: "rust-ecdsa",
  title: "Rust ECDSA signature",
  description: "p256/p384/k256 ecdsa::SigningKey / ring EcdsaKeyPair",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (Rust) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_RUST_ECDH = {
  id: "rust-ecdh",
  title: "Rust ECDH key agreement",
  description: "p256/p384 ecdh::EphemeralSecret / ring agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman (Rust) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_RUST_ED25519 = {
  id: "rust-ed25519",
  title: "Rust Ed25519 signature",
  description: "ed25519-dalek SigningKey/Keypair / ring Ed25519KeyPair",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Ed25519 (Rust) is a modern but still classical signature scheme."
};
var RULE_RUST_X25519 = {
  id: "rust-x25519",
  title: "Rust X25519 key agreement",
  description: "x25519-dalek EphemeralSecret/StaticSecret",
  category: "key-exchange",
  severity: "low",
  confidence: "high",
  algorithm: "X25519",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "X25519 (Rust) is modern but still classical key agreement \u2014 harvest-now-decrypt-later."
};
var rustDetector = {
  id: "rust-crypto",
  description: "Classical asymmetric crypto in Rust (rsa, ring, *-dalek, p256/k256)",
  scope: "source",
  language: "rust",
  rules: [RULE_RUST_RSA, RULE_RUST_ECDSA, RULE_RUST_ECDH, RULE_RUST_ED25519, RULE_RUST_X25519],
  appliesTo: (f) => hasExtension(f, RUST_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_RUST_RSA, RULE_RUST_RSA);
    add(RE_RUST_ECDSA, RULE_RUST_ECDSA);
    add(RE_RUST_ECDH, RULE_RUST_ECDH);
    add(RE_RUST_ED25519, RULE_RUST_ED25519);
    add(RE_RUST_X25519, RULE_RUST_X25519);
    return findings;
  }
};

// ../core/dist/detectors/ruby.js
var RE_RB_RSA = /\bOpenSSL::PKey::RSA\.(?:new|generate)\s*\(/g;
var RE_RB_EC = /\bOpenSSL::PKey::EC\.(?:new|generate)\s*\(/g;
var RE_RB_DSA = /\bOpenSSL::PKey::DSA\.(?:new|generate)\s*\(/g;
var RE_RB_DH = /\bOpenSSL::PKey::DH\.new\s*\(/g;
var RULE_RB_RSA = {
  id: "ruby-rsa",
  title: "Ruby RSA key/usage",
  description: "OpenSSL::PKey::RSA.new / .generate",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical RSA (Ruby/OpenSSL) is not quantum-safe and RSA encryption is HNDL-exposed."
};
var RULE_RB_EC = {
  id: "ruby-ec",
  title: "Ruby EC key generation",
  description: "OpenSSL::PKey::EC.new / .generate",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical EC key pair (Ruby/OpenSSL). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
};
var RULE_RB_DSA = {
  id: "ruby-dsa",
  title: "Ruby DSA key/signature",
  description: "OpenSSL::PKey::DSA.new / .generate",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (Ruby/OpenSSL) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var RULE_RB_DH = {
  id: "ruby-dh",
  title: "Ruby Diffie-Hellman key exchange",
  description: "OpenSSL::PKey::DH.new",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman (Ruby/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var rubyDetector = {
  id: "ruby-crypto",
  description: "Classical asymmetric crypto in Ruby (OpenSSL::PKey::{RSA,EC,DSA,DH})",
  scope: "source",
  language: "ruby",
  rules: [RULE_RB_RSA, RULE_RB_EC, RULE_RB_DSA, RULE_RB_DH],
  appliesTo: (f) => hasExtension(f, RUBY_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_RB_RSA, RULE_RB_RSA);
    add(RE_RB_EC, RULE_RB_EC);
    add(RE_RB_DSA, RULE_RB_DSA);
    add(RE_RB_DH, RULE_RB_DH);
    return findings;
  }
};

// ../core/dist/detectors/c.js
var RE_C_RSA = /\bRSA_generate_key(?:_ex)?\s*\(|\bEVP_RSA_gen\s*\(/g;
var RE_C_EC = /\bEC_KEY_generate_key\s*\(|\bEC_KEY_new_by_curve_name\s*\(/g;
var RE_C_ECDSA = /\bECDSA_do_sign\s*\(|\bECDSA_sign\s*\(/g;
var RE_C_ECDH = /\bECDH_compute_key\s*\(/g;
var RE_C_DSA = /\bDSA_generate_key\s*\(|\bDSA_generate_parameters(?:_ex)?\s*\(/g;
var RE_C_DH = /\bDH_generate_key\s*\(|\bDH_generate_parameters(?:_ex)?\s*\(/g;
var RULE_C_RSA = {
  id: "c-rsa-keygen",
  title: "C/OpenSSL RSA key generation",
  description: "OpenSSL RSA_generate_key(_ex) / EVP_RSA_gen",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical RSA key pair (C/OpenSSL), which is not quantum-safe."
};
var RULE_C_EC = {
  id: "c-ec-keygen",
  title: "C/OpenSSL EC key generation",
  description: "OpenSSL EC_KEY_generate_key / EC_KEY_new_by_curve_name",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical EC key pair (C/OpenSSL). EC keys feed BOTH ECDSA signatures and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
  remediation: "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204)."
};
var RULE_C_ECDSA = {
  id: "c-ecdsa",
  title: "C/OpenSSL ECDSA signature",
  description: "OpenSSL ECDSA_sign / ECDSA_do_sign",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical ECDSA signing (C/OpenSSL) is forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)"
};
var RULE_C_ECDH = {
  id: "c-ecdh",
  title: "C/OpenSSL ECDH key agreement",
  description: "OpenSSL ECDH_compute_key",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Elliptic-curve Diffie-Hellman (C/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var RULE_C_DSA = {
  id: "c-dsa",
  title: "C/OpenSSL DSA key/usage",
  description: "OpenSSL DSA_generate_key / DSA_generate_parameters",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "DSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Classical DSA (C/OpenSSL) is deprecated and forgeable by a quantum attacker.",
  remediation: "Rotate off DSA and migrate to ML-DSA-65 (FIPS 204)."
};
var RULE_C_DH = {
  id: "c-dh",
  title: "C/OpenSSL Diffie-Hellman key exchange",
  description: "OpenSSL DH_generate_key / DH_generate_parameters",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman (C/OpenSSL) is broken by Shor's algorithm (harvest-now-decrypt-later)."
};
var cDetector = {
  id: "c-crypto",
  description: "Classical asymmetric crypto in C/C++ (OpenSSL)",
  scope: "source",
  language: "c",
  rules: [RULE_C_RSA, RULE_C_EC, RULE_C_ECDSA, RULE_C_ECDH, RULE_C_DSA, RULE_C_DH],
  appliesTo: (f) => hasExtension(f, C_EXTENSIONS),
  detect({ file, content }) {
    const findings = [];
    const add = (re, rule) => eachMatch(re, content, (m) => findings.push(findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length })));
    add(RE_C_RSA, RULE_C_RSA);
    add(RE_C_EC, RULE_C_EC);
    add(RE_C_ECDSA, RULE_C_ECDSA);
    add(RE_C_ECDH, RULE_C_ECDH);
    add(RE_C_DSA, RULE_C_DSA);
    add(RE_C_DH, RULE_C_DH);
    return findings;
  }
};

// ../core/dist/detectors/pem.js
var PEM_RULES = [
  {
    re: /-----BEGIN RSA PRIVATE KEY-----/g,
    meta: {
      id: "pem-rsa-private-key",
      title: "RSA private key (PEM)",
      description: "PKCS#1 RSA private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "RSA",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded RSA private key (PKCS#1 PEM); classical and not quantum-safe.",
      remediation: "Migrate to ML-DSA / ML-KEM keys and remove embedded private keys from source."
    }
  },
  {
    re: /-----BEGIN EC PRIVATE KEY-----/g,
    meta: {
      id: "pem-ec-private-key",
      title: "EC private key (PEM)",
      description: "SEC1 EC private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "ECDSA",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded EC private key (SEC1 PEM); classical ECDSA/ECDH key, not quantum-safe.",
      remediation: "Migrate to ML-DSA (FIPS 204) keys and remove embedded private keys from source."
    }
  },
  {
    re: /-----BEGIN DSA PRIVATE KEY-----/g,
    meta: {
      id: "pem-dsa-private-key",
      title: "DSA private key (PEM)",
      description: "DSA private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "DSA",
      hndl: false,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded DSA private key (PEM); classical, already deprecated, and not quantum-safe.",
      remediation: "Rotate immediately (DSA is deprecated) and migrate to ML-DSA-65 (FIPS 204)."
    }
  },
  {
    re: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    meta: {
      id: "pem-openssh-private-key",
      title: "OpenSSH private key",
      description: "OpenSSH private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded OpenSSH private key (RSA/ECDSA/Ed25519); classical and not quantum-safe.",
      remediation: "Rotate the key; plan migration to PQC-capable SSH (e.g. sntrup761x25519)."
    }
  },
  {
    re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    meta: {
      id: "pem-pgp-private-key",
      title: "PGP/GPG private key block",
      description: "OpenPGP private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded PGP/GPG private key block (RSA/ECDSA/EdDSA/ElGamal); classical and not quantum-safe.",
      remediation: "Rotate the key; track OpenPGP PQC drafts for migration."
    }
  },
  {
    re: /-----BEGIN PGP MESSAGE-----/g,
    meta: {
      id: "pem-pgp-message",
      title: "PGP/GPG encrypted message",
      description: "OpenPGP encrypted message block",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message: "Embedded PGP/GPG message; likely encrypted with classical RSA/ElGamal (harvest-now-decrypt-later).",
      remediation: "Re-encrypt with PQC-capable tooling as OpenPGP PQC profiles mature."
    }
  },
  {
    re: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/g,
    meta: {
      id: "pem-pkcs8-private-key",
      title: "Private key (PKCS#8 PEM)",
      description: "PKCS#8 private key block",
      category: "certificate",
      severity: "critical",
      confidence: "high",
      algorithm: "unknown",
      hndl: true,
      cwe: CWE_HARDCODED_KEY,
      sensitive: true,
      message: "Embedded PKCS#8 private key; likely classical RSA/EC, not quantum-safe.",
      remediation: "Migrate to PQC keys and remove embedded private keys from source."
    }
  },
  {
    re: /-----BEGIN CERTIFICATE-----/g,
    meta: {
      id: "pem-certificate",
      title: "X.509 certificate (PEM)",
      description: "X.509 certificate block",
      category: "certificate",
      severity: "low",
      confidence: "high",
      algorithm: "unknown",
      hndl: false,
      cwe: CWE_BROKEN_CRYPTO,
      message: "Embedded X.509 certificate; almost certainly signed with classical RSA/ECDSA.",
      remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature."
    }
  }
];
var pemDetector = {
  id: "pem-material",
  description: "PEM-encoded private keys and X.509 certificates in any file",
  scope: "config",
  language: "any",
  rules: PEM_RULES.map((r) => r.meta),
  // Applies to every text file; the walker already filters out binaries.
  appliesTo: () => true,
  detect({ file, content }) {
    if (!content.includes("-----BEGIN "))
      return [];
    const findings = [];
    for (const rule of PEM_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(findingFromRule(rule.meta, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length
        }));
      });
    }
    return findings;
  }
};

// ../core/dist/registry.js
function detectorScope(d) {
  return d.scope ?? "source";
}
var DetectorRegistry = class _DetectorRegistry {
  byId = /* @__PURE__ */ new Map();
  order = [];
  /** Construct a registry, optionally seeded with an initial detector set. */
  constructor(initial = []) {
    for (const d of initial)
      this.register(d);
  }
  /** Register a detector. Throws on a duplicate id. Returns `this` for chaining. */
  register(d) {
    if (this.byId.has(d.id)) {
      throw new Error(`duplicate detector id: ${d.id}`);
    }
    this.byId.set(d.id, d);
    this.order.push(d.id);
    return this;
  }
  /** Look up a detector by its id (exact, not prefix). */
  get(id) {
    return this.byId.get(id);
  }
  /** True if a detector with this id is registered. */
  has(id) {
    return this.byId.has(id);
  }
  /** All registered detectors, in registration order. */
  all() {
    return this.order.map((id) => this.byId.get(id));
  }
  /**
   * The flattened rule catalog: every {@link RuleMeta} declared by every
   * registered detector, in detector-registration then in-detector order. This
   * is the single source of truth for rule metadata consumed by SARIF
   * `rules[]`, the MCP `explain_finding` resolver, and per-rule enable/disable.
   * Duplicate rule ids across detectors throw (ids are globally unique).
   */
  ruleCatalog() {
    const out = [];
    const seen = /* @__PURE__ */ new Set();
    for (const det of this.all()) {
      for (const rule of det.rules ?? []) {
        if (seen.has(rule.id)) {
          throw new Error(`duplicate rule id in catalog: ${rule.id}`);
        }
        seen.add(rule.id);
        out.push(rule);
      }
    }
    return out;
  }
  /** Resolve a rule id to its {@link RuleMeta} and the detector that emits it. */
  forRule(ruleId) {
    for (const det of this.all()) {
      for (const rule of det.rules ?? []) {
        if (rule.id === ruleId)
          return { rule, detector: det };
      }
    }
    return void 0;
  }
  /** A shallow copy of this registry (useful to extend the defaults). */
  clone() {
    return new _DetectorRegistry(this.all());
  }
};
var defaultRegistry = new DetectorRegistry([
  ...sourceDetectors,
  pythonDetector,
  goDetector,
  javaDetector,
  csharpDetector,
  rustDetector,
  rubyDetector,
  cDetector,
  pemDetector
]);

// ../core/dist/inventory.js
var SEVERITIES = ["critical", "high", "medium", "low", "info"];
var SEVERITY_WEIGHT = {
  critical: 30,
  high: 18,
  medium: 8,
  low: 3,
  info: 1
};
function penaltyFor(weight, occurrence) {
  return weight / Math.sqrt(occurrence);
}
var SCORE_SCALE = 100;
function readinessScore(findings) {
  if (findings.length === 0)
    return 100;
  const seen = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  let penalty = 0;
  for (const f of findings) {
    seen[f.severity] += 1;
    penalty += penaltyFor(SEVERITY_WEIGHT[f.severity], seen[f.severity]);
  }
  return Math.max(0, Math.min(100, Math.round(100 * Math.exp(-penalty / SCORE_SCALE))));
}
function buildInventory(findings) {
  const byAlgorithm = {};
  const byCategory = {};
  const bySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  let hndlCount = 0;
  for (const f of findings) {
    if (f.algorithm) {
      byAlgorithm[f.algorithm] = (byAlgorithm[f.algorithm] ?? 0) + 1;
    }
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    bySeverity[f.severity] += 1;
    if (f.hndl)
      hndlCount += 1;
  }
  void SEVERITIES;
  return {
    byAlgorithm,
    byCategory,
    bySeverity,
    hndlCount,
    readinessScore: readinessScore(findings)
  };
}

// ../core/dist/errors.js
var AbortError = class extends Error {
  name = "AbortError";
  constructor(message = "The scan was aborted.") {
    super(message);
  }
};
var BudgetExceededError = class extends Error {
  name = "BudgetExceededError";
  constructor(message) {
    super(message);
  }
};

// ../core/dist/scan.js
var detectors = [
  ...sourceDetectors,
  pythonDetector,
  goDetector,
  javaDetector,
  csharpDetector,
  rustDetector,
  rubyDetector,
  cDetector,
  pemDetector
];
function compareFindings(a, b) {
  if (a.location.file !== b.location.file)
    return a.location.file < b.location.file ? -1 : 1;
  if (a.location.line !== b.location.line)
    return a.location.line - b.location.line;
  return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
}
function resolveDetectors(options) {
  return options.detectors ?? defaultRegistry.all();
}
function detectFile(file, content, dets, toggles, disabledRules) {
  const out = [];
  for (const det of dets) {
    if (!det.appliesTo(file))
      continue;
    const isConfig = detectorScope(det) === "config";
    if (isConfig ? !toggles.config : !toggles.source)
      continue;
    out.push(...det.detect({ file, content }));
  }
  if (toggles.deps && isManifestFile(file)) {
    out.push(...scanManifest(file, content));
  }
  if (disabledRules && disabledRules.length > 0) {
    const disabled = new Set(disabledRules);
    return out.filter((f) => !disabled.has(f.ruleId));
  }
  return out;
}
async function scan(options) {
  const startedAt = /* @__PURE__ */ new Date();
  const doSource = options.source !== false;
  const doDeps = options.dependencies !== false;
  const doConfig = options.config !== false;
  const scanMinified = options.scanMinified === true;
  const dets = resolveDetectors(options);
  const rootStat = await stat2(options.root);
  const rootIsFile = rootStat.isFile();
  const baseDir = rootIsFile ? path2.dirname(options.root) : options.root;
  const singleFileName = rootIsFile ? path2.basename(options.root) : null;
  const findings = [];
  let filesScanned = 0;
  let analyzedFiles = 0;
  let bytesScanned = 0;
  const signal = options.signal;
  const maxFiles = options.maxFiles;
  const maxBytes = options.maxBytes;
  const relPaths = options.files ? filterExplicitFiles(options.files, options) : walkFiles(options.root, {
    include: options.include,
    exclude: options.exclude,
    noDefaultIgnores: options.noDefaultIgnores,
    maxFileSize: options.maxFileSize
  });
  for await (const rel of relPaths) {
    if (signal?.aborted)
      throw new AbortError();
    if (typeof maxFiles === "number" && filesScanned >= maxFiles) {
      throw new BudgetExceededError(`maxFiles budget exceeded (limit: ${maxFiles}).`);
    }
    const absPath = singleFileName ? options.root : path2.join(baseDir, ...rel.split("/"));
    const reportedPath = singleFileName ? toPosix(rel) : rel;
    options.onFile?.(reportedPath);
    let content;
    try {
      content = await readFile(absPath, "utf8");
    } catch {
      continue;
    }
    if (!scanMinified && !isManifestFile(reportedPath) && looksMinified(content)) {
      continue;
    }
    bytesScanned += Buffer.byteLength(content, "utf8");
    if (typeof maxBytes === "number" && bytesScanned > maxBytes) {
      throw new BudgetExceededError(`maxBytes budget exceeded (limit: ${maxBytes}).`);
    }
    filesScanned += 1;
    if (isAnalyzableSource(reportedPath))
      analyzedFiles += 1;
    findings.push(...detectFile(reportedPath, content, dets, {
      source: doSource,
      config: doConfig,
      deps: doDeps
    }, options.disabledRules));
  }
  findings.sort(compareFindings);
  const inventory = buildInventory(findings);
  const finishedAt = /* @__PURE__ */ new Date();
  return {
    root: options.root,
    findings,
    filesScanned,
    analyzedFiles,
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION
  };
}
function filterExplicitFileList(files, options) {
  const include = options.include ?? [];
  const exclude = options.exclude ?? [];
  const seen = /* @__PURE__ */ new Set();
  const list = [...files].map((f) => toPosix(f)).filter((f) => {
    if (seen.has(f))
      return false;
    seen.add(f);
    return true;
  }).sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  return list.filter((rel) => {
    if (isBinaryPath(rel))
      return false;
    if (include.length > 0 && !matchesAny2(rel, include))
      return false;
    if (matchesAny2(rel, exclude))
      return false;
    return true;
  });
}
async function* filterExplicitFiles(files, options) {
  for (const rel of filterExplicitFileList(files, options))
    yield rel;
}
function matchesAny2(rel, patterns) {
  for (const pattern of patterns) {
    if (!pattern)
      continue;
    const p = toPosix(pattern).replace(/\/+$/, "");
    if (rel.includes(p))
      return true;
    if (rel === p || rel.startsWith(`${p}/`))
      return true;
  }
  return false;
}

// ../core/dist/parallel.js
import { stat as stat3 } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path3 from "node:path";
import { fileURLToPath } from "node:url";
var DEFAULT_PARALLEL_THRESHOLD_BYTES = 2 * 1024 * 1024;
var DEFAULT_PARALLEL_FILE_THRESHOLD = 200;
var DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024;
function chunkByBytes(files, chunkBytes) {
  const limit = Math.max(1, chunkBytes);
  const chunks = [];
  let current = [];
  let currentBytes = 0;
  for (const f of files) {
    if (current.length > 0 && currentBytes + f.size > limit) {
      chunks.push({ files: current });
      current = [];
      currentBytes = 0;
    }
    current.push(f.rel);
    currentBytes += f.size;
  }
  if (current.length > 0)
    chunks.push({ files: current });
  return chunks;
}
function mergeChunkResults(results) {
  const findings = [];
  let filesScanned = 0;
  for (const r of results) {
    for (const f of r.findings)
      findings.push(f);
    filesScanned += r.filesScanned;
  }
  findings.sort(compareFindings);
  return { findings, filesScanned };
}
function resolveConcurrency(options) {
  const raw = options.concurrency;
  if (typeof raw === "number" && raw >= 1)
    return Math.floor(raw);
  const avail = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, avail);
}
function shouldParallelize(options, files) {
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
  const byteFloor = options.parallelThresholdBytes ?? DEFAULT_PARALLEL_THRESHOLD_BYTES;
  const fileFloor = options.parallelFileThreshold ?? DEFAULT_PARALLEL_FILE_THRESHOLD;
  if (resolveConcurrency(options) <= 1)
    return false;
  return totalBytes >= byteFloor && files.length >= fileFloor;
}
async function enumerateFiles(options, baseDir) {
  const rels = [];
  if (options.files) {
    for (const rel of filterExplicitFileList(options.files, options))
      rels.push(rel);
  } else {
    for await (const rel of walkFiles(options.root, {
      include: options.include,
      exclude: options.exclude,
      noDefaultIgnores: options.noDefaultIgnores,
      maxFileSize: options.maxFileSize
    })) {
      rels.push(rel);
    }
  }
  const sized = [];
  for (const rel of rels) {
    let size = 0;
    try {
      size = (await stat3(path3.join(baseDir, ...rel.split("/")))).size;
    } catch {
    }
    sized.push({ rel, size });
  }
  return sized;
}
function workerEntry() {
  const here = fileURLToPath(import.meta.url);
  const dir = path3.dirname(here);
  const js = path3.join(dir, "scan-worker.js");
  if (existsSync(js))
    return { entry: js };
  const ts = path3.join(dir, "scan-worker.ts");
  if (existsSync(ts))
    return { entry: ts, execArgv: ["--import", "tsx"] };
  return { entry: js };
}
async function scanParallel(options) {
  const startedAt = /* @__PURE__ */ new Date();
  const rootStat = await stat3(options.root);
  const baseDir = rootStat.isFile() ? path3.dirname(options.root) : options.root;
  if (rootStat.isFile() || options.detectors) {
    return scan(options);
  }
  const files = await enumerateFiles(options, baseDir);
  if (!shouldParallelize(options, files)) {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  let WorkerCtor;
  try {
    ({ Worker: WorkerCtor } = await import("node:worker_threads"));
  } catch {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  const chunks = chunkByBytes(files, options.chunkBytes ?? DEFAULT_CHUNK_BYTES);
  const concurrency = Math.min(resolveConcurrency(options), chunks.length);
  const { entry, execArgv } = workerEntry();
  const toggles = {
    source: options.source !== false,
    config: options.config !== false,
    deps: options.dependencies !== false,
    scanMinified: options.scanMinified === true,
    // Plain string array — structured-cloneable, so it crosses the worker boundary.
    disabledRules: options.disabledRules
  };
  let results;
  try {
    results = await runPool(WorkerCtor, entry, execArgv, baseDir, toggles, chunks, concurrency, options.onFile);
  } catch {
    return scan({ ...options, files: files.map((f) => f.rel) });
  }
  const merged = mergeChunkResults(results);
  const inventory = buildInventory(merged.findings);
  const finishedAt = /* @__PURE__ */ new Date();
  const analyzedFiles = files.reduce((n, f) => isAnalyzableSource(f.rel) ? n + 1 : n, 0);
  return {
    root: options.root,
    findings: merged.findings,
    filesScanned: merged.filesScanned,
    analyzedFiles,
    inventory,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    toolVersion: VERSION
  };
}
function runPool(WorkerCtor, entry, execArgv, baseDir, toggles, chunks, concurrency, onFile) {
  return new Promise((resolve2, reject) => {
    const results = new Array(chunks.length);
    let next = 0;
    let done = 0;
    let failed = false;
    const workers = [];
    const cleanup = () => {
      for (const w of workers)
        void w.terminate();
    };
    const dispatch = (w) => {
      if (failed)
        return;
      if (next >= chunks.length) {
        void w.terminate();
        return;
      }
      const idx = next++;
      w.postMessage({ index: idx, files: chunks[idx].files });
    };
    const spawn = () => {
      const w = new WorkerCtor(entry, {
        workerData: { baseDir, toggles },
        ...execArgv ? { execArgv } : {}
      });
      w.on("message", (msg) => {
        if (msg.error) {
          if (!failed) {
            failed = true;
            cleanup();
            reject(new Error(msg.error));
          }
          return;
        }
        if (msg.files && onFile)
          for (const f of msg.files)
            onFile(f);
        if (msg.result) {
          results[msg.index] = msg.result;
          done++;
          if (done === chunks.length) {
            cleanup();
            resolve2(results);
            return;
          }
          dispatch(w);
        }
      });
      w.on("error", (err) => {
        if (!failed) {
          failed = true;
          cleanup();
          reject(err);
        }
      });
      return w;
    };
    const n = Math.max(1, Math.min(concurrency, chunks.length));
    for (let i = 0; i < n; i++) {
      const w = spawn();
      workers.push(w);
      dispatch(w);
    }
  });
}

// ../core/dist/baseline.js
import { createHash } from "node:crypto";
import { readFile as readFile2, writeFile } from "node:fs/promises";
var BASELINE_VERSION = 1;
function normalizeSnippet(snippet) {
  if (!snippet)
    return "";
  return snippet.replace(/\s+/g, " ").trim();
}
function fingerprintFinding(f) {
  const snippet = normalizeSnippet(f.location.snippet);
  const input = `${f.ruleId}|${f.location.file}|${snippet}`;
  return createHash("sha256").update(input, "utf8").digest("hex");
}
function baselineFromFindings(findings) {
  const set = /* @__PURE__ */ new Set();
  for (const f of findings)
    set.add(fingerprintFinding(f));
  return {
    version: BASELINE_VERSION,
    fingerprints: [...set].sort()
  };
}
function applyBaseline(findings, baseline) {
  const accepted = new Set(baseline.fingerprints);
  const newFindings = [];
  const suppressed = [];
  for (const f of findings) {
    if (accepted.has(fingerprintFinding(f)))
      suppressed.push(f);
    else
      newFindings.push(f);
  }
  return { newFindings, suppressed };
}
function coerceBaseline(value) {
  if (value === null || typeof value !== "object") {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  const obj = value;
  const version = typeof obj.version === "number" ? obj.version : BASELINE_VERSION;
  const fingerprints = Array.isArray(obj.fingerprints) ? obj.fingerprints.filter((x) => typeof x === "string") : [];
  return { version, fingerprints };
}
async function loadBaseline(path4) {
  let text;
  try {
    text = await readFile2(path4, "utf8");
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
  try {
    return coerceBaseline(JSON.parse(text));
  } catch {
    return { version: BASELINE_VERSION, fingerprints: [] };
  }
}
async function saveBaseline(path4, findings) {
  const baseline = baselineFromFindings(findings);
  await writeFile(path4, `${JSON.stringify(baseline, null, 2)}
`, "utf8");
  return baseline;
}

// ../core/dist/changed.js
import { execFile } from "node:child_process";
import { promisify } from "node:util";
var execFileAsync = promisify(execFile);
async function git(cwd, args) {
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true
    });
    return stdout;
  } catch {
    return null;
  }
}
function toLines(stdout) {
  if (!stdout)
    return [];
  return stdout.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
}
async function changedFiles(root, since) {
  const inside = await git(root, ["rev-parse", "--is-inside-work-tree"]);
  if (inside === null || inside.trim() !== "true")
    return [];
  const out = /* @__PURE__ */ new Set();
  if (since) {
    for (const f of toLines(await git(root, ["diff", "--name-only", "--relative", "--diff-filter=ACMR", since]))) {
      out.add(f);
    }
  }
  for (const f of toLines(await git(root, ["diff", "--name-only", "--relative", "--diff-filter=ACMR"]))) {
    out.add(f);
  }
  for (const f of toLines(await git(root, ["diff", "--name-only", "--relative", "--diff-filter=ACMR", "--cached"]))) {
    out.add(f);
  }
  for (const f of toLines(await git(root, ["ls-files", "--others", "--exclude-standard", "--", "."]))) {
    out.add(f);
  }
  return [...out].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}

// ../core/dist/severity.js
var SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function severityRank(s) {
  const i = SEVERITY_ORDER.indexOf(s);
  return i < 0 ? SEVERITY_ORDER.length : i;
}
function meetsThreshold(severity, threshold) {
  return severityRank(severity) <= severityRank(threshold);
}
function sarifLevel(severity) {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

// ../core/dist/report.js
var SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
var INFORMATION_URI = "https://github.com/quantakrypto/pqc-tools";
function emittedSnippet(f, redactSnippets) {
  if (redactSnippets || f.sensitive)
    return void 0;
  return f.location.snippet;
}
function sarifRank(severity) {
  switch (severity) {
    case "critical":
      return 100;
    case "high":
      return 80;
    case "medium":
      return 50;
    case "low":
      return 20;
    default:
      return 5;
  }
}
function sarifRule(spec) {
  return {
    id: spec.id,
    name: spec.id,
    shortDescription: { text: spec.title },
    fullDescription: { text: spec.message },
    defaultConfiguration: { level: sarifLevel(spec.severity), rank: sarifRank(spec.severity) },
    ...spec.remediation ? { help: { text: `Remediation: ${spec.remediation}` } } : {},
    properties: {
      category: spec.category,
      ...spec.algorithm ? { algorithm: spec.algorithm } : {},
      hndl: spec.hndl,
      ...spec.cwe ? { cwe: spec.cwe, "security-severity": securitySeverity(spec.severity) } : {},
      ...spec.cwe ? { tags: ["security", spec.cwe] } : {}
    },
    ...spec.cwe ? {
      relationships: [
        { target: { id: spec.cwe, toolComponent: { name: "CWE" } }, kinds: ["relevant"] }
      ]
    } : {}
  };
}
function toSarif(result, opts) {
  const redactSnippets = opts?.redactSnippets ?? false;
  const ruleIndex = /* @__PURE__ */ new Map();
  const rules = [];
  const cweTaxa = /* @__PURE__ */ new Set();
  for (const r of opts?.catalog ?? []) {
    if (ruleIndex.has(r.id))
      continue;
    if (r.cwe)
      cweTaxa.add(r.cwe);
    ruleIndex.set(r.id, rules.length);
    rules.push(sarifRule({
      id: r.id,
      title: r.title,
      message: r.message,
      severity: r.severity,
      category: r.category,
      algorithm: r.algorithm,
      hndl: r.hndl,
      cwe: r.cwe,
      remediation: r.remediation
    }));
  }
  for (const f of result.findings) {
    if (f.cwe)
      cweTaxa.add(f.cwe);
    if (ruleIndex.has(f.ruleId))
      continue;
    ruleIndex.set(f.ruleId, rules.length);
    rules.push(sarifRule({
      id: f.ruleId,
      title: f.title,
      message: f.message,
      severity: f.severity,
      category: f.category,
      algorithm: f.algorithm,
      hndl: f.hndl,
      cwe: f.cwe,
      remediation: f.remediation
    }));
  }
  const results = result.findings.map((f) => {
    const region = { startLine: f.location.line };
    if (typeof f.location.column === "number")
      region.startColumn = f.location.column;
    if (typeof f.location.endLine === "number")
      region.endLine = f.location.endLine;
    const snippet = emittedSnippet(f, redactSnippets);
    return {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId),
      level: sarifLevel(f.severity),
      message: { text: f.message },
      properties: {
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        hndl: f.hndl,
        ...f.algorithm ? { algorithm: f.algorithm } : {},
        ...f.remediation ? { remediation: f.remediation } : {},
        ...f.cwe ? { cwe: f.cwe } : {}
      },
      ...f.cwe ? {
        taxa: [
          {
            target: { id: f.cwe, toolComponent: { name: "CWE" } }
          }
        ]
      } : {},
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.location.file },
            region: {
              ...region,
              ...snippet ? { snippet: { text: snippet } } : {}
            }
          }
        }
      ]
    };
  });
  const taxonomies = cweTaxa.size > 0 ? [
    {
      name: "CWE",
      informationUri: "https://cwe.mitre.org/",
      organization: "MITRE",
      shortDescription: { text: "The MITRE Common Weakness Enumeration" },
      taxa: [...cweTaxa].sort().map((id) => ({
        id,
        helpUri: `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/, "")}.html`
      }))
    }
  ] : [];
  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "qScan",
            informationUri: INFORMATION_URI,
            version: result.toolVersion || VERSION,
            rules
          }
        },
        ...taxonomies.length > 0 ? { taxonomies } : {},
        results
      }
    ]
  };
}
function securitySeverity(severity) {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}
function toJson(result, opts) {
  const redactSnippets = opts?.redactSnippets ?? false;
  return {
    toolVersion: result.toolVersion,
    root: result.root,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    filesScanned: result.filesScanned,
    ...result.analyzedFiles !== void 0 ? { analyzedFiles: result.analyzedFiles } : {},
    inventory: {
      readinessScore: result.inventory.readinessScore,
      hndlCount: result.inventory.hndlCount,
      bySeverity: result.inventory.bySeverity,
      byCategory: result.inventory.byCategory,
      byAlgorithm: result.inventory.byAlgorithm
    },
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      algorithm: f.algorithm,
      hndl: f.hndl,
      message: f.message,
      remediation: f.remediation,
      cwe: f.cwe,
      location: {
        file: f.location.file,
        line: f.location.line,
        column: f.location.column,
        endLine: f.location.endLine,
        snippet: emittedSnippet(f, redactSnippets)
      }
    }))
  };
}

// ../core/dist/cbom.js
import { createHash as createHash2 } from "node:crypto";
function primitiveFor(category) {
  switch (category) {
    case "kem":
      return "kem";
    case "key-exchange":
      return "key-agree";
    case "signature":
      return "signature";
    case "certificate":
      return "pki";
    case "tls":
      return "other";
    default:
      return "other";
  }
}
function isQuantumVulnerable(algorithm) {
  return algorithm !== "unknown";
}
function bomRef(key) {
  return `crypto:${createHash2("sha256").update(key, "utf8").digest("hex").slice(0, 16)}`;
}
function toCbom(result) {
  const groups = /* @__PURE__ */ new Map();
  for (const f of result.findings) {
    const algorithm = f.algorithm ?? "unknown";
    const primitive = primitiveFor(f.category);
    const key = `${algorithm}|${primitive}`;
    let g = groups.get(key);
    if (!g) {
      g = { algorithm, primitive, findings: [] };
      groups.set(key, g);
    }
    g.findings.push(f);
  }
  const components = [...groups.entries()].sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0).map(([key, g]) => {
    const occurrences = g.findings.map((f) => ({
      location: `${f.location.file}:${f.location.line}`,
      ...f.cwe ? { additionalContext: f.cwe } : {}
    })).sort((a, b) => a.location < b.location ? -1 : a.location > b.location ? 1 : 0);
    const anyHndl = g.findings.some((f) => f.hndl);
    return {
      type: "cryptographic-asset",
      "bom-ref": bomRef(key),
      name: `${g.algorithm} (${g.primitive})`,
      cryptoProperties: {
        assetType: "algorithm",
        algorithmProperties: {
          primitive: g.primitive,
          parameterSetIdentifier: g.algorithm,
          executionEnvironment: "software-plain-ram",
          classicalSecurityLevel: 0,
          nistQuantumSecurityLevel: 0,
          cryptoFunctions: g.primitive === "signature" ? ["sign", "verify"] : g.primitive === "kem" ? ["encapsulate", "decapsulate"] : g.primitive === "key-agree" ? ["keyagree"] : ["other"]
        },
        quantumVulnerable: isQuantumVulnerable(g.algorithm),
        harvestNowDecryptLater: anyHndl
      },
      evidence: { occurrences }
    };
  });
  const serial = `urn:uuid:${stableUuid(result)}`;
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: serial,
    version: 1,
    metadata: {
      timestamp: result.finishedAt,
      tools: {
        components: [
          {
            type: "application",
            name: "qScan",
            version: result.toolVersion || VERSION
          }
        ]
      },
      component: {
        type: "application",
        "bom-ref": "root",
        name: result.root
      }
    },
    components
  };
}
function stableUuid(result) {
  const h = createHash2("sha256").update(`${result.root}|${result.toolVersion}|${result.findings.length}`, "utf8").digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

// ../qscan/dist/baseline.js
function applyBaseline2(findings, baseline) {
  const resolved = baseline instanceof Set ? { version: BASELINE_VERSION, fingerprints: [...baseline] } : baseline;
  const { newFindings, suppressed } = applyBaseline(findings, resolved);
  return { kept: newFindings, suppressed };
}
async function readBaseline(path4) {
  const { readFile: readFile4 } = await import("node:fs/promises");
  let raw;
  try {
    raw = await readFile4(path4, "utf8");
  } catch (cause) {
    throw new Error(`could not read baseline file "${path4}": ${errMessage(cause)}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error(`baseline file "${path4}" is not valid JSON: ${errMessage(cause)}`);
  }
  if (!isBaselineFile(parsed)) {
    throw new Error(`baseline file "${path4}" is missing a string "fingerprints" array`);
  }
  return new Set(parsed.fingerprints);
}
function isBaselineFile(value) {
  if (typeof value !== "object" || value === null)
    return false;
  const obj = value;
  return Array.isArray(obj.fingerprints) && obj.fingerprints.every((f) => typeof f === "string");
}
function errMessage(cause) {
  return cause instanceof Error ? cause.message : String(cause);
}

// ../qscan/dist/args.js
function defaultOptions() {
  return {
    path: ".",
    format: "human",
    severityThreshold: "high",
    source: true,
    dependencies: true,
    config: true,
    ignore: [],
    include: [],
    noDefaultIgnores: false,
    scanMinified: false,
    changed: false,
    parallel: false,
    quiet: false,
    noSnippets: false,
    noConfigFile: false
  };
}

// ../qscan/dist/report.js
var PLAIN = { reset: "", bold: "", dim: "", red: "", yellow: "", green: "", cyan: "" };
var COLOR = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  dim: "\x1B[2m",
  red: "\x1B[31m",
  yellow: "\x1B[33m",
  green: "\x1B[32m",
  cyan: "\x1B[36m"
};
function renderJson(result, opts) {
  return JSON.stringify(toJson(result, opts), null, 2);
}
function renderSarif(result, opts) {
  return JSON.stringify(toSarif(result, { catalog: defaultRegistry.ruleCatalog(), ...opts }), null, 2);
}
function renderCbom(result) {
  return JSON.stringify(toCbom(result), null, 2);
}
function renderHuman(result, opts = {}) {
  const c = opts.color ? COLOR : PLAIN;
  const topN = opts.topN ?? 5;
  const { findings, inventory, filesScanned } = result;
  const analyzedFiles = result.analyzedFiles;
  const noAnalyzable = analyzedFiles === 0;
  const lines = [];
  lines.push(`${c.bold}qScan \u2014 quantum-vulnerable cryptography report${c.reset}`);
  const coverage = analyzedFiles === void 0 ? "" : `  \u2022  analyzed: ${analyzedFiles} (${ANALYZABLE_LANGUAGES_LABEL})`;
  lines.push(`${c.dim}root: ${result.root}  \u2022  files scanned: ${filesScanned}${coverage}  \u2022  qscan v${result.toolVersion}${c.reset}`);
  lines.push("");
  if (findings.length === 0) {
    if (noAnalyzable && filesScanned > 0) {
      lines.push(`${c.yellow}No analyzable source found.${c.reset} Scanned ${filesScanned} file${filesScanned === 1 ? "" : "s"}, but none were in a supported language (${ANALYZABLE_LANGUAGES_LABEL}).`);
      lines.push(`${c.dim}The score below covers only what qScan can read today \u2014 it is NOT a clean bill of health for this codebase.${c.reset}`);
      lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100 (no analyzable source)${c.reset}`);
      lines.push("");
      lines.push(`${c.dim}Next step:${c.reset} multi-language support is expanding; track coverage before relying on the score.`);
      return lines.join("\n");
    }
    lines.push(`${c.green}No quantum-vulnerable cryptography detected.${c.reset}`);
    lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
    lines.push("");
    lines.push(`${c.dim}Next step:${c.reset} keep scanning in CI to catch regressions.`);
    return lines.join("\n");
  }
  const counts = SEVERITY_ORDER.map((sev) => {
    const n = inventory.bySeverity[sev] ?? 0;
    return n > 0 ? `${severityColor(sev, c)}${n} ${sev}${c.reset}` : null;
  }).filter((s) => s !== null);
  lines.push(`${c.bold}${findings.length} finding${findings.length === 1 ? "" : "s"}${c.reset}  (${counts.join(", ")})`);
  if (inventory.hndlCount > 0) {
    lines.push(`${c.yellow}${inventory.hndlCount}${c.reset} exposed to harvest-now-decrypt-later (HNDL).`);
  }
  lines.push(`${c.bold}Readiness score: ${readiness(inventory.readinessScore, c)}/100${c.reset}`);
  lines.push("");
  const top = [...findings].sort(compareFindings2).slice(0, topN);
  lines.push(`${c.bold}Top findings${c.reset}`);
  for (const f of top) {
    const loc = `${f.location.file}:${f.location.line}`;
    lines.push(`  ${severityColor(f.severity, c)}${f.severity.padEnd(8)}${c.reset} ${c.cyan}${f.ruleId}${c.reset}  ${loc}`);
    lines.push(`           ${f.message}`);
    if (f.remediation) {
      lines.push(`           ${c.dim}\u2192 ${f.remediation}${c.reset}`);
    }
  }
  if (findings.length > top.length) {
    lines.push(`  ${c.dim}\u2026and ${findings.length - top.length} more${c.reset}`);
  }
  lines.push("");
  lines.push(`${c.dim}Next step:${c.reset} ${nextStep(findings)}`);
  return lines.join("\n");
}
function nextStep(findings) {
  const worst = [...findings].sort(compareFindings2)[0];
  if (!worst)
    return "review the findings above.";
  if (worst.remediation) {
    return `migrate ${worst.location.file} \u2014 ${worst.remediation}`;
  }
  return `triage ${worst.ruleId} in ${worst.location.file}:${worst.location.line}.`;
}
function compareFindings2(a, b) {
  const bySev = severityRank(a.severity) - severityRank(b.severity);
  if (bySev !== 0)
    return bySev;
  const byFile = a.location.file.localeCompare(b.location.file);
  if (byFile !== 0)
    return byFile;
  return a.location.line - b.location.line;
}
function readiness(score, c) {
  const color = score >= 80 ? c.green : score >= 50 ? c.yellow : c.red;
  return `${color}${score}${c.reset}`;
}
function severityColor(severity, c) {
  switch (severity) {
    case "critical":
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    default:
      return c.dim;
  }
}

// ../qscan/dist/index.js
var EXIT = {
  /** No findings at/above threshold, or a baseline was written. */
  OK: 0,
  /** One or more findings at/above the severity threshold. */
  FINDINGS: 1,
  /** Usage error or I/O failure. */
  ERROR: 2
};
function toScanOptions(options) {
  const scanOptions = {
    root: options.path,
    source: options.source,
    dependencies: options.dependencies,
    config: options.config,
    noDefaultIgnores: options.noDefaultIgnores,
    scanMinified: options.scanMinified
  };
  if (options.ignore.length > 0)
    scanOptions.exclude = options.ignore;
  if (options.include.length > 0)
    scanOptions.include = options.include;
  if (options.maxFileSize !== void 0)
    scanOptions.maxFileSize = options.maxFileSize;
  if (options.concurrency !== void 0)
    scanOptions.concurrency = options.concurrency;
  return scanOptions;
}
async function runQscan(opts, hooks = {}) {
  const options = { ...defaultOptions(), ...opts };
  const scanFn = hooks.scanFn ?? (options.parallel ? scanParallel : scan);
  const resolveChanged = hooks.changedFilesFn ?? changedFiles;
  const scanOptions = toScanOptions(options);
  if (options.changed) {
    scanOptions.files = await resolveChanged(options.path, options.since);
  }
  const result = await scanFn(scanOptions);
  if (options.writeBaseline) {
    const baseline = await saveBaseline(options.writeBaseline, result.findings);
    return {
      result,
      suppressed: [],
      baselineWritten: baseline,
      exitCode: EXIT.OK
    };
  }
  let suppressed = [];
  if (options.baseline) {
    const fingerprints = await readBaseline(options.baseline);
    const split = applyBaseline2(result.findings, fingerprints);
    result.findings = split.kept;
    suppressed = split.suppressed;
  }
  const exitCode = result.findings.some((f) => meetsThreshold(f.severity, options.severityThreshold)) ? EXIT.FINDINGS : EXIT.OK;
  return {
    result,
    suppressed,
    report: renderReport(result, options.format, {
      color: hooks.color ?? false,
      redactSnippets: options.noSnippets
    }),
    exitCode
  };
}
function renderReport(result, format, opts = {}) {
  const { color = false, redactSnippets = false } = typeof opts === "boolean" ? { color: opts } : opts;
  switch (format) {
    case "json":
      return renderJson(result, { redactSnippets });
    case "sarif":
      return renderSarif(result, { redactSnippets });
    case "cbom":
      return renderCbom(result);
    case "human":
    default:
      return renderHuman(result, { color });
  }
}

// src/io.ts
import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { EOL } from "node:os";
function inputEnvName(name) {
  return `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
}
function getInput(name, env = process.env) {
  const raw = env[inputEnvName(name)];
  return raw === void 0 ? "" : raw.trim();
}
function getBooleanInput(name, defaultValue = false, env = process.env) {
  const value = getInput(name, env);
  if (value === "") return defaultValue;
  if (["true", "True", "TRUE"].includes(value)) return true;
  if (["false", "False", "FALSE"].includes(value)) return false;
  throw new TypeError(
    `Input "${name}" does not meet YAML 1.2 "Core Schema" specification: got "${value}"`
  );
}
function escapeData(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function escapeProperty(value) {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}
function formatCommand(command, message, properties = {}) {
  const entries = [
    ["title", properties.title],
    ["file", properties.file],
    ["line", properties.line],
    ["col", properties.col],
    ["endLine", properties.endLine],
    ["endColumn", properties.endColumn]
  ];
  const props = entries.filter(([, v]) => v !== void 0 && v !== "").map(([k, v]) => `${k}=${escapeProperty(String(v))}`).join(",");
  const head = props ? `::${command} ${props}::` : `::${command}::`;
  return `${head}${escapeData(message)}`;
}
function issueCommand(command, message, properties) {
  process.stdout.write(formatCommand(command, message, properties) + EOL);
}
function info(message) {
  process.stdout.write(message + EOL);
}
function warning(message, properties) {
  issueCommand("warning", message, properties);
}
function error(message, properties) {
  issueCommand("error", message, properties);
}
function notice(message, properties) {
  issueCommand("notice", message, properties);
}
function setOutput(name, value, env = process.env) {
  const filePath = env["GITHUB_OUTPUT"];
  if (filePath) {
    const delimiter = `ghadelimiter_${randomUUID()}`;
    if (name.includes(delimiter)) {
      throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
    }
    if (/[\r\n]/.test(name)) {
      throw new Error("Unexpected input: name should not contain a CR or LF character");
    }
    if (value.includes(delimiter)) {
      throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
    }
    appendFileSync(filePath, `${name}<<${delimiter}${EOL}${value}${EOL}${delimiter}${EOL}`, {
      encoding: "utf8"
    });
    return;
  }
  process.stdout.write(formatCommand("set-output", value, { title: name }) + EOL);
}
function setFailed(message) {
  error(message);
  process.exitCode = 1;
}

// src/escape.ts
function mdCell(value) {
  const clipped = value.length > 512 ? `${value.slice(0, 512)}\u2026` : value;
  return clipped.replace(/\\/g, "\\\\").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\|/g, "\\|").replace(/`/g, "\\`").replace(/[\r\n]+/g, " ");
}

// src/main.ts
var DEFAULT_OUTPUT = "quantakrypto.sarif.json";
function readInputs(env = process.env) {
  const severityThreshold = getInput("severity-threshold", env) || "high";
  if (!SEVERITY_ORDER.includes(severityThreshold)) {
    throw new TypeError(
      `Invalid severity-threshold "${severityThreshold}"; expected one of ${SEVERITY_ORDER.join(", ")}`
    );
  }
  const format = getInput("format", env) || "sarif";
  if (format !== "sarif" && format !== "json") {
    throw new TypeError(`Invalid format "${format}"; expected "sarif" or "json"`);
  }
  const baseline = getInput("baseline", env);
  const githubToken = getInput("github-token", env);
  return {
    path: getInput("path", env) || ".",
    severityThreshold,
    failOnFindings: getBooleanInput("fail-on-findings", true, env),
    format,
    output: getInput("output", env) || DEFAULT_OUTPUT,
    baseline: baseline || void 0,
    commentPr: getBooleanInput("comment-pr", false, env),
    githubToken: githubToken || void 0,
    redactSnippets: getBooleanInput("redact-snippets", false, env)
  };
}
function renderReportWithOptions(result, format, opts) {
  const doc = format === "sarif" ? toSarif(result, { catalog: defaultRegistry.ruleCatalog(), ...opts }) : toJson(result, opts);
  return JSON.stringify(doc, null, 2);
}
function shouldFail(blockingCount, failOnFindings) {
  return failOnFindings && blockingCount > 0;
}
function annotationLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  return "notice";
}
function annotateFindings(findings, threshold) {
  for (const f of findings) {
    const level = meetsThreshold(f.severity, threshold) ? "error" : annotationLevel(f.severity);
    const message = f.remediation ? `${f.message} \u2192 ${f.remediation}` : f.message;
    const props = {
      title: `quantakrypto: ${f.title}`,
      file: f.location.file,
      line: f.location.line,
      col: f.location.column,
      endLine: f.location.endLine
    };
    if (level === "error") error(message, props);
    else if (level === "notice") notice(message, props);
    else warning(message, props);
  }
}
function buildSummary(result, newFindings, threshold) {
  const score = result.inventory.readinessScore;
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, threshold));
  const lines = [];
  lines.push("## quantakrypto \u2014 Quantum Readiness Scan");
  lines.push("");
  lines.push(`**Readiness score:** ${score}/100`);
  lines.push(
    `**New findings:** ${newFindings.length} (${blocking.length} at or above \`${threshold}\`)`
  );
  lines.push("");
  if (blocking.length === 0) {
    lines.push("No new quantum-vulnerable cryptography at or above the threshold. \u2705");
    return lines.join("\n");
  }
  lines.push("| Severity | Rule | File | Message |");
  lines.push("| --- | --- | --- | --- |");
  for (const f of blocking.slice(0, 50)) {
    const loc = mdCell(`${f.location.file}:${f.location.line}`);
    const rule = mdCell(f.ruleId);
    const msg = mdCell(f.message);
    lines.push(`| ${f.severity} | \`${rule}\` | ${loc} | ${msg} |`);
  }
  if (blocking.length > 50) lines.push(`| \u2026 | | | _${blocking.length - 50} more_ |`);
  lines.push("");
  lines.push("<sub>Reported by [quantakrypto](https://quantakrypto.com/tools).</sub>");
  return lines.join("\n");
}
async function readPullRequestContext(env = process.env) {
  try {
    const repository = env["GITHUB_REPOSITORY"];
    const eventPath = env["GITHUB_EVENT_PATH"];
    if (!repository || !eventPath) return void 0;
    const [owner, repo] = repository.split("/");
    if (!owner || !repo) return void 0;
    const payload = JSON.parse(await readFile3(eventPath, "utf8"));
    const prNumber = payload.pull_request?.number ?? payload.number;
    if (typeof prNumber !== "number") return void 0;
    const apiUrl = env["GITHUB_API_URL"] || "https://api.github.com";
    return { owner, repo, prNumber, apiUrl };
  } catch {
    return void 0;
  }
}
var COMMENT_MARKER = "<!-- quantakrypto-action -->";
async function findExistingComment(ctx, headers) {
  const url = `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments?per_page=100`;
  const res = await fetch(url, { headers });
  if (!res.ok) return null;
  const comments = await res.json();
  const mine = comments.find((c) => typeof c.body === "string" && c.body.includes(COMMENT_MARKER));
  return mine ? mine.id : null;
}
async function commentOnPullRequest(ctx, token, body) {
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
    "User-Agent": "quantakrypto-action"
  };
  const markedBody = `${COMMENT_MARKER}
${body}`;
  try {
    const existingId = await findExistingComment(ctx, headers);
    const url = existingId ? `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/comments/${existingId}` : `${ctx.apiUrl}/repos/${ctx.owner}/${ctx.repo}/issues/${ctx.prNumber}/comments`;
    const res = await fetch(url, {
      method: existingId ? "PATCH" : "POST",
      headers,
      body: JSON.stringify({ body: markedBody })
    });
    if (!res.ok) {
      warning(`Could not comment on PR #${ctx.prNumber}: ${res.status} ${res.statusText}`);
      return false;
    }
    return true;
  } catch (err) {
    warning(`Could not comment on PR: ${err.message}`);
    return false;
  }
}
function resolveInWorkspace(p, env) {
  const workspace = resolve(env["GITHUB_WORKSPACE"] || process.cwd());
  const resolved = isAbsolute(p) ? resolve(p) : resolve(workspace, p);
  if (resolved !== workspace && !resolved.startsWith(workspace + sep2)) {
    throw new Error(`path "${p}" escapes the workspace (${workspace})`);
  }
  return resolved;
}
async function loadBaselineSet(baselinePath, env) {
  const abs = resolveInWorkspace(baselinePath, env);
  return loadBaseline(abs);
}
async function run(env = process.env) {
  const inputs = readInputs(env);
  const scanRoot = resolveInWorkspace(inputs.path, env);
  info(`quantakrypto: scanning ${scanRoot} (threshold: ${inputs.severityThreshold})`);
  const { result } = await runQscan({
    path: scanRoot,
    format: inputs.format,
    severityThreshold: inputs.severityThreshold
  });
  const baseline = inputs.baseline ? await loadBaselineSet(inputs.baseline, env) : { version: 1, fingerprints: [] };
  const { newFindings } = applyBaseline(result.findings, baseline);
  const outputPath = resolveInWorkspace(inputs.output, env);
  await mkdir(dirname3(outputPath), { recursive: true });
  await writeFile2(
    outputPath,
    renderReportWithOptions(result, inputs.format, { redactSnippets: inputs.redactSnippets }),
    "utf8"
  );
  info(`quantakrypto: wrote ${inputs.format} report to ${inputs.output}`);
  annotateFindings(newFindings, inputs.severityThreshold);
  const blocking = newFindings.filter((f) => meetsThreshold(f.severity, inputs.severityThreshold));
  setOutput("findings-count", String(blocking.length), env);
  setOutput("readiness-score", String(result.inventory.readinessScore), env);
  setOutput("sarif-file", inputs.output, env);
  if (inputs.commentPr && inputs.githubToken) {
    const ctx = await readPullRequestContext(env);
    if (ctx) {
      const body = buildSummary(result, newFindings, inputs.severityThreshold);
      await commentOnPullRequest(ctx, inputs.githubToken, body);
    } else {
      info("quantakrypto: comment-pr enabled but no pull-request context found; skipping comment.");
    }
  }
  info(
    `quantakrypto: ${newFindings.length} new finding(s), ${blocking.length} at/above "${inputs.severityThreshold}"; readiness ${result.inventory.readinessScore}/100.`
  );
  if (shouldFail(blocking.length, inputs.failOnFindings)) {
    setFailed(
      `quantakrypto: ${blocking.length} quantum-vulnerable finding(s) at or above "${inputs.severityThreshold}".`
    );
    process.exit(1);
  }
}
var invokedDirectly = process.argv[1] !== void 0 && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invokedDirectly) {
  run().catch((err) => {
    setFailed(`quantakrypto: ${err.message}`);
    process.exit(1);
  });
}
export {
  annotateFindings,
  buildSummary,
  commentOnPullRequest,
  fingerprintFinding as fingerprint,
  meetsThreshold,
  readInputs,
  readPullRequestContext,
  run,
  shouldFail
};
