/**
 * Curated database of packages that primarily expose classical asymmetric
 * cryptography (and are therefore quantum-vulnerable), across multiple
 * ecosystems (npm, PyPI, crates.io, Go modules, Maven, RubyGems), plus a
 * manifest scanner that flags any of them found in the corresponding manifest
 * (package.json, requirements.txt, Cargo.toml, go.mod, pom.xml, Gemfile, …).
 *
 * The list is intentionally focused on libraries whose *purpose* is classical
 * public-key crypto. General-purpose packages that merely call the language's
 * stdlib crypto are out of scope here (those are caught by the source detectors).
 * Extraction is generous but every finding must match a curated entry, so a new
 * manifest format is cheap to add (see `manifestEcosystem` + `candidateNames`).
 */
import type {
  AlgorithmFamily,
  DependencyEcosystem,
  Finding,
  VulnerableDependency,
} from "./types.js";
import { makeFinding } from "./detect-utils.js";
import { remediationText } from "./remediation.js";
import { CWE_BROKEN_CRYPTO } from "./cwe.js";

/** Known quantum-vulnerable npm dependencies. */
export const vulnerableDependencies: VulnerableDependency[] = [
  {
    name: "node-forge",
    ecosystem: "npm",
    reason: "Pure-JS implementation of RSA, RSA-OAEP, and X.509 PKI.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "elliptic",
    ecosystem: "npm",
    reason: "Elliptic-curve ECDSA/ECDH (secp256k1, p256, ed25519).",
    algorithms: ["ECDSA", "ECDH", "EdDSA"],
    severity: "high",
  },
  {
    name: "jsrsasign",
    ecosystem: "npm",
    reason: "RSA/ECDSA/DSA signing, JWT, and X.509 in pure JS.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high",
  },
  {
    name: "node-rsa",
    ecosystem: "npm",
    reason: "Classical RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "ursa",
    ecosystem: "npm",
    reason: "OpenSSL-backed RSA encryption and signing bindings.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "sshpk",
    ecosystem: "npm",
    reason: "Parses/handles SSH and PEM keys (RSA, ECDSA, Ed25519, DSA).",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium",
  },
  {
    name: "jsonwebtoken",
    ecosystem: "npm",
    reason: "JWTs commonly signed with RS256/ES256 (classical RSA/ECDSA).",
    algorithms: ["RSA", "ECDSA"],
    severity: "high",
  },
  {
    name: "jose",
    ecosystem: "npm",
    reason: "JWS/JWE with classical RSA-OAEP, RSA-PSS, ECDH-ES and ECDSA.",
    algorithms: ["RSA", "ECDH", "ECDSA", "EdDSA"],
    severity: "high",
  },
  {
    name: "jws",
    ecosystem: "npm",
    reason: "JSON Web Signatures using classical RS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "high",
  },
  {
    name: "eccrypto",
    ecosystem: "npm",
    reason: "ECIES (ECDH-based) encryption and ECDSA signatures.",
    algorithms: ["ECIES", "ECDH", "ECDSA"],
    severity: "high",
  },
  {
    name: "secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH bindings (blockchain keys).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "tweetnacl",
    ecosystem: "npm",
    reason: "X25519 key exchange and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low",
  },
  {
    name: "ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures (classical).",
    algorithms: ["EdDSA"],
    severity: "low",
  },
  {
    name: "@noble/curves",
    ecosystem: "npm",
    reason: "Audited classical curves: ECDSA, ECDH, Ed25519, X25519, secp256k1.",
    algorithms: ["ECDSA", "ECDH", "EdDSA", "X25519"],
    severity: "medium",
  },
  {
    name: "@noble/secp256k1",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA/ECDH (classical).",
    algorithms: ["ECDSA", "ECDH"],
    severity: "medium",
  },
  {
    name: "@noble/ed25519",
    ecosystem: "npm",
    reason: "Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "low",
  },
  {
    name: "paseto",
    ecosystem: "npm",
    reason: "PASETO public tokens signed with classical Ed25519 (v2/v4) or RSA.",
    algorithms: ["EdDSA", "RSA"],
    severity: "medium",
  },
  {
    name: "bcrypto",
    ecosystem: "npm",
    reason: "Broad classical crypto suite: RSA, ECDSA, ECDH, Ed25519, DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA", "DSA"],
    severity: "high",
  },
  {
    name: "ecpair",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA key pairs for Bitcoin.",
    algorithms: ["ECDSA"],
    severity: "medium",
  },
  {
    name: "keypair",
    ecosystem: "npm",
    reason: "Pure-JS RSA key pair generation.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "ethers",
    ecosystem: "npm",
    reason: "Ethereum library built on secp256k1 ECDSA signing and key derivation.",
    algorithms: ["ECDSA"],
    severity: "high",
  },
  {
    name: "web3",
    ecosystem: "npm",
    reason: "Ethereum library using secp256k1 ECDSA for accounts and signing.",
    algorithms: ["ECDSA"],
    severity: "high",
  },
  {
    name: "bitcoinjs-lib",
    ecosystem: "npm",
    reason: "Bitcoin library built on secp256k1 ECDSA/Schnorr keys and signatures.",
    algorithms: ["ECDSA"],
    severity: "high",
  },
  {
    name: "ethereumjs-util",
    ecosystem: "npm",
    reason: "secp256k1 ECDSA utilities for Ethereum keys and signatures.",
    algorithms: ["ECDSA"],
    severity: "medium",
  },
  {
    name: "openpgp",
    ecosystem: "npm",
    reason: "OpenPGP.js: RSA, ECDSA, ECDH, and EdDSA public-key crypto.",
    algorithms: ["RSA", "ECDSA", "ECDH", "EdDSA"],
    severity: "high",
  },
  {
    name: "node-jose",
    ecosystem: "npm",
    reason: "JOSE (JWS/JWE/JWK) with classical RSA and EC algorithms.",
    algorithms: ["RSA", "ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "jwa",
    ecosystem: "npm",
    reason: "JSON Web Algorithms: RSA (RS/PS) and EC (ES) signatures.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "jwk-to-pem",
    ecosystem: "npm",
    reason: "Converts RSA/EC JWKs to PEM — classical public keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "fast-jwt",
    ecosystem: "npm",
    reason: "JWT signing/verification with classical RS/PS/ES algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "ssh2",
    ecosystem: "npm",
    reason: "SSH client/server using classical RSA/ECDSA/Ed25519 host and user keys.",
    algorithms: ["RSA", "ECDSA", "EdDSA"],
    severity: "high",
  },
  {
    name: "@peculiar/x509",
    ecosystem: "npm",
    reason: "X.509 certificate library over classical RSA/EC keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "pkijs",
    ecosystem: "npm",
    reason: "PKI (X.509/CMS) built on classical RSA and EC public-key crypto.",
    algorithms: ["RSA", "ECDSA", "ECDH"],
    severity: "medium",
  },
  {
    name: "http-signature",
    ecosystem: "npm",
    reason: "HTTP request signing with classical RSA/ECDSA keys.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "libsodium-wrappers",
    ecosystem: "npm",
    reason: "libsodium: Ed25519 signatures and X25519 key exchange (classical).",
    algorithms: ["EdDSA", "X25519"],
    severity: "medium",
  },
  {
    name: "ecdsa-sig-formatter",
    ecosystem: "npm",
    reason: "Formats ECDSA signatures — a marker of classical EC signing.",
    algorithms: ["ECDSA"],
    severity: "low",
  },

  // --- PyPI (Python) ---
  {
    name: "pycryptodome",
    ecosystem: "pypi",
    reason: "RSA / ECC / DSA public-key crypto for Python.",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high",
  },
  {
    name: "pycryptodomex",
    ecosystem: "pypi",
    reason: "RSA / ECC / DSA public-key crypto (the `Cryptodome` namespace).",
    algorithms: ["RSA", "ECDSA", "DSA"],
    severity: "high",
  },
  {
    name: "rsa",
    ecosystem: "pypi",
    reason: "Pure-Python RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "ecdsa",
    ecosystem: "pypi",
    reason: "Pure-Python ECDSA/ECDH over NIST + secp256k1 curves.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "cryptography",
    ecosystem: "pypi",
    reason: "General crypto library exposing classical RSA/EC/DH/DSA (also symmetric/PQC).",
    algorithms: ["RSA", "ECDH", "ECDSA", "DSA"],
    severity: "medium",
  },
  {
    name: "pyjwt",
    ecosystem: "pypi",
    reason: "JWT signing with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "python-jose",
    ecosystem: "pypi",
    reason: "JOSE/JWT with classical RSA/ECDSA algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "paramiko",
    ecosystem: "pypi",
    reason: "SSH client/server with classical RSA/ECDSA/Ed25519/DSA host + user keys.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "DSA"],
    severity: "medium",
  },
  {
    name: "pyopenssl",
    ecosystem: "pypi",
    reason: "OpenSSL bindings for classical RSA/EC X.509 + TLS.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "pynacl",
    ecosystem: "pypi",
    reason:
      "libsodium bindings — X25519 key agreement and Ed25519 signatures (modern but classical).",
    algorithms: ["X25519", "EdDSA"],
    severity: "low",
  },

  // --- crates.io (Rust) ---
  {
    name: "rsa",
    ecosystem: "cargo",
    reason: "Pure-Rust RSA encryption and signing.",
    algorithms: ["RSA"],
    severity: "high",
  },
  {
    name: "ring",
    ecosystem: "cargo",
    reason: "RSA / ECDSA / Ed25519 / ECDH primitives.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "ECDH"],
    severity: "medium",
  },
  {
    name: "openssl",
    ecosystem: "cargo",
    reason: "OpenSSL bindings for classical RSA/EC crypto.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "p256",
    ecosystem: "cargo",
    reason: "NIST P-256 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "p384",
    ecosystem: "cargo",
    reason: "NIST P-384 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "k256",
    ecosystem: "cargo",
    reason: "secp256k1 ECDSA signatures and ECDH key agreement.",
    algorithms: ["ECDSA", "ECDH"],
    severity: "high",
  },
  {
    name: "ed25519-dalek",
    ecosystem: "cargo",
    reason: "Ed25519 signatures (modern but classical).",
    algorithms: ["EdDSA"],
    severity: "low",
  },
  {
    name: "x25519-dalek",
    ecosystem: "cargo",
    reason: "X25519 key agreement (modern but classical).",
    algorithms: ["X25519"],
    severity: "low",
  },

  // --- Go modules ---
  {
    name: "golang.org/x/crypto",
    ecosystem: "go",
    reason: "SSH, OpenPGP, and classical curve helpers on top of the Go stdlib.",
    algorithms: ["RSA", "ECDSA", "EdDSA", "ECDH"],
    severity: "medium",
  },

  // --- Maven (Java) ---
  {
    name: "bcprov-jdk18on",
    ecosystem: "maven",
    reason: "BouncyCastle provider — full classical RSA/ECDSA/ECDH/DSA suite.",
    algorithms: ["RSA", "ECDSA", "ECDH", "DSA"],
    severity: "high",
  },
  {
    name: "bcprov-jdk15on",
    ecosystem: "maven",
    reason: "BouncyCastle provider (JDK 1.5+) — classical RSA/ECDSA/ECDH/DSA.",
    algorithms: ["RSA", "ECDSA", "ECDH", "DSA"],
    severity: "high",
  },
  {
    name: "bcpkix-jdk18on",
    ecosystem: "maven",
    reason: "BouncyCastle PKIX — classical X.509 / CMS with RSA/ECDSA.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "java-jwt",
    ecosystem: "maven",
    reason: "Auth0 JWT with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },

  // --- RubyGems ---
  {
    name: "jwt",
    ecosystem: "rubygems",
    reason: "Ruby JWT with classical RS*/ES* algorithms.",
    algorithms: ["RSA", "ECDSA"],
    severity: "medium",
  },
  {
    name: "rbnacl",
    ecosystem: "rubygems",
    reason: "libsodium bindings — X25519 key agreement and Ed25519 signatures.",
    algorithms: ["X25519", "EdDSA"],
    severity: "low",
  },
  {
    name: "ed25519",
    ecosystem: "rubygems",
    reason: "Ed25519 signatures (modern but classical).",
    algorithms: ["EdDSA"],
    severity: "low",
  },
];

/**
 * Normalise a package name for matching within its ecosystem. PyPI is
 * case-insensitive and folds runs of `-_.` to a single `-` (PEP 503); cargo /
 * maven / rubygems are effectively lower-case; npm and go module paths are
 * matched verbatim (npm scopes and go paths are case-sensitive).
 */
function normalizeName(ecosystem: DependencyEcosystem, name: string): string {
  const n = name.trim();
  if (ecosystem === "pypi") return n.toLowerCase().replace(/[-_.]+/g, "-");
  if (ecosystem === "npm" || ecosystem === "go") return n;
  return n.toLowerCase();
}

/** ecosystem → (normalised name → entry). Scoped so `rsa` (pypi) ≠ `rsa` (cargo). */
const BY_ECOSYSTEM: Map<DependencyEcosystem, Map<string, VulnerableDependency>> = (() => {
  const m = new Map<DependencyEcosystem, Map<string, VulnerableDependency>>();
  for (const d of vulnerableDependencies) {
    let em = m.get(d.ecosystem);
    if (!em) {
      em = new Map();
      m.set(d.ecosystem, em);
    }
    em.set(normalizeName(d.ecosystem, d.name), d);
  }
  return m;
})();

/**
 * Precompiled `"name":` lookup regex per known npm package (P1-9): the set is
 * static, so build the (name → RegExp) map once rather than per manifest. Only
 * npm uses the JSON-key form; other ecosystems locate names generically.
 */
const KEY_REGEX_BY_NAME = new Map<string, RegExp>(
  vulnerableDependencies
    .filter((d) => d.ecosystem === "npm")
    .map((d): [string, RegExp] => {
      const escaped = d.name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
      return [d.name, new RegExp(`"${escaped}"\\s*:`)];
    }),
);

/** Algorithm families that expose confidentiality (HNDL) rather than only signing. */
const CONFIDENTIALITY_FAMILIES: ReadonlySet<AlgorithmFamily> = new Set<AlgorithmFamily>([
  "RSA",
  "ECDH",
  "DH",
  "ECIES",
  "X25519",
  "X448",
]);

/**
 * Build a remediation string covering ALL families a package exposes (C5),
 * rather than only `algorithms[0]`. De-duplicates the per-family recommendation
 * strings and joins them, so a signature+KEM library points at both replacements.
 */
function multiFamilyRemediation(algorithms: readonly AlgorithmFamily[]): string {
  const parts = new Set<string>();
  for (const a of algorithms) parts.add(remediationText(a));
  return [...parts].join("; ");
}

/**
 * The dependency ecosystem a manifest filename belongs to, or null when the file
 * is not a manifest we parse. Drives both {@link isManifestFile} and the scanner
 * dispatch — one place to add a manifest format.
 */
export function manifestEcosystem(file: string): DependencyEcosystem | null {
  const base = (file.split("/").pop() ?? file).toLowerCase();
  if (base === "package.json" || base === "package-lock.json") return "npm";
  if (base === "requirements.txt" || /^requirements[\w.-]*\.txt$/.test(base)) return "pypi";
  if (base === "pyproject.toml" || base === "pipfile") return "pypi";
  if (base === "cargo.toml") return "cargo";
  if (base === "go.mod") return "go";
  if (base === "pom.xml" || base === "build.gradle" || base === "build.gradle.kts") return "maven";
  if (base === "gemfile" || base.endsWith(".gemspec")) return "rubygems";
  return null;
}

/** True if a file path looks like a manifest we can parse for dependencies. */
export function isManifestFile(file: string): boolean {
  return manifestEcosystem(file) !== null;
}

/**
 * Extract candidate package names from a non-npm manifest. Extraction is
 * deliberately GENEROUS — every finding still has to match a curated DB entry,
 * so over-extracting harmless tokens (e.g. a TOML `version = …` key) costs
 * nothing while keeping the parsers tiny and format-tolerant.
 */
function candidateNames(ecosystem: DependencyEcosystem, content: string): string[] {
  const names: string[] = [];
  const lines = content.split("\n");
  switch (ecosystem) {
    case "pypi": {
      // requirements.txt / Pipfile / pyproject.toml: leading token per line, plus
      // quoted deps in arrays/tables. Skip comments and `-r/-e/--flag` lines.
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#") || line.startsWith("-")) continue;
        const lead = /^["']?([A-Za-z][A-Za-z0-9._-]+)/.exec(line);
        if (lead) names.push(lead[1]);
        for (const m of line.matchAll(/["']([A-Za-z][A-Za-z0-9._-]+)/g)) names.push(m[1]);
      }
      break;
    }
    case "cargo": {
      // Cargo.toml: dependency-table keys `name = …` and `[…dependencies.name]`.
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const key = /^([A-Za-z0-9][A-Za-z0-9_-]+)\s*=/.exec(line);
        if (key) names.push(key[1]);
        const table = /^\[[\w.-]*dependencies\.([A-Za-z0-9][A-Za-z0-9_-]+)\]/.exec(line);
        if (table) names.push(table[1]);
      }
      break;
    }
    case "go": {
      // go.mod: `require path v1.2.3` (single or in a require( … ) block).
      for (const m of content.matchAll(/(?:^|\s)([a-z0-9][\w.\-/]+)\s+v\d/gm)) names.push(m[1]);
      break;
    }
    case "maven": {
      // pom.xml <artifactId> tags + gradle `group:artifact:version` strings.
      for (const m of content.matchAll(/<artifactId>\s*([\w.-]+)\s*<\/artifactId>/g)) {
        names.push(m[1]);
      }
      for (const m of content.matchAll(/["']([\w.-]+):([\w.-]+):[\w.$-]+["']/g)) names.push(m[2]);
      break;
    }
    case "rubygems": {
      // Gemfile `gem 'name'` + gemspec `add_*dependency 'name'`.
      for (const m of content.matchAll(/\bgem\s+["']([\w.-]+)["']/g)) names.push(m[1]);
      for (const m of content.matchAll(
        /add(?:_runtime|_development)?_dependency\s+["']([\w.-]+)["']/g,
      )) {
        names.push(m[1]);
      }
      break;
    }
    case "npm":
      break; // npm uses the JSON path, not this extractor.
  }
  return names;
}

/** First offset of a package `name` as a whole token in the manifest text (or 0). */
function offsetOfName(content: string, name: string): number {
  const escaped = name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  const m = new RegExp(`(?<![\\w./-])${escaped}(?![\\w-])`).exec(content);
  return m ? m.index : 0;
}

/**
 * Build a finding for a vulnerable dependency located in a manifest. The
 * location points at the line where the package name appears in the file (best
 * effort), falling back to line 1.
 */
function dependencyFinding(
  dep: VulnerableDependency,
  file: string,
  content: string,
  index: number,
): Finding {
  // Use the first listed algorithm for the headline family, but derive the
  // remediation from ALL families the package exposes (C5).
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
    message: `${dep.name} — ${dep.reason}`,
    remediation: multiFamilyRemediation(dep.algorithms),
    file,
    content,
    index,
  });
}

/** Locate the offset of a JSON key `"name"` in the manifest text (or 0). */
function offsetOfKey(content: string, name: string): number {
  // Use the precompiled per-name regex (non-global; .exec from position 0).
  const re = KEY_REGEX_BY_NAME.get(name);
  if (!re) return 0;
  const m = re.exec(content);
  return m ? m.index : 0;
}

/** Sort findings by title for deterministic output. */
function sortByTitle(findings: Finding[]): Finding[] {
  findings.sort((a, b) => (a.title < b.title ? -1 : a.title > b.title ? 1 : 0));
  return findings;
}

/**
 * Scan a single manifest file for vulnerable dependencies, dispatching by the
 * file's ecosystem ({@link manifestEcosystem}). npm manifests are parsed as
 * JSON; every other ecosystem uses the generous {@link candidateNames} extractor
 * filtered against the ecosystem-scoped database. Returns one finding per
 * distinct vulnerable package.
 */
export function scanManifest(file: string, content: string): Finding[] {
  const ecosystem = manifestEcosystem(file);
  if (!ecosystem) return [];
  const db = BY_ECOSYSTEM.get(ecosystem);
  if (!db) return [];

  if (ecosystem === "npm") return scanNpmManifest(content, file, db);

  const found = new Map<string, VulnerableDependency>(); // dedupe by entry
  for (const raw of candidateNames(ecosystem, content)) {
    const dep = db.get(normalizeName(ecosystem, raw));
    if (dep) found.set(dep.name, dep);
  }
  const findings: Finding[] = [];
  for (const dep of found.values()) {
    findings.push(dependencyFinding(dep, file, content, offsetOfName(content, dep.name)));
  }
  return sortByTitle(findings);
}

/**
 * npm manifest scan.
 * - `package.json`: dependencies / devDependencies / peerDependencies / optionalDependencies.
 * - `package-lock.json` (v2/v3): the `packages` map keys (node_modules/<name>).
 */
function scanNpmManifest(
  content: string,
  file: string,
  db: Map<string, VulnerableDependency>,
): Finding[] {
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch {
    return []; // not valid JSON — skip quietly.
  }
  if (json === null || typeof json !== "object") return [];

  const found = new Set<string>();
  const obj = json as Record<string, unknown>;

  const collectFromRecord = (rec: unknown): void => {
    if (rec === null || typeof rec !== "object") return;
    for (const key of Object.keys(rec as Record<string, unknown>)) {
      if (db.has(key)) found.add(key);
    }
  };

  collectFromRecord(obj.dependencies);
  collectFromRecord(obj.devDependencies);
  collectFromRecord(obj.peerDependencies);
  collectFromRecord(obj.optionalDependencies);

  const packages = obj.packages;
  if (packages !== null && typeof packages === "object") {
    for (const key of Object.keys(packages as Record<string, unknown>)) {
      if (!key) continue; // root package entry
      const marker = "node_modules/";
      const idx = key.lastIndexOf(marker);
      const name = idx >= 0 ? key.slice(idx + marker.length) : key;
      if (db.has(name)) found.add(name);
    }
  }

  const findings: Finding[] = [];
  for (const name of found) {
    const dep = db.get(name);
    if (!dep) continue;
    findings.push(dependencyFinding(dep, file, content, offsetOfKey(content, name)));
  }
  return sortByTitle(findings);
}
