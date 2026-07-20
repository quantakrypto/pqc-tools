/**
 * Source-code detectors for classical, non-quantum-safe asymmetric cryptography
 * in JavaScript / TypeScript. Each detector is pure and stateless: it declares
 * which files it applies to, the catalog of rules it can emit (`rules`), and
 * returns zero or more Findings for a file's contents.
 *
 * Rule metadata (title / severity / category / remediation / …) lives ONCE in
 * the per-detector `RuleMeta` declarations below, not inline in `detect()`.
 * `detect()` builds findings from those declarations via `findingFromRule`,
 * overriding only the fields that genuinely vary per match (e.g. the concrete
 * algorithm family of a `generateKeyPair('ec')` call). The declarations are the
 * catalog surfaced by the registry, SARIF `rules[]`, and the MCP resolver.
 *
 * The detection strategy is deliberately lexical (regex over source text). This
 * is robust to bundling and partial files and keeps the package dependency-free.
 * Confidence is set per-pattern to reflect how specific the match is.
 *
 * All per-file regexes are precompiled at module scope (not re-created per
 * file) — `eachMatch` clones a fresh stateful copy only when a regex lacks the
 * global flag, and these are all global, so they are reused safely.
 *
 * HNDL (harvest-now-decrypt-later) policy:
 *   - confidentiality primitives (key exchange / KEM: ECDH, DH, RSA-OAEP) → hndl:true
 *   - signatures (RSA-PSS, ECDSA, EdDSA, DSA, JWT alg) → hndl:false, but still high
 *     severity because a quantum attacker can forge them.
 *   - EC keygen is ambiguous (an 'ec' key feeds BOTH ECDSA and ECDH); it is
 *     classified conservatively as key-exchange-capable (hndl:true).
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import {
  JS_TS_EXTENSIONS,
  DOC_EXTENSIONS,
  JWT_HOST_EXTENSIONS,
  eachMatch,
  enclosingObject,
  findingFromRule,
  hasExtension,
  nearSortedCall,
} from "../detect-utils.js";
import { CWE_BROKEN_CRYPTO, CWE_CERT_VALIDATION, CWE_WEAK_STRENGTH } from "../cwe.js";

/* -------------------------------------------------------------------------- */
/* Precompiled regexes (module scope — never recreated per file)              */
/* -------------------------------------------------------------------------- */

// `rsa-pss` is listed before `rsa` so the alternation consumes the full token
// (ordered alternation would otherwise match `rsa` and reject the `-pss` tail).
const RE_GENERATE_KEYPAIR =
  /generateKeyPair(?:Sync)?\s*\(\s*['"`](rsa-pss|rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"`]/g;

/** Per-key-type classification for `generateKeyPair(Sync)('<type>', …)`. Hoisted
 * to module scope so the direct matcher AND the import-alias pass (below) share
 * one source of truth for how each key type is classified. */
interface KeygenInfo {
  algo: Finding["algorithm"];
  cat: Finding["category"];
  sev: Finding["severity"];
  hndl: boolean;
  label: string;
  message?: string;
  remediation?: string;
}
const KEYGEN_INFO: Record<string, KeygenInfo> = {
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
    remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
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
    message:
      "Generates a classical EC key pair. EC keys feed BOTH ECDSA signatures " +
      "and ECDH key agreement; the ECDH path is harvest-now-decrypt-later exposed.",
    remediation:
      "For key agreement: hybrid X25519MLKEM768 (ML-KEM-768). For signatures: ML-DSA-65 (FIPS 204).",
  },
  dsa: { algo: "DSA", cat: "signature", sev: "high", hndl: false, label: "DSA" },
  dh: { algo: "DH", cat: "key-exchange", sev: "high", hndl: true, label: "Diffie-Hellman" },
  x25519: { algo: "X25519", cat: "key-exchange", sev: "medium", hndl: true, label: "X25519" },
  x448: { algo: "X448", cat: "key-exchange", sev: "medium", hndl: true, label: "X448" },
  ed25519: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed25519" },
  ed448: { algo: "EdDSA", cat: "signature", sev: "low", hndl: false, label: "Ed448" },
};

/** Emit a keygen finding for `generateKeyPair(Sync)('<type>')` at [index]. Shared
 * by the direct matcher and the import-alias pass so both classify identically. */
function pushKeygenFinding(
  findings: Finding[],
  rawType: string,
  file: string,
  content: string,
  index: number,
  matchLength: number,
): void {
  const info = KEYGEN_INFO[rawType.toLowerCase()];
  if (!info) return;
  findings.push(
    findingFromRule(
      RULE_NODE_KEYGEN,
      { file, content, index, matchLength },
      {
        title: `${info.label} key generation`,
        category: info.cat,
        severity: info.sev,
        algorithm: info.algo,
        hndl: info.hndl,
        message:
          info.message ??
          `Generates a classical ${info.label} key pair, which is not quantum-safe.`,
        ...(info.remediation ? { remediation: info.remediation } : {}),
      },
    ),
  );
}

/** Canonical Node-crypto call names whose import-aliases we resolve. */
const ALIASABLE: readonly string[] = [
  "generateKeyPairSync",
  "generateKeyPair",
  "createECDH",
  "createDiffieHellman",
  "createDiffieHellmanGroup",
];

/**
 * Collect import-aliases for the canonical crypto calls we resolve, so
 * `import { generateKeyPairSync as gk } from 'node:crypto'` (or the CommonJS
 * `const { generateKeyPairSync: gk } = require('crypto')`) is followed when `gk`
 * is called later. Returns Map<canonical, alias[]>. An alias equal to its own
 * canonical name is skipped (already matched directly). Precision-safe: the
 * alias is only ever bound to a known crypto symbol, so a later `gk(` call is
 * unambiguously that symbol.
 */
function collectCryptoAliases(content: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (canonical: string, alias: string): void => {
    if (!alias || alias === canonical) return;
    const list = out.get(canonical) ?? [];
    if (!list.includes(alias)) list.push(alias);
    out.set(canonical, list);
  };
  // ESM named imports: `import { A as B, C as D } from '...'`.
  const esm = /import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*['"][^'"]*['"]/g;
  for (let m = esm.exec(content); m; m = esm.exec(content)) {
    const spec = /([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)/g;
    for (let s = spec.exec(m[1]); s; s = spec.exec(m[1])) {
      if (ALIASABLE.includes(s[1])) add(s[1], s[2]);
    }
  }
  // CommonJS destructure-rename: `const { A: B } = require('...')`.
  const cjs = /(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"][^'"]*['"]\s*\)/g;
  for (let m = cjs.exec(content); m; m = cjs.exec(content)) {
    const spec = /([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)/g;
    for (let s = spec.exec(m[1]); s; s = spec.exec(m[1])) {
      if (ALIASABLE.includes(s[1])) add(s[1], s[2]);
    }
  }
  return out;
}

/** Escape a string for safe interpolation into a dynamically-built RegExp. */
function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
const RE_CREATE_SIGN_VERIFY = /create(?:Sign|Verify)\s*\(/g;
// One-shot crypto.sign/verify(algorithm, data, key). A LOOKBEHIND (not a
// consumed char) anchors it so it doesn't fire inside identifiers like `assign(`
// or `createSign(` (handled by the dedicated createSign/createVerify rule) —
// consuming the preceding char used to push the match onto the previous line,
// corrupting the reported line/snippet and SARIF/baseline fingerprints. The
// first argument is either a quoted digest-algorithm string (RSA/ECDSA) or
// `null` — Node's EdDSA one-shot form is `crypto.sign(null, data, edKey)`.
const RE_ONESHOT_SIGN_VERIFY =
  /(?<![.\w])(?:crypto\.)?(sign|verify)\s*\(\s*(?:['"`][\w.-]+['"`]|null)\s*,/g;
const RE_CREATE_DH = /createDiffieHellman(?:Group)?\s*\(/g;
const RE_GET_DH = /getDiffieHellman\s*\(\s*['"`](modp\d+)['"`]\s*\)/g;
const RE_CREATE_ECDH = /createECDH\s*\(/g;
const RE_RSA_ENCRYPT = /(?:crypto\.)?(?:publicEncrypt|privateDecrypt)\s*\(/g;
const RE_DH_KEYOBJECT = /(?:crypto\.)?diffieHellman\s*\(\s*\{/g;

// WebCrypto. Includes the newer curve algorithms (Ed25519/Ed448 signatures,
// X25519/X448 key agreement) shipping in modern SubtleCrypto implementations.
const RE_WEBCRYPTO_ALGO =
  /\b(RSA-OAEP|RSA-PSS|RSASSA-PKCS1-v1_5|ECDH|ECDSA|Ed25519|Ed448|X25519|X448)\b/gi;
const RE_SUBTLE_CALL =
  /subtle\s*\.\s*(generateKey|importKey|exportKey|deriveKey|deriveBits|sign|verify|encrypt|decrypt|wrapKey|unwrapKey)\s*\(/g;

// Libraries.
const RE_FORGE_RSA = /pki\.rsa\.generateKeyPair\s*\(/g;
const RE_FORGE_ED25519 = /forge\.ed25519\b/g;
// Require a curve-like first argument so `new EC("request-scope")` (a non-crypto
// `EC` class) is not flagged; the elliptic library is always constructed with a
// named curve (`new EC('secp256k1')`, `new EC('p256')`, …).
const RE_ELLIPTIC_EC =
  /new\s+(?:elliptic\.)?ec\s*\(\s*['"`](?:sec[pt]|prime|nistp|curve|ed25519|ed448|brainpool|p-?(?:192|224|256|384|521)|x25519|x448)/gi;
const RE_JSRSASIGN_KEYGEN = /KEYUTIL\.generateKeypair\s*\(/g;
const RE_JSRSASIGN_SIGN = /KJUR\.crypto\.(?:Signature|ECDSA)\b/g;
const RE_NODE_RSA = /new\s+NodeRSA\s*\(/g;
// secp256k1 — direct @noble/secp256k1 / secp256k1-style API usage in source.
const RE_SECP256K1 =
  /\b(?:secp(?:256k1)?|secp)\s*\.\s*(sign|verify|getPublicKey|getSharedSecret|ecdh|recoverPublicKey)\s*\(/g;

// JWT/JOSE.
const RE_JWT_ALG = /['"`](RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|EdDSA)['"`]/g;
// JOSE ECDH-ES key agreement (HNDL) and COSE algorithm identifiers.
const RE_JOSE_ECDH = /['"`](ECDH-ES(?:\+A(?:128|192|256)KW)?)['"`]/g;

// TLS config.
const RE_TLS_LEGACY_VERSION =
  /(?:minVersion|maxVersion)\s*:\s*['"`]TLSv1(?:\.1)?['"`]|secureProtocol\s*:\s*['"`]TLSv1(?:_1)?_method['"`]/g;
const RE_TLS_REJECT = /rejectUnauthorized\s*:\s*false/g;
// Hardened cipher regex: bounded spans (no unbounded `[^'"`]*` straddling the
// alternation), single-quote-style anchoring removed in favour of {0,256} bounds
// so worst-case backtracking is linear in the bound, not the file (P0-6).
// Skip OpenSSL EXCLUSION syntax — `!MD5` / `:-RC4` / `!ECDHE-RSA-RC4-SHA` DISABLE
// those ciphers, so a hardened list must not be flagged as weak (audit: crypto #7). The
// single variable-length lookbehind walks back over the suite-name chars to the
// ELEMENT boundary (`:` / quote / comma / start) and rejects the match when that
// element begins with `!` or `-` — covering both a bare `!RC4` and a full-suite
// `!ECDHE-RSA-RC4-SHA`. The intra-name hyphen in a genuinely-enabled `ECDHE-RSA-RC4-SHA`
// (no leading `!`/`-`) still matches.
const RE_TLS_WEAK_CIPHER =
  /ciphers\s*:\s*['"`][^'"`\n]{0,256}?\b(?<![:'"`,]\s*[!-][\w-]{0,64})(RC4|DES|3DES|MD5|NULL|EXPORT|aNULL|eNULL)\b[^'"`\n]{0,256}?['"`]/gi;

/* -------------------------------------------------------------------------- */
/* Node.js `crypto` module                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Rule catalog for the Node `crypto` detector. `node-crypto-keygen` and
 * `node-crypto-dh-modp` refine some fields per match; the rest emit findings
 * straight from these declarations.
 */
const RULE_NODE_KEYGEN: RuleMeta = {
  id: "node-crypto-keygen",
  title: "Classical key generation",
  description: "crypto.generateKeyPair(Sync)('rsa'|'ec'|'dsa'|'dh'|…)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Generates a classical asymmetric key pair, which is not quantum-safe.",
};
const RULE_NODE_SIGN: RuleMeta = {
  id: "node-crypto-sign",
  title: "Classical signature (createSign/createVerify)",
  description: "crypto.createSign / crypto.createVerify",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Uses createSign/createVerify, typically RSA, ECDSA or DSA — all forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_NODE_SIGN_ONESHOT: RuleMeta = {
  id: "node-crypto-sign-oneshot",
  title: "Classical one-shot signature (crypto.sign/verify)",
  description: "one-shot crypto.sign / crypto.verify (Node ≥ 12)",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Uses the one-shot crypto.sign/crypto.verify API, typically RSA/ECDSA/EdDSA — forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
};
const RULE_NODE_DH: RuleMeta = {
  id: "node-crypto-dh",
  title: "Diffie-Hellman key exchange",
  description: "crypto.createDiffieHellman(Group)",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "Finite-field Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_NODE_DH_MODP: RuleMeta = {
  id: "node-crypto-dh-modp",
  title: "Diffie-Hellman MODP group",
  description: "crypto.getDiffieHellman('modpN')",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "DH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Named finite-field DH MODP group is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_NODE_ECDH: RuleMeta = {
  id: "node-crypto-ecdh",
  title: "ECDH key exchange",
  description: "crypto.createECDH",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Elliptic-curve Diffie-Hellman is broken by Shor's algorithm (harvest-now-decrypt-later).",
};
const RULE_NODE_RSA_ENCRYPT: RuleMeta = {
  id: "node-crypto-rsa-encrypt",
  title: "RSA public-key encryption",
  description: "crypto.publicEncrypt / crypto.privateDecrypt",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "RSA public-key encryption is broken by Shor's algorithm and exposed to harvest-now-decrypt-later.",
};
const RULE_NODE_DH_KEYOBJECT: RuleMeta = {
  id: "node-crypto-dh-keyobject",
  title: "Diffie-Hellman (KeyObject) key exchange",
  description: "crypto.diffieHellman({ privateKey, publicKey })",
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "crypto.diffieHellman() performs a classical (EC)DH agreement (harvest-now-decrypt-later).",
};

/** Detects classical asymmetric usage from Node's built-in `crypto` module. */
const nodeCryptoDetector: Detector = {
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
    RULE_NODE_DH_KEYOBJECT,
  ],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // generateKeyPair(Sync)('rsa' | 'ec' | 'dsa' | 'dh' | 'x25519' | 'ed25519', ...)
    eachMatch(RE_GENERATE_KEYPAIR, content, (m) => {
      pushKeygenFinding(findings, m[1], file, content, m.index, m[0].length);
    });

    // Import-alias resolution: follow `import { generateKeyPairSync as gk }` (and
    // the CommonJS destructure-rename) so an aliased call still detects. Only the
    // keygen / ECDH / DH constructors are resolved — their classification is
    // unambiguous. The alias regexes run on the ORIGINAL content, so locations
    // stay exact; it fires only when the alias was explicitly bound to a known
    // crypto symbol, so precision is unaffected.
    const aliases = collectCryptoAliases(content);
    for (const [canonical, names] of aliases) {
      for (const alias of names) {
        const a = escapeRe(alias);
        if (canonical === "generateKeyPairSync" || canonical === "generateKeyPair") {
          const re = new RegExp(
            `\\b${a}\\s*\\(\\s*['"\`](rsa-pss|rsa|ec|dsa|dh|x25519|x448|ed25519|ed448)['"\`]`,
            "g",
          );
          eachMatch(re, content, (m) =>
            pushKeygenFinding(findings, m[1], file, content, m.index, m[0].length),
          );
        } else if (canonical === "createECDH") {
          eachMatch(new RegExp(`\\b${a}\\s*\\(`, "g"), content, (m) =>
            findings.push(
              findingFromRule(RULE_NODE_ECDH, {
                file,
                content,
                index: m.index,
                matchLength: m[0].length,
              }),
            ),
          );
        } else {
          // createDiffieHellman / createDiffieHellmanGroup.
          eachMatch(new RegExp(`\\b${a}\\s*\\(`, "g"), content, (m) =>
            findings.push(
              findingFromRule(RULE_NODE_DH, {
                file,
                content,
                index: m.index,
                matchLength: m[0].length,
              }),
            ),
          );
        }
      }
    }

    // createSign / createVerify — RSA / ECDSA / DSA signatures.
    eachMatch(RE_CREATE_SIGN_VERIFY, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_SIGN, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // One-shot crypto.sign(algorithm, data, key) / crypto.verify(...) (Node ≥ 12).
    eachMatch(RE_ONESHOT_SIGN_VERIFY, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_SIGN_ONESHOT, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // createDiffieHellman / createDiffieHellmanGroup — finite-field DH key exchange.
    eachMatch(RE_CREATE_DH, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_DH, { file, content, index: m.index, matchLength: m[0].length }),
      );
    });

    // getDiffieHellman('modpN') — named built-in finite-field MODP groups.
    eachMatch(RE_GET_DH, content, (m) => {
      findings.push(
        findingFromRule(
          RULE_NODE_DH_MODP,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `Diffie-Hellman MODP group (${m[1]})`,
            message: `Named finite-field DH MODP group "${m[1]}" is broken by Shor's algorithm (harvest-now-decrypt-later).`,
          },
        ),
      );
    });

    // createECDH — elliptic-curve Diffie-Hellman key exchange.
    eachMatch(RE_CREATE_ECDH, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_ECDH, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // publicEncrypt / privateDecrypt — RSA encryption (KEM-like confidentiality).
    eachMatch(RE_RSA_ENCRYPT, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_RSA_ENCRYPT, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // diffieHellman({ privateKey, publicKey }) — KeyObject-based DH/ECDH.
    eachMatch(RE_DH_KEYOBJECT, content, (m) => {
      findings.push(
        findingFromRule(RULE_NODE_DH_KEYOBJECT, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* WebCrypto (SubtleCrypto)                                                    */
/* -------------------------------------------------------------------------- */

const RULE_WEBCRYPTO: RuleMeta = {
  id: "webcrypto-classical",
  title: "WebCrypto classical algorithm",
  description: "classical asymmetric algorithm passed to SubtleCrypto",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "A classical asymmetric WebCrypto algorithm is used, which is not quantum-safe.",
};

/**
 * Detects classical algorithms passed to WebCrypto's SubtleCrypto methods. The
 * algorithm name can appear as a bare string ("RSA-OAEP") or as
 * `{ name: "ECDH" }`; we scan both forms within a window after a subtle call.
 */
const webCryptoDetector: Detector = {
  id: "webcrypto",
  description: "Classical asymmetric algorithms via WebCrypto SubtleCrypto",
  scope: "source",
  language: "js",
  rules: [RULE_WEBCRYPTO],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // Only consider names that appear near a subtle.* call to reduce noise.
    // callIndexes is collected in ascending order (regex scans left→right), so
    // proximity is resolved with a binary search instead of an O(M·C) scan.
    const callIndexes: number[] = [];
    eachMatch(RE_SUBTLE_CALL, content, (m) => callIndexes.push(m.index));
    if (callIndexes.length === 0) return findings;

    eachMatch(RE_WEBCRYPTO_ALGO, content, (m) => {
      if (!nearSortedCall(callIndexes, m.index, 400)) return;
      const name = m[1].toUpperCase();
      // Classify by algorithm: RSA-OAEP is KEM (HNDL); ECDH/X25519/X448 are key
      // agreement (HNDL); RSA-PSS/RSASSA/ECDSA/Ed25519/Ed448 are signatures.
      let algorithm: Finding["algorithm"];
      let category: Finding["category"];
      let hndl: boolean;
      let severity: Finding["severity"] | undefined;
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
        severity = "low"; // modern but classical
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
      findings.push(
        findingFromRule(
          RULE_WEBCRYPTO,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `WebCrypto ${m[1]}`,
            category,
            algorithm,
            hndl,
            ...(severity ? { severity } : {}),
            message: `WebCrypto algorithm "${m[1]}" is classical asymmetric crypto and not quantum-safe.`,
          },
        ),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* Popular crypto libraries                                                    */
/* -------------------------------------------------------------------------- */

const RULE_FORGE_RSA: RuleMeta = {
  id: "forge-rsa-keygen",
  title: "node-forge RSA key generation",
  description: "node-forge pki.rsa.generateKeyPair",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-forge generates a classical RSA key pair, which is not quantum-safe.",
};
const RULE_FORGE_ED25519: RuleMeta = {
  id: "forge-ed25519",
  title: "node-forge Ed25519 usage",
  description: "node-forge forge.ed25519.*",
  category: "signature",
  severity: "low",
  confidence: "high",
  algorithm: "EdDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-forge Ed25519 is a modern but still classical signature scheme.",
};
const RULE_ELLIPTIC_EC: RuleMeta = {
  id: "elliptic-ec",
  title: "elliptic curve instantiation",
  description: "the `elliptic` library — new EC(...)",
  // `new EC(...)` is a dual-use curve context (ECDSA sign AND ECDH `key.derive()`).
  // Per this scanner's own EC-ambiguity policy, ambiguous EC is treated as
  // key-agreement-capable and HNDL-exposed (audit: crypto #8).
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "The `elliptic` library implements classical ECDSA/ECDH, both broken by Shor's algorithm.",
};
const RULE_SECP256K1: RuleMeta = {
  id: "secp256k1-usage",
  title: "secp256k1 ECDSA/ECDH usage",
  description: "direct @noble/secp256k1-style API usage",
  category: "signature",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDSA",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Direct secp256k1 usage (ECDSA signatures / ECDH agreement) is classical and broken by Shor's algorithm.",
  remediation: "ML-DSA-65 (FIPS 204) for signatures; hybrid X25519MLKEM768 for key agreement.",
};
const RULE_JSRSASIGN_KEYGEN: RuleMeta = {
  id: "jsrsasign-keygen",
  title: "jsrsasign key generation",
  description: "jsrsasign KEYUTIL.generateKeypair",
  // KEYUTIL.generateKeypair("RSA"|"EC") makes keys usable for RSA-OAEP encryption
  // and ECDH — HNDL-exposed, like Node's generateKeyPair (audit: crypto #13).
  category: "key-exchange",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "jsrsasign generates classical RSA/EC key pairs, which are not quantum-safe.",
  remediation: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
};
const RULE_JSRSASIGN_SIGN: RuleMeta = {
  id: "jsrsasign-sign",
  title: "jsrsasign signature",
  description: "jsrsasign KJUR.crypto.Signature / ECDSA",
  category: "signature",
  severity: "high",
  confidence: "high",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "jsrsasign signing uses classical RSA/ECDSA signatures, forgeable by a quantum attacker.",
  remediation: "ML-DSA-65 (FIPS 204)",
};
const RULE_NODE_RSA_LIB: RuleMeta = {
  id: "node-rsa",
  title: "node-rsa key/usage",
  description: "the `node-rsa` library — new NodeRSA(...)",
  category: "kem",
  severity: "high",
  confidence: "high",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message: "node-rsa wraps classical RSA encryption/signing, which is not quantum-safe.",
};

/** Detects classical crypto from popular npm libraries used in source. */
const libraryDetector: Detector = {
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
    RULE_NODE_RSA_LIB,
  ],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    const add = (re: RegExp, rule: RuleMeta) =>
      eachMatch(re, content, (m) =>
        findings.push(
          findingFromRule(rule, { file, content, index: m.index, matchLength: m[0].length }),
        ),
      );

    add(RE_FORGE_RSA, RULE_FORGE_RSA); // node-forge: pki.rsa.generateKeyPair(...)
    add(RE_FORGE_ED25519, RULE_FORGE_ED25519); // node-forge: forge.ed25519.*
    add(RE_ELLIPTIC_EC, RULE_ELLIPTIC_EC); // elliptic: new EC('secp256k1')
    // secp256k1: classify per method — getSharedSecret/ecdh are key AGREEMENT
    // (ECDH, harvest-now-decrypt-later); sign/verify/getPublicKey/recover are
    // ECDSA signatures (not HNDL). The old rule flagged everything as ECDSA.
    eachMatch(RE_SECP256K1, content, (m) => {
      const kex = m[1] === "getSharedSecret" || m[1] === "ecdh";
      findings.push(
        findingFromRule(
          RULE_SECP256K1,
          { file, content, index: m.index, matchLength: m[0].length },
          kex
            ? {
                title: "secp256k1 ECDH key agreement",
                category: "key-exchange",
                algorithm: "ECDH",
                hndl: true,
                message: `secp256k1 ECDH key agreement (.${m[1]}()) is classical and harvest-now-decrypt-later exposed.`,
              }
            : undefined,
        ),
      );
    });
    add(RE_JSRSASIGN_KEYGEN, RULE_JSRSASIGN_KEYGEN); // jsrsasign: KEYUTIL.generateKeypair(...)
    add(RE_JSRSASIGN_SIGN, RULE_JSRSASIGN_SIGN); // jsrsasign: KJUR.crypto.*
    add(RE_NODE_RSA, RULE_NODE_RSA_LIB); // node-rsa: new NodeRSA(...)

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* JWT / JOSE / COSE algorithm strings                                         */
/* -------------------------------------------------------------------------- */

// JOSE RSA key-transport algorithms (JWE `alg`): quoted RSA-OAEP / RSA-OAEP-256
// /384/512 / RSA1_5. Classical RSA *encryption* (key transport) — distinct from
// the RS*/PS* *signature* tokens above, and a harvest-now-decrypt-later surface.
const RE_JOSE_KEM = /['"`](RSA-OAEP(?:-(?:256|384|512))?|RSA1_5)['"`]/g;

const RULE_JWT_ALG: RuleMeta = {
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
  remediation: "ML-DSA-65 (FIPS 204); track IETF PQC JOSE/COSE algorithms",
};
const RULE_JOSE_ECDH: RuleMeta = {
  id: "jose-ecdh-es",
  title: "JOSE ECDH-ES key agreement",
  description: "JOSE ECDH-ES / ECDH-ES+A*KW key agreement",
  category: "key-exchange",
  severity: "high",
  confidence: "medium",
  algorithm: "ECDH",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "JOSE ECDH-ES performs classical ECDH key agreement — harvest-now-decrypt-later exposed.",
  remediation: "Track IETF PQC JOSE/COSE; adopt hybrid X25519MLKEM768 KEM-based encryption.",
};
const RULE_JOSE_RSA_OAEP: RuleMeta = {
  id: "jose-rsa-oaep",
  title: "JOSE RSA key-transport algorithm",
  description: "JWE RSA-OAEP / RSA-OAEP-256/384/512 / RSA1_5 key encryption",
  category: "key-exchange",
  severity: "high",
  confidence: "medium",
  algorithm: "RSA",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "JOSE RSA key transport (RSA-OAEP / RSA1_5) is classical RSA encryption — harvest-now-decrypt-later exposed.",
  remediation: "Track IETF PQC JOSE/COSE; adopt hybrid X25519MLKEM768 KEM-based encryption.",
};

/**
 * Detects classical signature algorithm identifiers used by JWT/JOSE, plus
 * ECDH-ES key-agreement identifiers (HNDL-exposed). These appear as string
 * literals: `alg: "RS256"`, `algorithms: ["ES256"]`, `enc: "ECDH-ES+A256KW"`.
 */
const jwtDetector: Detector = {
  id: "jwt-jose",
  description: "Classical JWT/JOSE algorithms (RS/PS/ES/EdDSA) and ECDH-ES key agreement",
  scope: "source",
  // Language-agnostic evidence: a quoted "RS256"/"ES256" alg token is the same
  // signal in JS/TS or Python (e.g. PyJWT `algorithm="RS256"`), so this detector
  // is un-gated from JS-only to the JWT host surfaces.
  language: "any",
  rules: [RULE_JWT_ALG, RULE_JOSE_ECDH, RULE_JOSE_RSA_OAEP],
  appliesTo: (f) => hasExtension(f, JWT_HOST_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // Deferral guards against double-counting:
    //  - webCryptoDetector owns a quoted `RSA-OAEP`/`ECDH-ES` sitting next to a
    //    `subtle.*(` call (it matches the `RSA-OAEP`/`ECDH` name). Collect the subtle
    //    call offsets so the JOSE key-management loops can skip those. (In non-JS host
    //    files there are no subtle calls, so nothing is skipped.)
    //  - jwkDetector owns any alg/`kty` that lives inside a JWK object; skip a token
    //    whose enclosing `{…}` carries a `"kty"` so a JWK's own `alg` is not counted by
    //    both detectors. Mirrors the same guard jose.ts applies for other languages.
    const subtleCalls: number[] = [];
    eachMatch(RE_SUBTLE_CALL, content, (m) => subtleCalls.push(m.index));
    const inJwk = (index: number): boolean => enclosingObject(content, index).includes('"kty"');

    // Classical JWS signature alg tokens. Anchored to quotes to avoid words.
    eachMatch(RE_JWT_ALG, content, (m) => {
      if (inJwk(m.index)) return; // jwk-{rsa,ec,eddsa} owns a JWK's own alg
      const alg = m[1];
      let algorithm: Finding["algorithm"];
      if (alg.startsWith("RS") || alg.startsWith("PS")) algorithm = "RSA";
      else if (alg === "EdDSA") algorithm = "EdDSA";
      else algorithm = "ECDSA"; // ES*
      findings.push(
        findingFromRule(
          RULE_JWT_ALG,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `JWT/JOSE algorithm ${alg}`,
            algorithm,
            message: `JWT/JOSE algorithm "${alg}" is a classical signature, forgeable by a quantum attacker.`,
          },
        ),
      );
    });

    // JOSE ECDH-ES key agreement (and ECDH-ES+A*KW) — confidentiality, HNDL.
    eachMatch(RE_JOSE_ECDH, content, (m) => {
      if (inJwk(m.index)) return; // jwk-ec owns a JWK's own alg
      if (nearSortedCall(subtleCalls, m.index, 400)) return; // webcrypto owns it
      findings.push(
        findingFromRule(
          RULE_JOSE_ECDH,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `JOSE key agreement ${m[1]}`,
            message: `JOSE "${m[1]}" performs classical ECDH key agreement — harvest-now-decrypt-later exposed.`,
          },
        ),
      );
    });

    // JOSE RSA key transport (RSA-OAEP / RSA1_5) — classical RSA encryption, HNDL.
    eachMatch(RE_JOSE_KEM, content, (m) => {
      if (inJwk(m.index)) return; // jwk-rsa owns a JWK's own alg
      // webCryptoDetector's regex matches `RSA-OAEP` but NOT `RSA1_5`, so only defer the
      // OAEP form near a subtle call — deferring RSA1_5 would drop it entirely.
      if (m[1].startsWith("RSA-OAEP") && nearSortedCall(subtleCalls, m.index, 400)) return;
      findings.push(
        findingFromRule(
          RULE_JOSE_RSA_OAEP,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `JOSE RSA key transport ${m[1]}`,
            message: `JOSE "${m[1]}" is classical RSA key transport — harvest-now-decrypt-later exposed.`,
          },
        ),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* TLS legacy configuration                                                    */
/* -------------------------------------------------------------------------- */

const RULE_TLS_LEGACY: RuleMeta = {
  id: "tls-legacy-version",
  title: "Legacy TLS version pinned",
  description: "minVersion/maxVersion/secureProtocol pinned to TLS 1.0/1.1",
  category: "tls",
  severity: "medium",
  confidence: "high",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "TLS 1.0/1.1 are deprecated and insecure; require TLS 1.3.",
  remediation: "Set minVersion: 'TLSv1.3' and prefer PQC-hybrid key exchange.",
};
const RULE_TLS_REJECT: RuleMeta = {
  id: "tls-reject-unauthorized",
  title: "TLS certificate verification disabled",
  description: "rejectUnauthorized: false",
  category: "tls",
  severity: "high",
  confidence: "high",
  hndl: false,
  cwe: CWE_CERT_VALIDATION,
  message: "rejectUnauthorized:false disables TLS certificate verification (MITM risk).",
  remediation: "Remove rejectUnauthorized:false; verify certificates properly.",
};
const RULE_TLS_WEAK_CIPHER: RuleMeta = {
  id: "tls-weak-cipher",
  title: "Weak TLS cipher configured",
  description: "weak/export cipher in a `ciphers` string",
  category: "tls",
  severity: "medium",
  confidence: "medium",
  hndl: false,
  cwe: CWE_WEAK_STRENGTH,
  message: "A weak cipher is configured in the TLS ciphers list.",
  remediation: "Use a modern AEAD cipher suite (TLS 1.3 defaults).",
};

/**
 * Detects legacy / insecure TLS configuration expressed as JS object literals:
 * forced TLS 1.0/1.1, disabled certificate verification, and weak ciphers.
 * These aren't quantum-specific but materially weaken transport security and
 * are squarely in qScan's "config" scope.
 */
const tlsDetector: Detector = {
  id: "tls-config",
  description: "Legacy / insecure TLS configuration in JS objects",
  scope: "config",
  language: "js",
  rules: [RULE_TLS_LEGACY, RULE_TLS_REJECT, RULE_TLS_WEAK_CIPHER],
  appliesTo: (f) => hasExtension(f, JS_TS_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // minVersion / maxVersion / secureProtocol pinned to TLS 1.0 or 1.1.
    eachMatch(RE_TLS_LEGACY_VERSION, content, (m) => {
      findings.push(
        findingFromRule(RULE_TLS_LEGACY, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // rejectUnauthorized: false — disables certificate verification.
    eachMatch(RE_TLS_REJECT, content, (m) => {
      findings.push(
        findingFromRule(RULE_TLS_REJECT, {
          file,
          content,
          index: m.index,
          matchLength: m[0].length,
        }),
      );
    });

    // Weak / export ciphers referenced in a ciphers string (bounded regex).
    eachMatch(RE_TLS_WEAK_CIPHER, content, (m) => {
      findings.push(
        findingFromRule(
          RULE_TLS_WEAK_CIPHER,
          { file, content, index: m.index, matchLength: m[0].length },
          { message: `Weak cipher (${m[1]}) configured in the TLS ciphers list.` },
        ),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* SSH public keys + TLS certificate signature algorithms (config scope)       */
/* -------------------------------------------------------------------------- */

const RE_SSH_PUBKEY = /\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\b/g;
const RE_CERT_SIG_ALG =
  /\b(sha(?:1|256|384|512)WithRSAEncryption|ecdsa-with-SHA(?:1|256|384|512)|rsassaPss|dsaWithSHA(?:1|256))\b/g;
// Classical SSH key-exchange algorithm identifiers: finite-field DH groups
// (diffie-hellman-group{1,14,15,16,17,18} + group-exchange), ECDH over NIST
// curves (ecdh-sha2-nistp*), and Curve25519 (curve25519-sha256). All are
// Shor-broken key agreement — the harvest-now-decrypt-later surface a lexical
// scan misses when only the `crypto/*` API is matched, not the negotiated kex.
const RE_SSH_KEX =
  /\b(diffie-hellman-group(?:1|14|15|16|17|18)(?:-sha1|-sha256|-sha512)?|diffie-hellman-group-exchange-sha(?:1|256)|ecdh-sha2-nistp(?:256|384|521)|curve25519-sha256)\b/g;

// A bare key-type token (`ssh-rsa`, `ssh-ed25519`, …) is real SSH crypto only
// when it is EITHER (a) followed by base64 key material — an actual
// authorized_keys / known_hosts entry — OR (b) one of ≥2 DISTINCT ssh key/host-key
// algorithm tokens on the same line — an algorithm-preference list
// (`HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa`, `%w[…]`, …). A
// lone token, e.g. a UI label / i18n value like `"ssh-rsa": "ssh-rsa"`, is
// neither, so it must NOT be flagged. `RE_SSH_ALGO_TOKEN` is a separate (cloned-
// on-use) copy so counting per line never disturbs the outer `eachMatch` state.
const RE_SSH_ALGO_TOKEN = /\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\b/g;
/** How far around a token we look for a sibling algorithm on the same line. A
 * real `HostKeyAlgorithms` list is short; bounding the window keeps the per-token
 * work O(1) so a pathological single huge line can't make detection quadratic. */
const SSH_LINE_WINDOW = 512;
function isRealSshKeyOrAlgoList(content: string, index: number, matchLen: number): boolean {
  // (a) base64 key material immediately after the token → a real SSH public key.
  if (/^\s+[A-Za-z0-9+/]{20,}/.test(content.slice(index + matchLen, index + matchLen + 80))) {
    return true;
  }
  // (b) ≥2 distinct ssh key/host-key algorithm tokens on the same line → a list.
  // Bound both the back-scan for the line start and the window itself so the work
  // is constant per token and never crosses a line boundary (i18n entries live on
  // separate lines, so a lone repeated token stays a single distinct token).
  const from = Math.max(0, index - SSH_LINE_WINDOW);
  const pre = content.slice(from, index);
  const preNl = pre.lastIndexOf("\n");
  const lineStart = preNl === -1 ? from : from + preNl + 1;
  const to = Math.min(content.length, index + matchLen + SSH_LINE_WINDOW);
  const post = content.slice(index, to);
  const postNl = post.indexOf("\n");
  const lineEnd = postNl === -1 ? to : index + postNl;
  const distinct = new Set<string>();
  for (const t of content.slice(lineStart, lineEnd).matchAll(RE_SSH_ALGO_TOKEN)) distinct.add(t[1]);
  return distinct.size >= 2;
}

const RULE_SSH_PUBKEY: RuleMeta = {
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
  remediation:
    "Plan migration to PQC-capable SSH: prefer the mlkem768x25519-sha256 KEX (ML-KEM-768 hybrid, OpenSSH 10's default since Apr 2025); sntrup761x25519 is an acceptable interim. Rotate to PQC host keys as they land.",
};
const RULE_CERT_SIG_ALG: RuleMeta = {
  id: "cert-signature-algorithm",
  title: "Classical certificate signature algorithm",
  description: "X.509/TLS certificate signature-algorithm identifiers",
  category: "certificate",
  severity: "low",
  confidence: "medium",
  algorithm: "unknown",
  hndl: false,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "A classical certificate signature algorithm (RSA/ECDSA/DSA) is a quantum forgery surface.",
  remediation: "Plan re-issuance with PQC-capable CAs as ML-DSA certificate profiles mature.",
};
const RULE_SSH_KEX: RuleMeta = {
  id: "ssh-kex-classical",
  title: "Classical SSH key exchange",
  description: "diffie-hellman-group* / group-exchange / ecdh-sha2-* / curve25519-sha256 kex",
  category: "key-exchange",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "A classical SSH key-exchange algorithm (finite-field DH / ECDH / X25519) is harvest-now-decrypt-later exposed.",
  remediation:
    "Prefer the mlkem768x25519-sha256 KEX (ML-KEM-768 hybrid, OpenSSH 10 default); sntrup761x25519 is an acceptable interim.",
};

/**
 * Detects classical SSH public keys (`authorized_keys` / `known_hosts` lines)
 * and X.509 certificate signature-algorithm identifiers in any text file. These
 * are language-agnostic config surfaces — the SSH-key forgery surface and the
 * PKI signature surface that lexical PEM detection misses.
 */
const sshCertDetector: Detector = {
  id: "ssh-cert",
  description: "SSH public keys and TLS/X.509 certificate signature algorithms in config",
  scope: "config",
  language: "any",
  rules: [RULE_SSH_PUBKEY, RULE_CERT_SIG_ALG, RULE_SSH_KEX],
  // Skip prose/docs: a changelog or README that merely mentions `ssh-rsa` in a
  // sentence is not crypto config. PEM material is caught by its own detector.
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];

    // SSH public keys: ssh-rsa AAAA…, ecdsa-sha2-nistp256 …, ssh-ed25519 …
    eachMatch(RE_SSH_PUBKEY, content, (m) => {
      // Skip a bare token that is neither a real key nor an algorithm list (e.g.
      // a `"ssh-rsa": "ssh-rsa"` i18n label) — see `isRealSshKeyOrAlgoList`.
      if (!isRealSshKeyOrAlgoList(content, m.index, m[0].length)) return;
      const tok = m[1];
      const algorithm: Finding["algorithm"] = tok.startsWith("ssh-rsa")
        ? "RSA"
        : tok === "ssh-ed25519"
          ? "EdDSA"
          : tok === "ssh-dss"
            ? "DSA"
            : "ECDSA";
      findings.push(
        findingFromRule(
          RULE_SSH_PUBKEY,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `Classical SSH public key (${tok})`,
            algorithm,
            message: `SSH public key type "${tok}" is a classical key forgeable by a quantum attacker.`,
          },
        ),
      );
    });

    // X.509 / TLS certificate signature algorithm identifiers (forgery surface).
    eachMatch(RE_CERT_SIG_ALG, content, (m) => {
      const tok = m[1];
      const algorithm: Finding["algorithm"] = /RSA|rsassa/i.test(tok)
        ? "RSA"
        : tok.startsWith("ecdsa")
          ? "ECDSA"
          : "DSA";
      findings.push(
        findingFromRule(
          RULE_CERT_SIG_ALG,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `Classical certificate signature algorithm (${tok})`,
            algorithm,
            message: `Certificate signature algorithm "${tok}" is classical (RSA/ECDSA/DSA) — a quantum forgery surface.`,
          },
        ),
      );
    });

    // SSH key-exchange algorithm identifiers (finite-field DH / ECDH / X25519).
    eachMatch(RE_SSH_KEX, content, (m) => {
      const tok = m[1];
      const algorithm: Finding["algorithm"] = tok.startsWith("diffie-hellman")
        ? "DH"
        : tok.startsWith("ecdh")
          ? "ECDH"
          : "X25519";
      findings.push(
        findingFromRule(
          RULE_SSH_KEX,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            title: `Classical SSH key exchange (${tok})`,
            algorithm,
            message: `SSH key-exchange "${tok}" is classical (${algorithm}) — harvest-now-decrypt-later exposed.`,
          },
        ),
      );
    });

    return findings;
  },
};

/* -------------------------------------------------------------------------- */
/* Classical TLS key-exchange cipher suites (language-agnostic config)         */
/* -------------------------------------------------------------------------- */

// Classical KEX cipher-suite identifiers, in both the OpenSSL (`ECDHE-RSA-…`) and
// IANA (`TLS_ECDHE_RSA_WITH_…`) spellings, with `-` or `_` separators. These name
// a Shor-broken key exchange (ECDHE/DHE), so they are the harvest-now surface a
// PQC scanner should flag — distinct from the legacy-*version* / weak-cipher rules
// above. Case-sensitive on purpose: cipher-suite tokens are upper-case constants,
// so prose like "ecdhe rsa" does not misfire. No trailing \b so the IANA
// `TLS_ECDHE_RSA_WITH_…` form (a `_` follows `RSA`) still matches.
const RE_TLS_CLASSICAL_KEX = /\b(?:TLS_)?(?:ECDHE|ECDH|DHE)[-_](?:RSA|ECDSA|DSS)/g;

const RULE_TLS_CLASSICAL_KEX: RuleMeta = {
  id: "tls-classical-kex",
  title: "Classical TLS key-exchange cipher suite",
  description: "ECDHE / DHE cipher suites negotiate Shor-broken key exchange",
  category: "tls",
  severity: "medium",
  confidence: "medium",
  algorithm: "unknown",
  hndl: true,
  cwe: CWE_BROKEN_CRYPTO,
  message:
    "Classical TLS key exchange (ECDHE/DHE) is harvest-now-decrypt-later exposed — the session key can be recorded now and recovered by a quantum attacker.",
  remediation:
    "Adopt a PQC-hybrid TLS 1.3 key exchange (e.g. X25519MLKEM768) as your stack and peers support it; keep classical suites only as a transitional fallback.",
};

/**
 * Detects classical TLS key-exchange cipher suites in any text/config file
 * (OpenSSL cipher lists, IANA suite constants in Go/Java/C#/Rust, `.properties`,
 * etc.). Language-agnostic because the suite identifiers are the same tokens
 * everywhere — this is the cross-language TLS gap the legacy-version rule misses.
 */
const tlsClassicalKexDetector: Detector = {
  id: "tls-cipher-suite",
  description: "Classical TLS key-exchange cipher suites (ECDHE/DHE) in any config",
  scope: "config",
  language: "any",
  rules: [RULE_TLS_CLASSICAL_KEX],
  appliesTo: (f) => !hasExtension(f, DOC_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    eachMatch(RE_TLS_CLASSICAL_KEX, content, (m) => {
      const tok = m[0];
      const algorithm: Finding["algorithm"] = tok.includes("ECDH") ? "ECDH" : "DH";
      findings.push(
        findingFromRule(
          RULE_TLS_CLASSICAL_KEX,
          { file, content, index: m.index, matchLength: m[0].length },
          {
            algorithm,
            message: `Classical TLS key-exchange suite "${tok}…" (${algorithm}) is harvest-now-decrypt-later exposed.`,
          },
        ),
      );
    });
    return findings;
  },
};

/** All built-in source/config detectors, in run order. */
export const sourceDetectors: Detector[] = [
  nodeCryptoDetector,
  webCryptoDetector,
  libraryDetector,
  jwtDetector,
  tlsDetector,
  sshCertDetector,
  tlsClassicalKexDetector,
];
