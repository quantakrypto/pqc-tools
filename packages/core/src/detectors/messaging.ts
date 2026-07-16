/**
 * Config detector: classical transport crypto in message brokers / event streams
 * (Kafka, RabbitMQ, MQTT/Mosquitto, NATS). Broker traffic is "communication
 * between things"; a legacy TLS floor or a classical (EC)DHE cipher suite makes
 * every message in flight harvest-now-decrypt-later exposed.
 *
 * Covered in broker config files (`.properties`, `.conf`, `.cfg`, `.ini`):
 *  - Kafka `ssl.protocol` / `ssl.enabled.protocols = TLSv1 | TLSv1.1` (legacy).
 *  - MQTT/Mosquitto `tls_version tlsv1 | tlsv1.1` (legacy).
 *  - Kafka `ssl.cipher.suites` naming a classical `ECDHE_RSA` / `ECDHE_ECDSA` /
 *    `TLS_RSA` suite — the harvestable key-exchange path.
 */
import type { Detector, Finding, RuleMeta } from "../types.js";
import { eachMatch, findingFromRule, hasExtension } from "../detect-utils.js";
import { CWE_RISKY_PRIMITIVE, CWE_BROKEN_CRYPTO } from "../cwe.js";

const MQ_EXTENSIONS: readonly string[] = [".properties", ".conf", ".cfg", ".ini"];

interface MqRule {
  re: RegExp;
  meta: RuleMeta;
}

const MQ_RULES: MqRule[] = [
  {
    // Match TLSv1 (=1.0) and TLSv1.1 but never TLSv1.2 / TLSv1.3: the negative
    // lookahead stops "TLSv1" from matching the "TLSv1" inside "TLSv1.3".
    re: /\bssl\.(?:enabled\.)?protocols?\s*=\s*[^\n]*\bTLSv1(?:\.1)?(?![.\d])/gi,
    meta: {
      id: "mq-kafka-legacy-tls",
      title: "Kafka legacy TLS protocol",
      description: "Kafka ssl.protocol / ssl.enabled.protocols permits TLS 1.0 / 1.1",
      category: "tls",
      severity: "medium",
      confidence: "high",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message: "Kafka broker permits legacy TLS 1.0/1.1; its classical key exchange is weak and harvestable.",
      remediation: "Require TLS 1.3 and track PQC-hybrid KEX (X25519MLKEM768).",
    },
  },
  {
    re: /\btls_version\s+tlsv1(?:\.1)?(?![.\d])/gi,
    meta: {
      id: "mq-mqtt-legacy-tls",
      title: "MQTT legacy TLS version",
      description: "Mosquitto/MQTT tls_version permits TLS 1.0 / 1.1",
      category: "tls",
      severity: "medium",
      confidence: "high",
      hndl: false,
      cwe: CWE_RISKY_PRIMITIVE,
      message: "MQTT broker permits legacy TLS 1.0/1.1; its classical key exchange is weak and harvestable.",
      remediation: "Require TLS 1.3 and track PQC-hybrid KEX for device fleets.",
    },
  },
  {
    re: /\bssl\.cipher\.suites\s*=\s*[^\n]*(?:ECDHE_RSA|ECDHE_ECDSA|TLS_RSA|_DHE_RSA)/g,
    meta: {
      id: "mq-classical-cipher",
      title: "Broker classical (EC)DHE cipher suite",
      description: "Kafka ssl.cipher.suites names a classical ECDHE/DHE/RSA suite",
      category: "tls",
      severity: "medium",
      confidence: "high",
      algorithm: "ECDH",
      hndl: true,
      cwe: CWE_BROKEN_CRYPTO,
      message:
        "Broker TLS is pinned to a classical (EC)DHE/RSA cipher suite; the key exchange is harvest-now-decrypt-later exposed.",
      remediation: "Move to TLS 1.3 with a PQC-hybrid group (X25519MLKEM768) once the broker/runtime supports it.",
    },
  },
];

/** Detects classical transport crypto in message-broker / event-stream config. */
export const messagingDetector: Detector = {
  id: "messaging-transport",
  description: "Classical transport crypto in message brokers (Kafka, MQTT, RabbitMQ, NATS)",
  scope: "config",
  language: "any",
  rules: MQ_RULES.map((r) => r.meta),
  appliesTo: (f) => hasExtension(f, MQ_EXTENSIONS),
  detect({ file, content }): Finding[] {
    const findings: Finding[] = [];
    for (const rule of MQ_RULES) {
      eachMatch(rule.re, content, (m) => {
        findings.push(
          findingFromRule(rule.meta, { file, content, index: m.index, matchLength: m[0].length }),
        );
      });
    }
    return findings;
  },
};
