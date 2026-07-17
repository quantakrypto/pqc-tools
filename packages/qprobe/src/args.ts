/**
 * Hand-rolled CLI argument parser (zero dependencies), mirroring qScan's approach:
 * the parser is pure and total — it never throws and never does I/O.
 */

export type ProbeModeArg = "tls" | "ssh" | "auto";
export type FormatArg = "human" | "json" | "sarif" | "cbom";

export interface CliArgs {
  targets: string[];
  mode: ProbeModeArg;
  iOwnThis: boolean;
  ownedHostsFile?: string;
  servername?: string;
  timeoutMs: number;
  format: FormatArg;
  help: boolean;
}

export function parseArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = {
    targets: [],
    mode: "auto",
    iOwnThis: false,
    timeoutMs: 8000,
    format: "human",
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "--i-own-this":
        args.iOwnThis = true;
        break;
      case "--tls":
        args.mode = "tls";
        break;
      case "--ssh":
        args.mode = "ssh";
        break;
      case "--owned-hosts":
        args.ownedHostsFile = argv[++i];
        break;
      case "--servername":
        args.servername = argv[++i];
        break;
      case "--timeout":
        args.timeoutMs = Number(argv[++i]) || args.timeoutMs;
        break;
      case "--format": {
        const v = argv[++i];
        if (v === "json" || v === "sarif" || v === "cbom" || v === "human") args.format = v;
        break;
      }
      case "--json":
        args.format = "json";
        break;
      case "--sarif":
        args.format = "sarif";
        break;
      case "--cbom":
        args.format = "cbom";
        break;
      default:
        if (a && !a.startsWith("-")) args.targets.push(a);
        break;
    }
  }
  return args;
}

export const HELP = `qprobe — active post-quantum readiness probing of live TLS/SSH endpoints you OWN.

USAGE
  qprobe [options] <host[:port]> [host[:port] ...]

AUTHORIZATION (required — one of)
  --i-own-this            Attest you are authorized to probe the given endpoint(s).
  --owned-hosts <file>    Ownership manifest (one host per line, # comments).

  Active probing of endpoints you do not own may be unlawful. qprobe refuses CIDR
  blocks, IP ranges, wildcards and target lists. See THREAT-MODEL.md.

OPTIONS
  --tls | --ssh           Force a probe mode (default: auto — SSH on :22, else TLS).
  --servername <name>     TLS SNI server name (default: the host).
  --timeout <ms>          Per-connection timeout (default: 8000).
  --format <human|json|sarif|cbom>
                          Output format (default: human). --json / --sarif / --cbom
                          are aliases. SARIF 2.1.0 and CycloneDX 1.6 CBOM compose
                          with qScan output (same formats).
  -h, --help              Show this help.

EXAMPLES
  qprobe --i-own-this example.com                 # TLS 443: hybrid KEX + cert posture
  qprobe --ssh --i-own-this git.example.com       # SSH 22: KEXINIT algorithms
  qprobe --owned-hosts hosts.txt api.example.com:8443 --json

qprobe reports the negotiated reality; it never modifies an endpoint ("engine disposes").`;
