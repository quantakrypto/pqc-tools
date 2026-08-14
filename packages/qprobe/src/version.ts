/**
 * qProbe version, surfaced in JSON output.
 *
 * Kept in lockstep with package.json by version.test.ts. It used to say only
 * "keep in sync with package.json", and it had drifted four minors: every
 * qProbe JSON report and every endpoint CBOM since 0.8.0 carried toolVersion
 * 0.7.0, which is evidence data, not cosmetics.
 */
export const VERSION = "0.12.0";
