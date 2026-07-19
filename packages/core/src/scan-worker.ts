/**
 * Worker-thread entry for {@link scanParallel}. Built to `dist/scan-worker.js`
 * and spawned by `parallel.ts`. Each worker reads its assigned files and runs
 * the SAME pure detector pipeline as the serial scan (`detectFile`), returning
 * `{ findings, filesScanned }` per chunk. No shared mutable state.
 *
 * This file performs side effects (wires up message handlers) only when it is
 * actually running inside a worker thread, so importing it from the main thread
 * (e.g. for coverage) is harmless.
 */
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { parentPort, workerData } from "node:worker_threads";

import type { Finding } from "./types.js";
import { defaultRegistry } from "./registry.js";
import { detectFile } from "./scan.js";
import { isKeystorePath, looksMinified } from "./walk.js";
import { isManifestFile } from "./dependencies.js";

interface WorkerToggles {
  source: boolean;
  config: boolean;
  deps: boolean;
  scanMinified: boolean;
  disabledRules?: string[];
}

interface ChunkRequest {
  index: number;
  files: string[];
}

if (parentPort) {
  const data = (workerData ?? {}) as { baseDir: string; toggles: WorkerToggles };
  const baseDir = data.baseDir;
  const toggles = data.toggles;
  const dets = defaultRegistry.all();
  const port = parentPort;

  port.on("message", (req: ChunkRequest) => {
    try {
      const findings: Finding[] = [];
      let filesScanned = 0;
      let unreadable = 0;
      let skippedMinified = 0;
      const scannedNames: string[] = [];

      for (const rel of req.files) {
        const abs = path.join(baseDir, ...rel.split("/"));
        // Keystores (.jks/.p12/…) are read byte-preserving (latin1); see scan.ts.
        const keystore = isKeystorePath(rel);
        let content: string;
        try {
          content = readFileSync(abs, keystore ? "latin1" : "utf8");
        } catch {
          unreadable += 1;
          continue;
        }
        if (!toggles.scanMinified && !isManifestFile(rel) && !keystore && looksMinified(content)) {
          skippedMinified += 1;
          continue;
        }
        filesScanned += 1;
        scannedNames.push(rel);
        findings.push(
          ...detectFile(
            rel,
            content,
            dets,
            {
              source: toggles.source,
              config: toggles.config,
              deps: toggles.deps,
            },
            toggles.disabledRules,
          ),
        );
      }

      port.postMessage({
        index: req.index,
        files: scannedNames,
        result: { findings, filesScanned, unreadable, skippedMinified },
      });
    } catch (err) {
      port.postMessage({
        index: req.index,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  });
}
