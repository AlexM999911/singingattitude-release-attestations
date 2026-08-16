import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { validateReleaseBundle } from "./lib/bury-p1-release-runtime.mjs";

const PATHS = Object.freeze({
  manifest: "manifests/bury-p1-reviewed.json",
  ownerAuthorization: "authorizations/bury-p1-owner-authorization.json",
  ownerAuthorizationSidecar: "authorizations/bury-p1-owner-authorization.sha256",
  completeBundle: "manifests/bury-p1-reviewed-complete-bundle.json",
  contentLedger: "manifests/bury-p1-reviewed-content-ledger.json",
  candidateTree: "manifests/bury-p1-reviewed-candidate-tree.json",
});

export function loadReleaseDocuments({ readFileFn = readFileSync } = {}) {
  const read = (path) => JSON.parse(readFileFn(path, "utf8"));
  const ownerAuthorizationBytes = readFileFn(PATHS.ownerAuthorization, "utf8");
  return {
    manifest: read(PATHS.manifest),
    ownerAuthorization: JSON.parse(ownerAuthorizationBytes),
    ownerAuthorizationBytes,
    ownerAuthorizationSha256Sidecar: readFileFn(PATHS.ownerAuthorizationSidecar, "utf8"),
    completeBundle: read(PATHS.completeBundle),
    contentLedger: read(PATHS.contentLedger),
    candidateTree: read(PATHS.candidateTree),
  };
}

export function main({ now = new Date().toISOString().replace(".000Z", "Z"), readFileFn = readFileSync } = {}) {
  const result = validateReleaseBundle({
    ...loadReleaseDocuments({ readFileFn }),
    now,
    documentsOnly: true,
  });
  process.stdout.write(`${JSON.stringify({ ok: true, checks: result.checks })}\n`);
  return result;
}

if ((process.argv[1] ? pathToFileURL(process.argv[1]).href : "") === import.meta.url) {
  try { main(); } catch (error) {
    console.error(error instanceof Error ? error.message : "Bury P1 release document validation failed");
    process.exitCode = 1;
  }
}
