import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import {
  ATTESTATION_WORKFLOW,
  REPOSITORY,
  buildClaim,
  canonicalJson,
  consumeRelease,
  sha256Json,
  validateReleaseBundle,
} from "./lib/bury-p1-release-runtime.mjs";
import { loadReleaseDocuments } from "./validate-bury-p1-release-bundle.mjs";

const API = "https://api.github.com";
const CLAIM_PATH = "claims/bury-p1-pending.json";
const RECEIPT_PATH = "receipts/bury-p1-receipt.json";
const SHA = /^[0-9a-f]{40}$/;

function fail(message) { throw new Error(`Bury P1 consumption failed: ${message}`); }

function executorFromEnv(env) {
  const workflowRef = env.GITHUB_WORKFLOW_REF ?? "";
  const expectedSuffix = `${REPOSITORY}/.github/workflows/bury-p1-one-use-consumption.yml@refs/heads/main`;
  if (workflowRef !== expectedSuffix) fail("workflow identity/ref mismatch");
  if (env.GITHUB_REPOSITORY !== REPOSITORY || env.GITHUB_REPOSITORY_ID !== "1331425769" || env.GITHUB_REF !== "refs/heads/main" || env.GITHUB_EVENT_NAME !== "workflow_dispatch") fail("repository ID/name/ref/event mismatch");
  if (!SHA.test(env.GITHUB_SHA ?? "")) fail("workflow SHA is not exact");
  return {
    login: env.GITHUB_ACTOR,
    id: env.GITHUB_ACTOR_ID,
    repository: env.GITHUB_REPOSITORY,
    workflowPath: ".github/workflows/bury-p1-one-use-consumption.yml",
    ref: env.GITHUB_REF,
    sha: env.GITHUB_SHA,
    runId: env.GITHUB_RUN_ID,
    runAttempt: env.GITHUB_RUN_ATTEMPT,
  };
}

export function verifyNativeAttestation({ subjectPath, signerWorkflow, sourceSha, spawnFn = spawnSync }) {
  const args = [
    "attestation", "verify", subjectPath,
    "--repo", REPOSITORY,
    "--signer-workflow", `${REPOSITORY}/${signerWorkflow}`,
    "--signer-digest", sourceSha,
    "--source-digest", sourceSha,
    "--source-ref", "refs/heads/main",
    "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
    "--deny-self-hosted-runners",
    "--predicate-type", "https://slsa.dev/provenance/v1",
    "--format", "json",
  ];
  const result = spawnFn("gh", args, { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30_000 });
  if (result.status !== 0 || result.signal || typeof result.stdout !== "string") fail("GitHub/Sigstore cryptographic attestation verification failed");
  let parsed;
  try { parsed = JSON.parse(result.stdout); } catch { fail("GitHub attestation verifier returned malformed JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 30) fail("GitHub attestation verifier returned no bounded verification result");
  const candidates = parsed.map((entry) => ({
    entry,
    digest: createHash("sha256").update(canonicalJson(entry)).digest("hex"),
  })).sort((a, b) => a.digest.localeCompare(b.digest));
  return { output: candidates[0].entry, bundleSha256: candidates[0].digest, candidates };
}

export function verifyAnyNativeAttestation({ subjectPath, signerWorkflow, sourceShas, expectedBundleSha256, spawnFn }) {
  const verified = [];
  for (const sourceSha of [...new Set(sourceShas)]) {
    try {
      const result = verifyNativeAttestation({ subjectPath, signerWorkflow, sourceSha, spawnFn });
      verified.push(...result.candidates.map((candidate) => ({ sourceSha, output: candidate.entry, bundleSha256: candidate.digest })));
    } catch { /* A different reviewed main run may own the durable attestation. */ }
  }
  if (verified.length === 0) fail("no claim attestation verifies against either the winning or recovery workflow commit");
  if (expectedBundleSha256) {
    const exact = verified.find((value) => value.bundleSha256 === expectedBundleSha256);
    if (!exact) fail("no cryptographically verified attestation matches the winning durable digest");
    return exact;
  }
  return verified.sort((a, b) => a.bundleSha256.localeCompare(b.bundleSha256))[0];
}

export function createGitHubTagProvider({ token, commitSha, fetchFn = fetch }) {
  if (typeof token !== "string" || token.length < 20 || !SHA.test(commitSha ?? "")) fail("ephemeral token and exact commit SHA are required");
  const request = async (method, path, body, expected = [200]) => {
    if (!/^\/(?:repos\/AlexM999911\/singingattitude-release-attestations\/git\/(?:ref\/tags\/[A-Za-z0-9%._/-]+|tags(?:\/[0-9a-f]{40})?|refs))$/.test(path)) fail("API path escaped the bounded tag surface");
    const response = await fetchFn(`${API}${path}`, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2026-03-10" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (response.status === 404) return null;
    if (!expected.includes(response.status)) {
      fail(`GitHub tag API ${method} ${path} returned ${response.status}`);
    }
    return response.status === 204 ? null : response.json();
  };
  const readTag = async (tag) => {
    const ref = await request("GET", `/repos/${REPOSITORY}/git/ref/tags/${tag.split("/").map(encodeURIComponent).join("/")}`, undefined, [200, 404]);
    if (!ref) return null;
    if (ref.object?.type !== "tag" || !SHA.test(ref.object?.sha ?? "")) fail("existing claim/receipt ref is not an annotated tag");
    const object = await request("GET", `/repos/${REPOSITORY}/git/tags/${ref.object.sha}`);
    if (object?.object?.type !== "commit" || typeof object.message !== "string") fail("existing claim/receipt tag target/type mismatch");
    let value;
    try { value = JSON.parse(object.message); } catch { fail("existing claim/receipt tag message is not canonical JSON"); }
    const recordedSha = value?.workflowRun?.sha ?? value?.finalizerWorkflowRun?.sha;
    if (!SHA.test(recordedSha ?? "") || object.object.sha !== recordedSha) fail("existing claim/receipt tag does not target its recorded workflow commit");
    return value;
  };
  const createTag = async (tag, value) => {
    const message = canonicalJson(value);
    const targetSha = value?.workflowRun?.sha ?? value?.finalizerWorkflowRun?.sha;
    if (targetSha !== commitSha) fail("new claim/receipt tag must target the current protected workflow commit");
    const tagObject = await request("POST", `/repos/${REPOSITORY}/git/tags`, {
      tag,
      message,
      object: targetSha,
      type: "commit",
      tagger: { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com", date: value.issuedAtUtc ?? value.verifiedAtUtc },
    }, [201]);
    try {
      await request("POST", `/repos/${REPOSITORY}/git/refs`, { ref: `refs/tags/${tag}`, sha: tagObject.sha }, [201]);
      return value;
    } catch (error) {
      const existing = await readTag(tag);
      if (existing && canonicalJson(existing) === message) return existing;
      throw error;
    }
  };
  return {
    readClaim: (authorizationId) => readTag(`bury-p1-consumed/${authorizationId}`),
    createClaim: (claim) => createTag(claim.claimTag, claim),
    readReceipt: (claimTag) => readTag(claimTag.replace("bury-p1-consumed/", "bury-p1-receipted/")),
    createReceipt: (receipt) => createTag(receipt.claim.tag.replace("bury-p1-consumed/", "bury-p1-receipted/"), receipt),
  };
}

function manifestAttestation(documents, executor, existingClaim, spawnFn) {
  const verified = verifyAnyNativeAttestation({
    subjectPath: "manifests/bury-p1-reviewed.json",
    signerWorkflow: ATTESTATION_WORKFLOW,
    sourceShas: [existingClaim?.workflowRun?.sha, executor.sha].filter(Boolean),
    expectedBundleSha256: existingClaim?.attestationBundleSha256,
    spawnFn,
  });
  return {
    verified: true,
    issuer: "https://token.actions.githubusercontent.com",
    repository: REPOSITORY,
    workflowPath: ATTESTATION_WORKFLOW,
    workflowRef: "refs/heads/main",
    workflowSha: verified.sourceSha,
    sourceCommit: verified.sourceSha,
    subjectPath: "manifests/bury-p1-reviewed.json",
    subjectDigest: sha256Json(documents.manifest),
    runnerEnvironment: "github-hosted",
    predicateType: "https://slsa.dev/provenance/v1",
    bundleSha256: verified.bundleSha256,
  };
}

export async function main({ phase = process.argv[2], env = process.env, fetchFn = fetch, spawnFn = spawnSync, readFileFn = readFileSync, writeFileFn = writeFileSync, now = new Date().toISOString().replace(".000Z", "Z") } = {}) {
  if (!["preflight", "finalize"].includes(phase)) fail("phase must be preflight or finalize");
  const executor = executorFromEnv(env);
  const documents = loadReleaseDocuments({ readFileFn });
  const provider = createGitHubTagProvider({ token: env.GH_TOKEN, commitSha: executor.sha, fetchFn });
  const existingClaim = await provider.readClaim(documents.manifest.authorization.authorizationId);
  const attestation = manifestAttestation(documents, executor, existingClaim, spawnFn);
  if (phase === "preflight") {
    const validation = validateReleaseBundle({ ...documents, executor, attestation, now, claimState: existingClaim });
    const expected = buildClaim({ manifest: documents.manifest, attestation, executor, validation, now });
    const claim = existingClaim ?? await provider.createClaim(expected);
    writeFileFn(CLAIM_PATH, `${canonicalJson(claim)}\n`, { encoding: "utf8", mode: 0o600, flag: "w" });
    return claim;
  }
  const claimBytes = readFileFn(CLAIM_PATH, "utf8");
  const claim = JSON.parse(claimBytes);
  if (canonicalJson(claim) !== canonicalJson(existingClaim)) fail("local claim does not equal the winning durable claim");
  const existingReceipt = await provider.readReceipt(claim.claimTag);
  const claimVerification = verifyAnyNativeAttestation({
    subjectPath: CLAIM_PATH,
    signerWorkflow: ".github/workflows/bury-p1-one-use-consumption.yml",
    sourceShas: [claim.workflowRun.sha, executor.sha],
    expectedBundleSha256: existingReceipt?.attestationBundleSha256,
    spawnFn,
  });
  const runtimeProvider = {
    ...provider,
    readAttestation: async (digest) => digest === sha256Json(claim) ? { verified: true, claimSha256: digest, bundleSha256: claimVerification.bundleSha256 } : null,
    createAttestation: async () => fail("claim attestation must be created only by the pinned actions/attest step"),
  };
  const receipt = await consumeRelease({ ...documents, executor, attestation, now, provider: runtimeProvider });
  writeFileFn(RECEIPT_PATH, `${canonicalJson(receipt)}\n`, { encoding: "utf8", mode: 0o600, flag: "w" });
  return receipt;
}

if ((process.argv[1] ? pathToFileURL(process.argv[1]).href : "") === import.meta.url) {
  main().then((value) => process.stdout.write(`${JSON.stringify({ result: value.result ?? "CLAIMED" })}\n`)).catch((error) => {
    console.error(error instanceof Error ? error.message : "Bury P1 consumption failed");
    process.exitCode = 1;
  });
}
