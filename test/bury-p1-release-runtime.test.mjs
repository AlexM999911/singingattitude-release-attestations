import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  canonicalJson,
  consumeRelease,
  sha256Json,
  validateReleaseBundle,
} from "../scripts/lib/bury-p1-release-runtime.mjs";
import {
  createGitHubTagProvider,
  verifyAnyNativeAttestation,
  verifyNativeAttestation,
} from "../scripts/consume-bury-p1-release.mjs";
import { validatePullRequestSnapshot } from "../scripts/lib/bury-p1-trusted-pr-validator.mjs";
import { main as activationProbeMain, runActivationProbe } from "../scripts/run-bury-p1-activation-probe.mjs";

const REPOSITORY = "AlexM999911/singingattitude-release-attestations";
const NOW = "2026-08-14T12:00:00Z";
const COMMIT = "a".repeat(40);
const TREE = "b".repeat(40);
const WORKFLOW_SHA = "c".repeat(40);

function fixture() {
  const entries = [
    { path: "supabase/migrations/20260814090000_bury.sql", sha256: "1".repeat(64) },
    { path: "tests/sql/bury-acuity-authority/00_baseline.sql", sha256: "2".repeat(64) },
  ];
  const pathListSha256 = sha256Json(entries.map(({ path }) => path));
  const contentLedger = {
    schemaVersion: "bury-p1-content-ledger-v1",
    candidateCommit: COMMIT,
    candidateTree: TREE,
    entries,
  };
  const contentLedgerSha256 = sha256Json(contentLedger);
  const migrationLedgerSha256 = sha256Json(entries);
  const approvals = [
    {
      schemaVersion: "bury-p1-external-approval-reference-v1",
      authorityRole: "business-release-owner",
      decision: "APPROVED",
      evidenceReference: "BURY-LIUBA/RELEASE/20260814",
      evidenceSha256: "3".repeat(64),
      acceptedAtUtc: "2026-08-14T10:00:00Z",
      validUntilUtc: "2026-08-14T14:00:00Z",
      subjectCommit: COMMIT,
      subjectCandidateLedgerSha256: contentLedgerSha256,
      authorityGrants: [],
    },
    {
      schemaVersion: "bury-p1-external-approval-reference-v1",
      authorityRole: "independent-qa-reviewer",
      decision: "PASS",
      evidenceReference: "BURY-MATTHEW/QA/20260814",
      evidenceSha256: "4".repeat(64),
      acceptedAtUtc: "2026-08-14T10:30:00Z",
      validUntilUtc: "2026-08-14T14:00:00Z",
      subjectCommit: COMMIT,
      subjectCandidateLedgerSha256: contentLedgerSha256,
      authorityGrants: [],
    },
  ];
  const approvalReferences = approvals.map((approval) => ({
    authorityRole: approval.authorityRole,
    sha256: sha256Json(approval),
  }));
  const completeBundle = {
    schemaVersion: "bury-p1-complete-bundle-v1",
    candidateCommit: COMMIT,
    candidateTree: TREE,
    pathListSha256,
    contentLedgerSha256,
    migrationLedgerSha256,
    approvalReferences,
  };
  const manifest = {
    schemaVersion: "bury-p1-attestation-manifest-v1",
    recordId: "BURY-P1-REVIEWED-20260814",
    trustModel: "BURY-P1-MODE-A-GITHUB-ATTESTATION-WITH-EXTERNAL-HUMAN-APPROVALS-V1",
    repository: REPOSITORY,
    authorization: {
      authorizationId: "BURY-P1-REVIEWED-20260814",
      oneUse: true,
      p1Authorized: true,
      g2Authorized: false,
    },
    candidate: {
      commit: COMMIT,
      tree: TREE,
      pathListSha256,
      contentLedgerSha256,
      completeBundleSha256: sha256Json(completeBundle),
      migrationLedgerSha256,
    },
    target: {
      profile: "isolated-localhost-disposable-v1",
      reference: "local-supabase://bury-p1-reviewed",
      nonProduction: true,
      noCustomerData: true,
      exclusiveLocalhost: true,
    },
    executionWindow: {
      startsAtUtc: "2026-08-14T11:00:00Z",
      expiresAtUtc: "2026-08-14T13:00:00Z",
    },
    migrations: entries.map((entry, index) => ({ order: index + 1, ...entry })),
    approvals: approvalReferences,
    actors: {
      repositoryExecutor: { githubLogin: "AlexM999911", githubAccountId: "123456789" },
      businessReleaseEvidenceReference: approvals[0].evidenceReference,
      independentQaEvidenceReference: approvals[1].evidenceReference,
    },
    boundaries: {
      production: false,
      providers: false,
      payments: false,
      email: false,
      deployment: false,
      publicBooking: false,
      g2: false,
    },
  };
  const manifestSha256 = sha256Json(manifest);
  const executor = {
    login: "AlexM999911",
    id: "123456789",
    repository: REPOSITORY,
    workflowPath: ".github/workflows/bury-p1-one-use-consumption.yml",
    ref: "refs/heads/main",
    sha: WORKFLOW_SHA,
    runId: "987654321",
    runAttempt: "1",
  };
  const attestation = {
    verified: true,
    issuer: "https://token.actions.githubusercontent.com",
    repository: REPOSITORY,
    workflowPath: ".github/workflows/bury-p1-native-attestation.yml",
    workflowRef: "refs/heads/main",
    workflowSha: WORKFLOW_SHA,
    sourceCommit: WORKFLOW_SHA,
    subjectPath: "manifests/bury-p1-reviewed.json",
    subjectDigest: manifestSha256,
    runnerEnvironment: "github-hosted",
    predicateType: "https://slsa.dev/provenance/v1",
    bundleSha256: "5".repeat(64),
  };
  return { manifest, approvals, completeBundle, contentLedger, candidateTree: { commit: COMMIT, tree: TREE, entries }, executor, attestation };
}

test("validates every authority, candidate, ledger, actor, window, attestation and unused-claim binding", () => {
  const value = fixture();
  const result = validateReleaseBundle({ ...value, now: NOW, claimState: null });
  assert.equal(result.ok, true);
  assert.deepEqual(Object.values(result.checks), Array(Object.keys(result.checks).length).fill(true));
});

test("fails closed for each of the five-finding cross-record controls", () => {
  const mutations = [
    ["manifest authority", (v) => { v.manifest.authorization.p1Authorized = false; }],
    ["candidate tree", (v) => { v.candidateTree.tree = "d".repeat(40); }],
    ["content ledger", (v) => { v.contentLedger.entries[0].sha256 = "e".repeat(64); }],
    ["business approval", (v) => { v.approvals[0].subjectCommit = "f".repeat(40); }],
    ["QA decision", (v) => { v.approvals[1].decision = "BLOCKED"; }],
    ["actor", (v) => { v.executor.login = "mallory"; }],
    ["window", (v) => { v.manifest.executionWindow.expiresAtUtc = "2026-08-14T11:30:00Z"; }],
    ["attestation issuer", (v) => { v.attestation.issuer = "https://evil.invalid"; }],
    ["attestation subject", (v) => { v.attestation.subjectDigest = "9".repeat(64); }],
    ["claim already used", (v) => { v.claimState = { authorizationId: v.manifest.authorization.authorizationId, manifestSha256: "9".repeat(64) }; }],
    ["public boundary", (v) => { v.manifest.boundaries.production = true; }],
  ];
  for (const [name, mutate] of mutations) {
    const value = fixture();
    value.claimState = null;
    mutate(value);
    assert.throws(() => validateReleaseBundle({ ...value, now: NOW }), Error, name);
  }
});

function memoryProvider(failAt, failAfterWrite = false) {
  const state = { claim: null, attestation: null, receipt: null, calls: [] };
  return {
    state,
    async readClaim() { state.calls.push("readClaim"); return state.claim; },
    async createClaim(claim) {
      state.calls.push("createClaim");
      if (failAt === "createClaim" && !failAfterWrite) throw new Error("injected claim failure");
      if (state.claim && canonicalJson(state.claim) !== canonicalJson(claim)) throw new Error("claim conflict");
      state.claim ??= structuredClone(claim);
      if (failAt === "createClaim") throw new Error("injected claim response loss");
      return state.claim;
    },
    async readAttestation() { state.calls.push("readAttestation"); return state.attestation; },
    async createAttestation(claim) {
      state.calls.push("createAttestation");
      if (failAt === "createAttestation" && !failAfterWrite) throw new Error("injected attestation failure");
      state.attestation ??= { verified: true, claimSha256: sha256Json(claim), bundleSha256: "6".repeat(64) };
      if (failAt === "createAttestation") throw new Error("injected attestation response loss");
      return state.attestation;
    },
    async readReceipt() { state.calls.push("readReceipt"); return state.receipt; },
    async createReceipt(receipt) {
      state.calls.push("createReceipt");
      if (failAt === "createReceipt" && !failAfterWrite) throw new Error("injected receipt failure");
      if (state.receipt && canonicalJson(state.receipt) !== canonicalJson(receipt)) throw new Error("receipt conflict");
      state.receipt ??= structuredClone(receipt);
      if (failAt === "createReceipt") throw new Error("injected receipt response loss");
      return state.receipt;
    },
  };
}

test("consumption is idempotent, mandatory-all-true, and recoverable at every failure boundary", async () => {
  for (const boundary of ["createClaim", "createAttestation", "createReceipt"]) {
    const provider = memoryProvider(boundary);
    const value = fixture();
    await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /injected/);
    const recovered = await consumeRelease({ ...value, now: NOW, provider: { ...provider, ...memoryProvider().provider } }).catch(() => null);
    // Retry with the same durable state but no fault injection.
    const retryProvider = memoryProvider();
    Object.assign(retryProvider.state, provider.state, { calls: [] });
    const result = await consumeRelease({ ...value, now: NOW, provider: retryProvider });
    assert.equal(result.result, "PASS", `${boundary}: ${recovered}`);
    assert.ok(result.claim);
    assert.deepEqual(Object.values(result.checks), Array(Object.keys(result.checks).length).fill(true));
    const again = await consumeRelease({ ...value, now: NOW, provider: retryProvider });
    assert.deepEqual(again, result);
  }
});

test("a conflicting partial claim or false/missing PASS check can never be resumed as success", async () => {
  const value = fixture();
  const provider = memoryProvider();
  provider.state.claim = { authorizationId: value.manifest.authorization.authorizationId, manifestSha256: "0".repeat(64) };
  await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /claim|binding|conflict/i);

  const provider2 = memoryProvider();
  provider2.state.receipt = { result: "PASS", checks: { repositoryIdentity: true }, claim: {} };
  await assert.rejects(consumeRelease({ ...value, now: NOW, provider: provider2 }), /receipt|check|claim/i);
});

test("forged PASS receipt fields and hostile winning-claim provenance are rejected on replay", async () => {
  const value = fixture();
  const complete = memoryProvider();
  const validReceipt = await consumeRelease({ ...value, now: NOW, provider: complete });
  const receiptMutations = [
    (r) => { r.repository = "attacker/repo"; },
    (r) => { r.candidateCommit = "9".repeat(40); },
    (r) => { r.manifestSha256 = "9".repeat(64); },
    (r) => { r.attestationBundleSha256 = "9".repeat(64); },
    (r) => { r.businessApprovalSha256 = "9".repeat(64); },
    (r) => { r.qaReceiptSha256 = "9".repeat(64); },
    (r) => { r.verifiedAtUtc = "2026-08-15T12:00:00Z"; },
    (r) => { r.finalizerWorkflowRun.actor = "mallory"; },
    (r) => { r.finalizerWorkflowRun.runId = "0"; },
  ];
  for (const mutate of receiptMutations) {
    const provider = memoryProvider();
    provider.state.claim = structuredClone(complete.state.claim);
    provider.state.attestation = structuredClone(complete.state.attestation);
    provider.state.receipt = structuredClone(validReceipt);
    mutate(provider.state.receipt);
    await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /receipt|binding|workflow|time|format/i);
  }

  const claimMutations = [
    (c) => { c.repository = "attacker/repo"; },
    (c) => { c.workflowRun.workflow = ".github/workflows/evil.yml"; },
    (c) => { c.workflowRun.ref = "refs/heads/evil"; },
    (c) => { c.workflowRun.actor = "mallory"; },
    (c) => { c.workflowRun.runId = "0"; },
    (c) => { c.issuedAtUtc = "2026-08-15T12:00:00Z"; },
  ];
  for (const mutate of claimMutations) {
    const provider = memoryProvider();
    provider.state.claim = structuredClone(complete.state.claim);
    mutate(provider.state.claim);
    await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /claim|workflow|actor|window|repository|format/i);
  }
});

test("a concurrently precreated hostile claim can never win exact reconciliation", async () => {
  const value = fixture();
  const provider = memoryProvider();
  provider.createClaim = async (expected) => ({
    ...expected,
    workflowRun: { ...expected.workflowRun, actor: "mallory", runId: "0" },
  });
  await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /durable claim|binding/i);
});

test("ambiguous success responses recover by exact durable-state read-back at every boundary", async () => {
  for (const boundary of ["createClaim", "createAttestation", "createReceipt"]) {
    const provider = memoryProvider(boundary, true);
    const value = fixture();
    await assert.rejects(consumeRelease({ ...value, now: NOW, provider }), /response loss/);
    const retry = memoryProvider();
    Object.assign(retry.state, provider.state, { calls: [] });
    const result = await consumeRelease({ ...value, now: NOW, provider: retry });
    assert.equal(result.result, "PASS", boundary);
  }
});

test("native verification is cryptographic, exact-identity, main-only, and denies self-hosted runners", () => {
  let call;
  const result = verifyNativeAttestation({
    subjectPath: "claims/bury-p1-pending.json",
    signerWorkflow: ".github/workflows/bury-p1-one-use-consumption.yml",
    sourceSha: WORKFLOW_SHA,
    spawnFn(command, args, options) {
      call = { command, args, options };
      return { status: 0, signal: null, stdout: "[{\"verificationResult\":{}}]" };
    },
  });
  assert.equal(call.command, "gh");
  for (const required of ["--repo", "--signer-workflow", "--signer-digest", "--source-digest", "--source-ref", "--cert-oidc-issuer", "--deny-self-hosted-runners", "--predicate-type", "--format"]) {
    assert.ok(call.args.includes(required), required);
  }
  assert.match(result.bundleSha256, /^[0-9a-f]{64}$/);
  assert.throws(() => verifyNativeAttestation({
    subjectPath: "x", signerWorkflow: "x", sourceSha: WORKFLOW_SHA,
    spawnFn: () => ({ status: 1, signal: null, stdout: "" }),
  }), /cryptographic|attestation/i);
});

test("old-SHA recovery deterministically selects the winning claim attestation", () => {
  const oldSha = "7".repeat(40);
  const oldCandidates = [{ old: "candidate-a" }, { old: "candidate-b" }]
    .map((entry) => ({ entry, digest: sha256Json(entry) }))
    .sort((a, b) => a.digest.localeCompare(b.digest));
  const expectedDigest = oldCandidates[1].digest;
  const result = verifyAnyNativeAttestation({
    subjectPath: "claims/bury-p1-pending.json",
    signerWorkflow: ".github/workflows/bury-p1-one-use-consumption.yml",
    sourceShas: [WORKFLOW_SHA, oldSha],
    expectedBundleSha256: expectedDigest,
    spawnFn(command, args) {
      const sha = args[args.indexOf("--signer-digest") + 1];
      const stdout = sha === oldSha ? JSON.stringify(oldCandidates.map((value) => value.entry)) : "[{\"current\":true}]";
      return { status: 0, signal: null, stdout };
    },
  });
  assert.equal(result.sourceSha, oldSha);
  assert.equal(result.bundleSha256, expectedDigest);
});

test("GitHub tag provider uses annotated-object then atomic ref creation and never update/delete", async () => {
  const calls = [];
  const responses = [
    { status: 201, body: { sha: "d".repeat(40) } },
    { status: 201, body: { ref: "refs/tags/bury-p1-consumed/X" } },
  ];
  const provider = createGitHubTagProvider({
    token: "x".repeat(32), commitSha: WORKFLOW_SHA,
    fetchFn: async (url, options) => {
      calls.push({ url, options });
      const response = responses.shift();
      return { status: response.status, json: async () => response.body };
    },
  });
  const claim = { claimTag: "bury-p1-consumed/BURY-P1-EXAMPLE-1234", issuedAtUtc: NOW, workflowRun: { sha: WORKFLOW_SHA } };
  assert.deepEqual(await provider.createClaim(claim), claim);
  assert.deepEqual(calls.map((call) => call.options.method), ["POST", "POST"]);
  assert.match(calls[0].url, /\/git\/tags$/);
  assert.match(calls[1].url, /\/git\/refs$/);
  assert.equal(calls.some((call) => ["PATCH", "DELETE", "PUT"].includes(call.options.method)), false);
});

test("trusted PR validation accepts only a complete executable cross-record release bundle", () => {
  const value = fixture();
  const files = [
    ["manifests/bury-p1-reviewed.json", value.manifest],
    ["manifests/bury-p1-reviewed-complete-bundle.json", value.completeBundle],
    ["manifests/bury-p1-reviewed-content-ledger.json", value.contentLedger],
    ["manifests/bury-p1-reviewed-candidate-tree.json", value.candidateTree],
    ["approvals/bury-p1-business-release.json", value.approvals[0]],
    ["approvals/bury-p1-independent-qa.json", value.approvals[1]],
  ];
  const policy = JSON.parse(readFileSync(new URL("../policy/bury-p1-public-content-policy-v1.json", import.meta.url), "utf8")).trustedPullRequestValidation;
  const makeSnapshot = (selected) => {
    const tree = []; const compare = []; const blobs = {};
    selected.forEach(([path, record], index) => {
      const content = `${JSON.stringify(record)}\n`;
      const sha = String(index + 3).repeat(40).slice(0, 40);
      tree.push({ path, mode: "100644", type: "blob", sha, size: Buffer.byteLength(content) });
      compare.push({ filename: path, status: "added", sha });
      blobs[sha] = { encoding: "base64", content: Buffer.from(content).toString("base64"), size: Buffer.byteLength(content) };
    });
    return {
      expectedRepository: REPOSITORY,
      policy,
      event: { repository: { full_name: REPOSITORY }, pull_request: {
        changed_files: selected.length,
        base: { ref: "main", sha: "1".repeat(40), repo: { full_name: REPOSITORY } },
        head: { sha: "2".repeat(40), repo: { full_name: REPOSITORY } },
      } },
      compare: { files: compare }, headCommit: { sha: "2".repeat(40), tree: { sha: "9".repeat(40) } },
      tree: { sha: "9".repeat(40), truncated: false, tree }, blobs,
    };
  };
  assert.deepEqual(validatePullRequestSnapshot(makeSnapshot(files)), { ok: true, errors: [] });
  const partial = validatePullRequestSnapshot(makeSnapshot(files.slice(0, 1)));
  assert.equal(partial.ok, false);
  assert.match(partial.errors.join("\n"), /complete|missing|cross-record/i);
});

test("activation probe has one fixed ref/payload and cannot escape into arbitrary mutation", async () => {
  const calls = [];
  const responses = [
    { status: 201, body: { sha: "8".repeat(40) } },
    { status: 201, body: { ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS" } },
    { status: 422, body: { message: "Repository rule violations" } },
    { status: 422, body: { message: "Repository rule violations" } },
  ];
  const result = await runActivationProbe({
    token: "x".repeat(32),
    workflowSha: WORKFLOW_SHA,
    repository: REPOSITORY,
    repositoryId: 1331425769,
    fetchFn: async (url, options) => {
      calls.push({ url, options });
      const next = responses.shift();
      return { status: next.status, json: async () => next.body };
    },
  });
  assert.equal(result.ref, "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS");
  assert.deepEqual(calls.map((call) => call.options.method), ["POST", "POST", "PATCH", "DELETE"]);
  assert.equal(calls.every((call) => call.url.startsWith("https://api.github.com/repos/AlexM999911/singingattitude-release-attestations/git/")), true);
  assert.equal(calls.slice(1).every((call) => JSON.stringify(call).includes("ACTIVATION-PROBE-ACTIONS")), true);
  assert.equal(JSON.parse(calls[1].options.body).ref, result.ref);
  assert.equal(JSON.parse(calls[2].options.body).sha, WORKFLOW_SHA);
  assert.equal(calls.filter((call) => call.options.body).every((call) => call.options.headers["Content-Type"] === "application/json"), true);

  await assert.rejects(runActivationProbe({ token: "x".repeat(32), workflowSha: WORKFLOW_SHA, repository: "attacker/repo", repositoryId: 1331425769, fetchFn: async () => { throw new Error("must not call"); } }), /repository/i);
  await assert.rejects(runActivationProbe({ token: "x".repeat(32), workflowSha: "main", repository: REPOSITORY, repositoryId: 1331425769, fetchFn: async () => { throw new Error("must not call"); } }), /SHA/i);

  for (const env of [
    { GITHUB_EVENT_NAME: "pull_request", GITHUB_REF: "refs/heads/main", GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/bury-p1-activation-probe.yml@refs/heads/main` },
    { GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/dev", GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/bury-p1-activation-probe.yml@refs/heads/main` },
    { GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_WORKFLOW_REF: `${REPOSITORY}/.github/workflows/attacker.yml@refs/heads/main` },
  ]) {
    await assert.rejects(activationProbeMain({ env, fetchFn: async () => { throw new Error("must not call"); } }), /protected main workflow/i);
  }

  const workflow = readFileSync(new URL("../.github/workflows/bury-p1-activation-probe.yml", import.meta.url), "utf8");
  assert.match(workflow, /^on:\n  workflow_dispatch:\n/m);
  assert.doesNotMatch(workflow, /inputs:|pull_request|schedule:|repository_dispatch/);
  assert.match(workflow, /environment: bury-p1-attestation/);
  assert.match(workflow, /permissions:\n      contents: write/);
  assert.doesNotMatch(workflow, /id-token:|actions:|pull-requests:|secrets\./);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /run: node scripts\/run-bury-p1-activation-probe\.mjs/);
});
