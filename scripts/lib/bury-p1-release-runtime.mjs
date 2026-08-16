import { createHash } from "node:crypto";

export const REPOSITORY = "AlexM999911/singingattitude-release-attestations";
export const CONSUMPTION_WORKFLOW = ".github/workflows/bury-p1-one-use-consumption.yml";
export const ATTESTATION_WORKFLOW = ".github/workflows/bury-p1-native-attestation.yml";
export const OWNER_IDENTITY = Object.freeze({
  githubLogin: "AlexM999911",
  githubAccountId: "234956861",
  businessOwner: true,
  technicalOwner: true,
});

const SHA256 = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const UTC = /^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const AUTHORIZATION = /^BURY-P1-[A-Z0-9-]{8,120}$/;
const REQUIRED_CHECKS = [
  "repositoryIdentity",
  "workflowIdentity",
  "candidateBinding",
  "manifestBinding",
  "contentLedgerBinding",
  "migrationLedgerBinding",
  "ownerAuthorization",
  "ownerIdentity",
  "executionWindow",
  "nativeAttestation",
  "oneUse",
  "g2Locked",
  "productionBookingLocked",
  "recoveryAuthority",
  "rollbackAuthority",
];

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonical(value));
}

export function sha256Json(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function ownerAuthorizationSidecar(bytes) {
  if (typeof bytes !== "string") fail("owner authorization bytes are required for the sidecar");
  return `${createHash("sha256").update(bytes, "utf8").digest("hex")}  authorizations/bury-p1-owner-authorization.json\n`;
}

function fail(message) {
  throw new Error(`Bury P1 release validation failed: ${message}`);
}

function object(value, name, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${name} must have exactly: ${expected.join(", ")}`);
  return value;
}

function string(value, pattern, name) {
  if (typeof value !== "string" || !pattern.test(value)) fail(`${name} has an invalid format`);
}

function utcMillis(value, name) {
  string(value, UTC, name);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis) || new Date(millis).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${name} is not canonical UTC`);
  }
  return millis;
}

function equal(actual, expected, name) {
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${name} binding mismatch`);
}

function assertPublicValue(value, name = "record") {
  const text = canonicalJson(value);
  const forbidden = [
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,
    /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{16,})\b/i,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\b(?:postgres(?:ql)?|mysql):\/\/[^\s"']+:[^\s"']+@/i,
    /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i,
  ];
  if (forbidden.some((pattern) => pattern.test(text))) fail(`${name} contains prohibited public content`);
}

function validateOwnerIdentity(value, name) {
  object(value, name, ["githubLogin", "githubAccountId", "businessOwner", "technicalOwner"]);
  equal(value, OWNER_IDENTITY, name);
}

function validateOwnerAuthorization(ownerAuthorization, bytes, sidecar, manifest, nowMillis) {
  object(ownerAuthorization, "owner authorization", [
    "schemaVersion", "ownerIdentity", "candidateCommit", "candidateTree", "manifestSha256",
    "migrationHashes", "executionWindow", "recoveryOwner", "rollbackAuthority", "oneUse",
    "g2Authorized", "productionBookingAuthorized",
  ]);
  if (ownerAuthorization.schemaVersion !== "BURY_P1_OWNER_AUTHORIZATION_V2") fail("owner authorization schema");
  validateOwnerIdentity(ownerAuthorization.ownerIdentity, "owner identity");
  validateOwnerIdentity(ownerAuthorization.recoveryOwner, "recovery owner");
  validateOwnerIdentity(ownerAuthorization.rollbackAuthority, "rollback authority");
  if (
    ownerAuthorization.candidateCommit !== manifest.candidate.commit
    || ownerAuthorization.candidateTree !== manifest.candidate.tree
    || ownerAuthorization.manifestSha256 !== sha256Json(manifest)
  ) fail("owner authorization candidate or manifest binding");
  equal(ownerAuthorization.migrationHashes, manifest.migrations, "owner authorization migration hashes");
  equal(ownerAuthorization.executionWindow, manifest.executionWindow, "owner authorization execution window");
  if (
    ownerAuthorization.oneUse !== true
    || ownerAuthorization.g2Authorized !== false
    || ownerAuthorization.productionBookingAuthorized !== false
  ) fail("owner authorization scope");
  const starts = utcMillis(ownerAuthorization.executionWindow.startsAtUtc, "owner authorization window start");
  const expires = utcMillis(ownerAuthorization.executionWindow.expiresAtUtc, "owner authorization window expiry");
  if (starts > nowMillis || expires < nowMillis || starts >= expires) fail("owner authorization window");
  if (typeof bytes !== "string" || bytes.length === 0 || bytes.length > 256 * 1024) fail("owner authorization bytes");
  let parsedBytes;
  try { parsedBytes = JSON.parse(bytes); } catch { fail("owner authorization bytes are not valid JSON"); }
  equal(parsedBytes, ownerAuthorization, "owner authorization parsed bytes");
  if (sidecar !== ownerAuthorizationSidecar(bytes)) fail("owner authorization SHA-256 sidecar");
  assertPublicValue(ownerAuthorization, "owner authorization");
}

function validateExistingClaim(claim, { manifest, manifestSha256, attestation, ownerAuthorizationSha256, nowMillis }) {
  if (claim === null || claim === undefined) return;
  object(claim, "existing claim", [
    "schemaVersion", "authorizationId", "repository", "claimTag", "manifestSha256",
    "attestationBundleSha256", "candidateCommit", "ownerAuthorizationSha256", "executionWindow",
    "workflowRun", "oneUse", "p1Authorized", "g2Authorized", "productionBookingAuthorized", "issuedAtUtc",
  ]);
  if (claim.schemaVersion !== "bury-p1-consumption-claim-v2" || claim.authorizationId !== manifest.authorization.authorizationId || claim.repository !== REPOSITORY || claim.claimTag !== `bury-p1-consumed/${manifest.authorization.authorizationId}` || claim.manifestSha256 !== manifestSha256) fail("existing claim identity/repository/manifest binding");
  if (claim.attestationBundleSha256 !== attestation.bundleSha256 || claim.candidateCommit !== manifest.candidate.commit || claim.ownerAuthorizationSha256 !== ownerAuthorizationSha256) fail("existing claim candidate/attestation/owner binding");
  equal(claim.executionWindow, manifest.executionWindow, "existing claim execution window");
  if (claim.oneUse !== true || claim.p1Authorized !== true || claim.g2Authorized !== false || claim.productionBookingAuthorized !== false) fail("existing claim authority flags");
  object(claim.workflowRun, "existing claim workflow provenance", ["repository", "workflow", "ref", "sha", "runId", "runAttempt", "actor", "actorId"]);
  if (claim.workflowRun.repository !== REPOSITORY || claim.workflowRun.workflow !== CONSUMPTION_WORKFLOW || claim.workflowRun.ref !== "refs/heads/main" || claim.workflowRun.actor !== OWNER_IDENTITY.githubLogin || claim.workflowRun.actorId !== OWNER_IDENTITY.githubAccountId) fail("existing claim workflow/actor provenance");
  string(claim.workflowRun.sha, GIT_SHA, "existing claim workflow SHA");
  string(claim.workflowRun.runId, /^[1-9][0-9]{0,19}$/, "existing claim run ID");
  string(claim.workflowRun.runAttempt, /^[1-9][0-9]{0,9}$/, "existing claim run attempt");
  const issued = utcMillis(claim.issuedAtUtc, "existing claim issuedAtUtc");
  if (issued < Date.parse(manifest.executionWindow.startsAtUtc) || issued > Date.parse(manifest.executionWindow.expiresAtUtc) || issued > nowMillis) fail("existing claim issuance window");
}

export function validateReleaseBundle({
  manifest,
  ownerAuthorization,
  ownerAuthorizationBytes,
  ownerAuthorizationSha256Sidecar,
  completeBundle,
  contentLedger,
  candidateTree,
  executor,
  attestation,
  now,
  claimState = null,
  documentsOnly = false,
}) {
  object(manifest, "manifest", ["schemaVersion", "recordId", "trustModel", "repository", "authorization", "candidate", "target", "executionWindow", "migrations", "owner", "boundaries"]);
  if (manifest.schemaVersion !== "bury-p1-attestation-manifest-v2" || !AUTHORIZATION.test(manifest.recordId)) fail("manifest identity");
  if (manifest.trustModel !== "BURY-P1-MODE-A-GITHUB-ATTESTATION-SINGLE-OWNER-V2") fail("trust model");
  if (manifest.repository !== REPOSITORY) fail("repository identity");
  object(manifest.authorization, "authorization", ["authorizationId", "oneUse", "p1Authorized", "g2Authorized", "productionBookingAuthorized"]);
  string(manifest.authorization.authorizationId, AUTHORIZATION, "authorization ID");
  if (manifest.authorization.authorizationId !== manifest.recordId || manifest.authorization.oneUse !== true || manifest.authorization.p1Authorized !== true || manifest.authorization.g2Authorized !== false || manifest.authorization.productionBookingAuthorized !== false) fail("authority flags");
  object(manifest.candidate, "candidate", ["commit", "tree", "pathListSha256", "contentLedgerSha256", "completeBundleSha256", "migrationLedgerSha256"]);
  for (const key of ["pathListSha256", "contentLedgerSha256", "completeBundleSha256", "migrationLedgerSha256"]) string(manifest.candidate[key], SHA256, `candidate ${key}`);
  string(manifest.candidate.commit, GIT_SHA, "candidate commit");
  string(manifest.candidate.tree, GIT_SHA, "candidate tree");

  object(candidateTree, "candidate tree read-back", ["commit", "tree", "entries"]);
  if (candidateTree.commit !== manifest.candidate.commit || candidateTree.tree !== manifest.candidate.tree) fail("candidate commit/tree read-back");
  if (!Array.isArray(candidateTree.entries) || candidateTree.entries.length < 1 || candidateTree.entries.length > 256) fail("candidate tree entries");
  for (const [index, entry] of candidateTree.entries.entries()) {
    object(entry, `candidate tree entry ${index}`, ["path", "sha256"]);
    string(entry.path, /^(?:src|scripts|tests|supabase|docs|schemas)\/[A-Za-z0-9_@./-]{1,240}$/, `candidate path ${index}`);
    if (entry.path.includes("..") || entry.path.includes("//") || entry.path.includes("\\")) fail(`candidate path ${index} traverses or is non-canonical`);
    string(entry.sha256, SHA256, `candidate content digest ${index}`);
  }
  if (new Set(candidateTree.entries.map((entry) => entry.path)).size !== candidateTree.entries.length) fail("duplicate candidate path");
  if (sha256Json(candidateTree.entries.map(({ path }) => path)) !== manifest.candidate.pathListSha256) fail("path-list digest");

  object(contentLedger, "content ledger", ["schemaVersion", "candidateCommit", "candidateTree", "entries"]);
  if (contentLedger.schemaVersion !== "bury-p1-content-ledger-v1" || contentLedger.candidateCommit !== manifest.candidate.commit || contentLedger.candidateTree !== manifest.candidate.tree) fail("content ledger candidate binding");
  equal(contentLedger.entries, candidateTree.entries, "content ledger entries");
  if (sha256Json(contentLedger) !== manifest.candidate.contentLedgerSha256) fail("content ledger digest");

  if (!Array.isArray(manifest.migrations) || manifest.migrations.length < 1 || manifest.migrations.length > 16) fail("migration ledger size");
  manifest.migrations.forEach((migration, index) => {
    object(migration, `migration ${index}`, ["order", "path", "sha256"]);
    if (migration.order !== index + 1) fail("migration order must be contiguous and exact");
    const treeEntry = candidateTree.entries.find((entry) => entry.path === migration.path);
    if (!treeEntry || treeEntry.sha256 !== migration.sha256) fail("migration content binding");
  });
  if (sha256Json(manifest.migrations.map(({ path, sha256 }) => ({ path, sha256 }))) !== manifest.candidate.migrationLedgerSha256) fail("migration ledger digest");

  const nowMillis = utcMillis(now, "validation time");
  validateOwnerAuthorization(ownerAuthorization, ownerAuthorizationBytes, ownerAuthorizationSha256Sidecar, manifest, nowMillis);
  const ownerAuthorizationSha256 = sha256Json(ownerAuthorization);

  object(manifest.target, "target", ["profile", "reference", "nonProduction", "noCustomerData", "exclusiveLocalhost"]);
  if (manifest.target.profile !== "isolated-localhost-disposable-v1" || !/^local-supabase:\/\/[a-z0-9-]{8,96}$/.test(manifest.target.reference) || manifest.target.nonProduction !== true || manifest.target.noCustomerData !== true || manifest.target.exclusiveLocalhost !== true) fail("disposable target boundary");
  object(manifest.boundaries, "boundaries", ["production", "providers", "payments", "email", "deployment", "publicBooking", "g2"]);
  if (Object.values(manifest.boundaries).some((value) => value !== false)) fail("public/P1 boundary escalation");
  object(manifest.executionWindow, "execution window", ["startsAtUtc", "expiresAtUtc"]);
  const starts = utcMillis(manifest.executionWindow.startsAtUtc, "window start");
  const expires = utcMillis(manifest.executionWindow.expiresAtUtc, "window expiry");
  if (starts > nowMillis || expires < nowMillis || starts >= expires || expires - starts > 24 * 60 * 60 * 1000) fail("execution window");

  validateOwnerIdentity(manifest.owner, "manifest owner");
  if (!documentsOnly) {
    object(executor, "workflow executor", ["login", "id", "repository", "workflowPath", "ref", "sha", "runId", "runAttempt"]);
    if (executor.login !== OWNER_IDENTITY.githubLogin || executor.id !== OWNER_IDENTITY.githubAccountId || executor.repository !== REPOSITORY || executor.workflowPath !== CONSUMPTION_WORKFLOW || executor.ref !== "refs/heads/main") fail("executor identity");
    string(executor.sha, GIT_SHA, "executor SHA");
    string(executor.runId, /^[1-9][0-9]{0,19}$/, "run ID");
    string(executor.runAttempt, /^[1-9][0-9]{0,9}$/, "run attempt");

    object(attestation, "native attestation verification", ["verified", "issuer", "repository", "workflowPath", "workflowRef", "workflowSha", "sourceCommit", "subjectPath", "subjectDigest", "runnerEnvironment", "predicateType", "bundleSha256"]);
    if (attestation.verified !== true || attestation.issuer !== "https://token.actions.githubusercontent.com" || attestation.repository !== REPOSITORY || attestation.workflowPath !== ATTESTATION_WORKFLOW || attestation.workflowRef !== "refs/heads/main" || !GIT_SHA.test(attestation.workflowSha) || attestation.sourceCommit !== attestation.workflowSha || attestation.subjectPath !== "manifests/bury-p1-reviewed.json" || attestation.subjectDigest !== sha256Json(manifest) || attestation.runnerEnvironment !== "github-hosted" || attestation.predicateType !== "https://slsa.dev/provenance/v1") fail("native attestation provenance");
    string(attestation.bundleSha256, SHA256, "attestation bundle digest");
  }

  object(completeBundle, "complete bundle", ["schemaVersion", "candidateCommit", "candidateTree", "pathListSha256", "contentLedgerSha256", "migrationLedgerSha256"]);
  if (completeBundle.schemaVersion !== "bury-p1-complete-bundle-v2" || completeBundle.candidateCommit !== manifest.candidate.commit || completeBundle.candidateTree !== manifest.candidate.tree || completeBundle.pathListSha256 !== manifest.candidate.pathListSha256 || completeBundle.contentLedgerSha256 !== manifest.candidate.contentLedgerSha256 || completeBundle.migrationLedgerSha256 !== manifest.candidate.migrationLedgerSha256) fail("complete bundle cross-record binding");
  if (sha256Json(completeBundle) !== manifest.candidate.completeBundleSha256) fail("complete bundle digest");
  if (!documentsOnly) validateExistingClaim(claimState, { manifest, manifestSha256: sha256Json(manifest), attestation, ownerAuthorizationSha256, nowMillis });
  assertPublicValue({ manifest, ownerAuthorization, completeBundle, contentLedger }, "release bundle");

  const checkNames = documentsOnly
    ? REQUIRED_CHECKS.filter((name) => !["workflowIdentity", "nativeAttestation", "oneUse"].includes(name))
    : REQUIRED_CHECKS;
  const checks = Object.fromEntries(checkNames.map((name) => [name, true]));
  return { ok: true, checks, manifestSha256: sha256Json(manifest), ownerAuthorizationSha256 };
}

export function buildClaim({ manifest, attestation, executor, validation, now }) {
  return {
    schemaVersion: "bury-p1-consumption-claim-v2",
    authorizationId: manifest.authorization.authorizationId,
    repository: REPOSITORY,
    claimTag: `bury-p1-consumed/${manifest.authorization.authorizationId}`,
    manifestSha256: validation.manifestSha256,
    attestationBundleSha256: attestation.bundleSha256,
    candidateCommit: manifest.candidate.commit,
    ownerAuthorizationSha256: validation.ownerAuthorizationSha256,
    executionWindow: structuredClone(manifest.executionWindow),
    workflowRun: {
      repository: REPOSITORY,
      workflow: CONSUMPTION_WORKFLOW,
      ref: "refs/heads/main",
      sha: executor.sha,
      runId: executor.runId,
      runAttempt: executor.runAttempt,
      actor: executor.login,
      actorId: executor.id,
    },
    oneUse: true,
    p1Authorized: true,
    g2Authorized: false,
    productionBookingAuthorized: false,
    issuedAtUtc: now,
  };
}

function validateReceipt(receipt, { claim, checks, manifest, validation, claimAttestation }) {
  object(receipt, "receipt", ["schemaVersion", "recordId", "result", "verifiedAtUtc", "repository", "candidateCommit", "manifestSha256", "attestationBundleSha256", "ownerAuthorizationSha256", "claim", "finalizerWorkflowRun", "checks", "authorityGrants"]);
  if (receipt.result !== "PASS" || receipt.schemaVersion !== "bury-p1-verification-receipt-v2" || receipt.recordId !== manifest.recordId || receipt.repository !== REPOSITORY || receipt.candidateCommit !== manifest.candidate.commit || receipt.manifestSha256 !== validation.manifestSha256 || receipt.attestationBundleSha256 !== claimAttestation.bundleSha256 || receipt.ownerAuthorizationSha256 !== claim.ownerAuthorizationSha256) fail("receipt identity/cross-record hash binding");
  const verifiedAt = utcMillis(receipt.verifiedAtUtc, "receipt verification time");
  if (verifiedAt < Date.parse(claim.issuedAtUtc) || verifiedAt > Date.parse(manifest.executionWindow.expiresAtUtc)) fail("receipt verification time is outside the winning claim/window");
  equal(receipt.checks, checks, "receipt mandatory checks");
  if (!receipt.claim || receipt.claim.tag !== claim.claimTag || receipt.claim.claimSha256 !== sha256Json(claim)) fail("receipt claim binding");
  object(receipt.finalizerWorkflowRun, "receipt finalizer workflow", ["repository", "workflow", "ref", "sha", "runId", "runAttempt", "actor", "actorId"]);
  if (receipt.finalizerWorkflowRun.repository !== REPOSITORY || receipt.finalizerWorkflowRun.workflow !== CONSUMPTION_WORKFLOW || receipt.finalizerWorkflowRun.ref !== "refs/heads/main" || !GIT_SHA.test(receipt.finalizerWorkflowRun.sha) || receipt.finalizerWorkflowRun.actor !== OWNER_IDENTITY.githubLogin || receipt.finalizerWorkflowRun.actorId !== OWNER_IDENTITY.githubAccountId || !/^[1-9][0-9]{0,19}$/.test(receipt.finalizerWorkflowRun.runId) || !/^[1-9][0-9]{0,9}$/.test(receipt.finalizerWorkflowRun.runAttempt)) fail("receipt finalizer workflow binding");
  if (!Array.isArray(receipt.authorityGrants) || receipt.authorityGrants.length !== 0) fail("receipt authority grants");
}

export async function consumeRelease(input) {
  const existingClaim = await input.provider.readClaim(input.manifest.authorization.authorizationId);
  const validation = validateReleaseBundle({ ...input, claimState: existingClaim });
  const expectedClaim = buildClaim({ ...input, validation });
  const claim = existingClaim ?? await input.provider.createClaim(expectedClaim);
  if (!existingClaim) {
    equal(claim, expectedClaim, "durable claim");
  }

  const existingReceipt = await input.provider.readReceipt(claim.claimTag);
  let claimAttestation = await input.provider.readAttestation(sha256Json(claim));
  claimAttestation ??= await input.provider.createAttestation(claim);
  object(claimAttestation, "claim attestation", ["verified", "claimSha256", "bundleSha256"]);
  if (claimAttestation.verified !== true || claimAttestation.claimSha256 !== sha256Json(claim)) fail("claim attestation binding");
  string(claimAttestation.bundleSha256, SHA256, "claim attestation bundle digest");
  if (existingReceipt) {
    validateReceipt(existingReceipt, { claim, checks: validation.checks, manifest: input.manifest, validation, claimAttestation });
    return existingReceipt;
  }

  const receipt = {
    schemaVersion: "bury-p1-verification-receipt-v2",
    recordId: manifestRecordId(input.manifest),
    result: "PASS",
    verifiedAtUtc: input.now,
    repository: REPOSITORY,
    candidateCommit: input.manifest.candidate.commit,
    manifestSha256: validation.manifestSha256,
    attestationBundleSha256: claimAttestation.bundleSha256,
    ownerAuthorizationSha256: expectedClaim.ownerAuthorizationSha256,
    claim: { tag: claim.claimTag, claimSha256: sha256Json(claim) },
    finalizerWorkflowRun: {
      repository: REPOSITORY,
      workflow: CONSUMPTION_WORKFLOW,
      ref: "refs/heads/main",
      sha: input.executor.sha,
      runId: input.executor.runId,
      runAttempt: input.executor.runAttempt,
      actor: input.executor.login,
      actorId: input.executor.id,
    },
    checks: validation.checks,
    authorityGrants: [],
  };
  validateReceipt(receipt, { claim, checks: validation.checks, manifest: input.manifest, validation, claimAttestation });
  const stored = await input.provider.createReceipt(receipt);
  equal(stored, receipt, "durable receipt");
  return stored;
}

function manifestRecordId(manifest) {
  return manifest.recordId;
}
