import { validateReleaseBundle } from "./bury-p1-release-runtime.mjs";

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const SAFE_PATH_PATTERN = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\)[\x20-\x7e]+$/;
const PINNED_ACTION_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/;
const SENSITIVE_CONTENT_PATTERNS = [
  { name: "raw email address", pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { name: "raw UUID", pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i },
  { name: "GitHub token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/ },
  { name: "Stripe live secret", pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/ },
  { name: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/ },
  { name: "bearer credential", pattern: /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/i },
  { name: "private key", pattern: /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----/ },
  { name: "database connection string", pattern: /\b(?:postgres(?:ql)?|mysql):\/\/[^\s]+/i },
  {
    name: "assigned secret",
    pattern: /\b(?:api[_-]?key|access[_-]?token|credential|secret|password|signing[_-]?key)\b\s*["']?\s*[:=]\s*["'][^"']+["']/i,
  },
];
const REVIEWED_PUBLIC_HIGH_ENTROPY_TOKENS = new Set([
  "supabase/migrations/20260803195726_bury_lane0_internal_workflow",
]);

function addError(errors, message) {
  if (!errors.includes(message)) errors.push(message);
}

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function inspectWorkflow(file, text, policy, errors) {
  const contract = policy.approvedWorkflowContracts[file.filename];
  if (!contract) {
    addError(errors, `Workflow action contract is not explicitly base-authorized: ${file.filename}`);
    return;
  }
  const contractKeys = [
    "allowedActions",
    "allowedJobKeys",
    "allowedPermissionEntries",
    "allowedStepKeys",
    "allowedTopLevelKeys",
    "allowedTriggers",
    "allowedRunCommands",
    "allowedWithKeys",
    "exactActionInputs",
    "exactEnvironmentEntries",
    "exactRunConditions",
    "requiredActionCounts",
    "requiredRunCounts",
    "requiredEnvironment",
    "requiredJobKeys",
    "requiredPermissionEntries",
  ];
  if (!exactKeys(contract, contractKeys)) {
    addError(errors, `Workflow contract is malformed for ${file.filename}`);
    return;
  }
  if (
    !Array.isArray(contract.allowedActions) ||
    !contract.allowedActions.every((value) => PINNED_ACTION_PATTERN.test(value)) ||
    !Array.isArray(contract.allowedTriggers) ||
    !contract.allowedTriggers.every((value) => ["pull_request", "push", "workflow_dispatch"].includes(value)) ||
    contractKeys
      .filter((key) => !["exactActionInputs", "exactEnvironmentEntries", "exactRunConditions", "requiredActionCounts", "requiredRunCounts", "requiredEnvironment"].includes(key))
      .slice(1)
      .some((key) => !Array.isArray(contract[key])) ||
    !contract.requiredActionCounts ||
    typeof contract.requiredActionCounts !== "object" ||
    Array.isArray(contract.requiredActionCounts) ||
    Object.entries(contract.requiredActionCounts).some(
      ([action, count]) => !contract.allowedActions.includes(action) || !Number.isInteger(count) || count < 1,
    ) ||
    !contract.requiredRunCounts ||
    typeof contract.requiredRunCounts !== "object" ||
    Array.isArray(contract.requiredRunCounts) ||
    Object.entries(contract.requiredRunCounts).some(
      ([command, count]) => !contract.allowedRunCommands.includes(command) || !Number.isInteger(count) || count < 1,
    ) ||
    !contract.exactActionInputs ||
    typeof contract.exactActionInputs !== "object" ||
    Array.isArray(contract.exactActionInputs) ||
    Object.keys(contract.exactActionInputs).some((action) => !contract.allowedActions.includes(action)) ||
    !contract.exactEnvironmentEntries ||
    typeof contract.exactEnvironmentEntries !== "object" ||
    Array.isArray(contract.exactEnvironmentEntries) ||
    !contract.exactRunConditions ||
    typeof contract.exactRunConditions !== "object" ||
    Array.isArray(contract.exactRunConditions) ||
    Object.entries(contract.exactRunConditions).some(([command, condition]) => !contract.allowedRunCommands.includes(command) || condition !== "always()") ||
    typeof contract.requiredEnvironment !== "boolean"
  ) {
    addError(errors, `Workflow contract is malformed for ${file.filename}`);
    return;
  }

  const closedSyntaxText = Object.hasOwn(contract.exactEnvironmentEntries, "GH_TOKEN")
    ? text.replace(/\$\{\{ github\.token \}\}/g, "AUTHORISED_GITHUB_TOKEN")
    : text;
  const exactSyntaxText = closedSyntaxText.replace(/\$\{\{ github\.sha \}\}/g, "AUTHORISED_PROTECTED_MAIN_SHA");
  // Only this deliberately tiny YAML subset is authorized. Anything that could
  // change YAML interpretation without changing these visible keys fails closed.
  if (
    /[^\x09\x0a\x0d\x20-\x7e]/.test(text) ||
    /\\/.test(text) ||
    /\t/.test(text) ||
    /#/.test(text) ||
    /^\s*(?:-\s*)?["'][^"']+["']\s*:/m.test(text) ||
    /(?:^|\s)(?:&[A-Za-z0-9_-]+|\*[A-Za-z0-9_-]+|![A-Za-z0-9_!-]*|<<\s*:)/m.test(text) ||
    /^\s*(?:%YAML|---|\.\.\.)/m.test(text) ||
    /:\s*[|>][+-]?\s*$/m.test(text) ||
    /[\[\]]/.test(text) ||
    /[{}]/.test(exactSyntaxText.replace(/^permissions:\s*\{\}\s*$/gm, ""))
  ) {
    addError(errors, `Workflow uses prohibited YAML syntax or unknown constructs: ${file.filename}`);
    return;
  }
  if (/\bpull_request_target\s*:/.test(text)) {
    addError(errors, `Future workflow may not use pull_request_target: ${file.filename}`);
  }
  const tokenScrubbed = Object.hasOwn(contract.exactEnvironmentEntries, "GH_TOKEN")
    ? text.replace(/^\s+GH_TOKEN:\s*\$\{\{ github\.token \}\}\s*$/gm, "")
    : text;
  if (/\b(?:secrets\.|github\.token\b)/i.test(tokenScrubbed)) {
    addError(errors, `Workflow may not expose a secret or token: ${file.filename}`);
  }
  if (/^\s+[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Za-z0-9_]*\s*:/im.test(tokenScrubbed)) {
    addError(errors, `Workflow may not declare credential-bearing environment keys: ${file.filename}`);
  }
  const triggers = [];
  const topLevelKeys = [];
  const permissionEntries = [];
  const actionReferences = [];
  const runCommands = [];
  const stack = [];
  const structuralKeyScopes = new Set();
  const jobKeys = new Set();
  const steps = [];
  const environmentEntries = {};
  let currentStep = null;
  let jobCount = 0;
  let protectedEnvironmentCount = 0;
  const lines = text.split(/\r?\n/);
  for (const [lineIndex, line] of lines.entries()) {
    if (line.trim() === "") continue;
    const indent = line.match(/^ */)[0].length;
    if (indent % 2 !== 0) {
      addError(errors, `Workflow indentation is outside the closed YAML subset at line ${lineIndex + 1}`);
      continue;
    }
    const trimmed = line.trimStart();
    const sequence = trimmed.startsWith("- ");
    const mapping = (sequence ? trimmed.slice(2) : trimmed).match(/^([A-Za-z0-9_-]+):(?:\s*(.*))?$/);
    if (!mapping) {
      addError(errors, `Workflow contains an unknown YAML construct at line ${lineIndex + 1}`);
      continue;
    }
    const [, key, rawValue = ""] = mapping;
    const value = rawValue.trim();
    while (stack.length && stack.at(-1).indent >= indent) stack.pop();
    const ancestors = stack.map((entry) => entry.key);
    const nearest = stack.at(-1)?.key;

    if (!ancestors.includes("steps") && !ancestors.includes("with")) {
      const scope = `${ancestors.join("/")}|${indent}|${key}`;
      if (structuralKeyScopes.has(scope)) {
        addError(errors, `Workflow contains a duplicate structural key: ${key}`);
      }
      structuralKeyScopes.add(scope);
    }

    const authorisedTokenExpression = nearest === "env" && key === "GH_TOKEN" && value === contract.exactEnvironmentEntries.GH_TOKEN;
    const authorisedActionExpression = ancestors.includes("with") && currentStep?.uses && value === contract.exactActionInputs[currentStep.uses]?.[key];
    if (/\$\{\{/.test(value) && !authorisedTokenExpression && !authorisedActionExpression) {
      addError(errors, `Workflow value may not contain a PR-influenceable expression at line ${lineIndex + 1}`);
    }
    if (indent === 0) {
      topLevelKeys.push(key);
      if (!contract.allowedTopLevelKeys.includes(key)) {
        addError(errors, `Unknown workflow top-level key: ${key}`);
      }
    } else if (nearest === "on") {
      if (indent !== 2 || !contract.allowedTriggers.includes(key) || value !== "") {
        addError(errors, `Workflow trigger is outside its path-specific contract: ${key}`);
      } else {
        triggers.push(key);
      }
    } else if (nearest === "permissions") {
      const permission = `${key}:${value}`;
      permissionEntries.push(permission);
      if (!contract.allowedPermissionEntries.includes(permission)) {
        addError(errors, `Workflow permission is outside its path-specific contract: ${permission}`);
      }
    } else if (nearest === "env") {
      if (Object.hasOwn(environmentEntries, key)) addError(errors, `Workflow contains a duplicate environment key: ${key}`);
      environmentEntries[key] = value;
    } else if (nearest === "jobs" && indent === 2) {
      if (!/^[a-z][a-z0-9-]{0,62}$/.test(key) || value !== "") {
        addError(errors, `Workflow job identifier is invalid: ${key}`);
      }
      jobCount += 1;
    } else if (ancestors.includes("with")) {
      if (!contract.allowedWithKeys.includes(key)) {
        addError(errors, `Workflow action input is outside its path-specific contract: ${key}`);
      }
      if (currentStep && Object.hasOwn(currentStep.with, key)) {
        addError(errors, `Workflow contains a duplicate action input: ${key}`);
      }
      if (currentStep) currentStep.with[key] = value;
      if (key === "persist-credentials" && value !== "false") {
        addError(errors, `Workflow checkout credentials must not persist: ${file.filename}`);
      }
      if (["push-to-registry", "show-summary"].includes(key) && value !== "false") {
        addError(errors, `Workflow attestation output must remain local and quiet: ${key}`);
      }
      if (key === "subject-path" && !/^(?:manifests|claims)\/[a-z0-9_-]+(?:\/[a-z0-9_-]+)*\.json$/.test(value)) {
        addError(errors, `Workflow subject path is not a fixed public JSON path: ${value}`);
      }
    } else if (ancestors.includes("steps")) {
      if (!contract.allowedStepKeys.includes(key)) {
        addError(errors, `Workflow step key is outside its path-specific contract: ${key}`);
      }
      if (sequence) {
        currentStep = { keys: new Set(), uses: null, run: null, condition: null, with: {} };
        steps.push(currentStep);
      }
      if (!currentStep) {
        addError(errors, `Workflow step key is not attached to a sequence entry: ${key}`);
      } else {
        if (!sequence && currentStep.keys.has(key)) {
          addError(errors, `Workflow contains a duplicate step key: ${key}`);
        }
        currentStep.keys.add(key);
      }
      if (key === "uses") {
        if (currentStep) currentStep.uses = value;
        actionReferences.push(value);
        if (!PINNED_ACTION_PATTERN.test(value) || !contract.allowedActions.includes(value)) {
          addError(errors, `Workflow action is not on the full-SHA allowlist: ${value}`);
        }
      }
      if (key === "run") {
        if (currentStep) currentStep.run = value;
        runCommands.push(value);
        if (!contract.allowedRunCommands.includes(value)) {
          addError(errors, `Workflow command is not an exact protected-runtime invocation: ${value}`);
        }
      }
      if (key === "if" && currentStep) currentStep.condition = value;
      if (key === "env") {
        addError(errors, `Workflow may not receive PR-controlled environment data: ${key}`);
      }
    } else if (ancestors.includes("jobs")) {
      if (!contract.allowedJobKeys.includes(key)) {
        addError(errors, `Workflow job key is outside its path-specific contract: ${key}`);
      }
      jobKeys.add(key);
      if (key === "runs-on" && value !== "ubuntu-24.04") {
        addError(errors, `Workflow runner must be ubuntu-24.04: ${value}`);
      }
      if (key === "environment" && value !== "bury-p1-attestation") {
        addError(errors, `Workflow environment is outside its path-specific contract: ${value}`);
      }
      if (key === "environment" && value === "bury-p1-attestation") {
        protectedEnvironmentCount += 1;
      }
    } else {
      addError(errors, `Workflow key is outside its closed structure: ${key}`);
    }

    if (sequence && !ancestors.includes("steps")) {
      addError(errors, `Workflow sequence is only permitted for steps: ${file.filename}`);
    }
    if (value === "") stack.push({ indent, key });
  }

  if (JSON.stringify([...new Set(topLevelKeys)].sort()) !== JSON.stringify([...contract.allowedTopLevelKeys].sort())) {
    addError(errors, `Workflow top-level keys do not match its closed contract: ${file.filename}`);
  }
  if (JSON.stringify([...new Set(triggers)].sort()) !== JSON.stringify([...contract.allowedTriggers].sort())) {
    addError(errors, `Workflow triggers do not match its path-specific contract: ${file.filename}`);
  }
  for (const required of contract.requiredPermissionEntries) {
    if (!permissionEntries.includes(required)) {
      addError(errors, `Workflow is missing required permission boundary: ${required}`);
    }
  }
  if (jobCount !== 1) {
    addError(errors, `Workflow contract requires exactly one job: ${file.filename}`);
  }
  for (const required of contract.requiredJobKeys) {
    if (!jobKeys.has(required)) {
      addError(errors, `Workflow is missing required job key: ${required}`);
    }
  }
  if (contract.requiredEnvironment && protectedEnvironmentCount !== 1) {
    addError(errors, "Workflow must use the protected bury-p1-attestation environment");
  }
  if (canonicalObject(environmentEntries) !== canonicalObject(contract.exactEnvironmentEntries)) {
    addError(errors, `Workflow environment does not match its exact ephemeral-token contract: ${file.filename}`);
  }
  for (const step of steps) {
    const expectedStepKeys = step.run === null
      ? ["name", "uses", "with"]
      : ["name", "run", ...(Object.hasOwn(contract.exactRunConditions, step.run) ? ["if"] : [])];
    if (JSON.stringify([...step.keys].sort()) !== JSON.stringify(expectedStepKeys.sort())) {
      addError(errors, "Every workflow step must match the exact action or protected-runtime shape");
    }
    if ((step.run === null) === (step.uses === null)) {
      addError(errors, "Every workflow step must select exactly one of uses or run");
    }
    if (step.run !== null && (step.condition ?? null) !== (contract.exactRunConditions[step.run] ?? null)) {
      addError(errors, `Protected runtime condition mismatch for ${step.run}`);
    }
    if (step.uses?.startsWith("actions/checkout@") && step.with["persist-credentials"] !== "false") {
      addError(errors, "Every checkout step must set persist-credentials: false");
    }
    if (step.uses?.startsWith("actions/attest@")) {
      if (!/^(?:manifests|claims)\/[a-z0-9_-]+(?:\/[a-z0-9_-]+)*\.json$/.test(step.with["subject-path"] ?? "")) {
        addError(errors, "Every attestation step requires a traversal-safe fixed subject path");
      }
      if (step.with["push-to-registry"] !== "false" || step.with["show-summary"] !== "false") {
        addError(errors, "Every attestation step must disable registry push and summary output");
      }
    }
    if (step.uses) {
      const expectedInputs = contract.exactActionInputs[step.uses];
      if (!expectedInputs || canonicalObject(step.with) !== canonicalObject(expectedInputs)) {
        addError(errors, `Action inputs do not match the exact contract for ${step.uses}`);
      }
    }
  }
  for (const [action, expectedCount] of Object.entries(contract.requiredActionCounts)) {
    if (actionReferences.filter((value) => value === action).length !== expectedCount) {
      addError(errors, `Workflow action cardinality mismatch for ${action}`);
    }
  }
  for (const [command, expectedCount] of Object.entries(contract.requiredRunCounts)) {
    if (runCommands.filter((value) => value === command).length !== expectedCount) {
      addError(errors, `Workflow command cardinality mismatch for ${command}`);
    }
  }
  if (
    JSON.stringify([...new Set(actionReferences)].sort()) !==
    JSON.stringify([...new Set(contract.allowedActions)].sort())
  ) {
    addError(errors, `Workflow actions do not match its protected-base allowlist: ${file.filename}`);
  }
  if (
    JSON.stringify([...new Set(runCommands)].sort()) !==
    JSON.stringify([...new Set(contract.allowedRunCommands)].sort())
  ) {
    addError(errors, `Workflow commands do not match its protected-runtime allowlist: ${file.filename}`);
  }
}

function canonicalObject(value) {
  return JSON.stringify(Object.fromEntries(Object.entries(value ?? {}).sort(([a], [b]) => a.localeCompare(b))));
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function inspectEncodedSecrets(file, text, errors) {
  const hexCandidates = text.match(/\b[0-9a-fA-F]{48,512}\b/g) ?? [];
  for (const candidate of hexCandidates) {
    if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(candidate)) continue;
    if (candidate.length % 2 !== 0) continue;
    const decoded = Buffer.from(candidate, "hex").toString("utf8");
    if (!/^[\x20-\x7e\r\n\t]+$/.test(decoded)) continue;
    if (
      SENSITIVE_CONTENT_PATTERNS.some(({ pattern }) => pattern.test(decoded)) ||
      /\b(?:credential|token|secret|password|api[_-]?key|signing[_-]?key)\b/i.test(decoded)
    ) {
      addError(errors, `Hex-encoded sensitive credential material in ${file.filename}`);
    }
  }
  const candidates = text.match(/[A-Za-z0-9+/_-]{24,}={0,2}/g) ?? [];
  for (const candidate of candidates) {
    if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(candidate)) continue;
    if (REVIEWED_PUBLIC_HIGH_ENTROPY_TOKENS.has(candidate)) continue;
    if (candidate.length >= 32 && shannonEntropy(candidate) >= 4.5) {
      addError(errors, `Encoded or high-entropy public text in ${file.filename}`);
    }
    const normalized = candidate.replace(/-/g, "+").replace(/_/g, "/");
    if (normalized.length % 4 === 1) continue;
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    let decoded;
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(padded, "base64"));
    } catch {
      continue;
    }
    if (/[^\x20-\x7e\r\n\t]/.test(decoded)) continue;
    if (
      SENSITIVE_CONTENT_PATTERNS.some(({ pattern }) => pattern.test(decoded)) ||
      /\b(?:credential|token|secret|password|api[_-]?key|signing[_-]?key)\b/i.test(decoded)
    ) {
      addError(errors, `Encoded sensitive credential material in ${file.filename}`);
    }
  }
}

function inspectJsonSchemaNode(node, pointer, file, errors) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    node.forEach((value, index) => inspectJsonSchemaNode(value, `${pointer}/${index}`, file, errors));
    return;
  }
  const isNameMap = pointer.endsWith("/properties") || pointer.endsWith("/$defs");
  const allowedKeywords = new Set([
    "$defs", "$id", "$ref", "$schema", "additionalProperties", "const", "enum", "items",
    "maximum", "maxItems", "minimum", "minItems", "pattern", "properties", "required", "title", "type",
  ]);
  if (!isNameMap) {
    for (const key of Object.keys(node)) {
      if (!allowedKeywords.has(key)) {
        addError(errors, `Unknown JSON Schema keyword ${key} at ${pointer || "/"} in ${file.filename}`);
      }
    }
    if (pointer.includes("/properties/") && Object.keys(node).length === 0) {
      addError(errors, `Empty JSON Schema property at ${pointer} in ${file.filename}`);
    }
  }
  if (Object.hasOwn(node, "properties") || node.type === "object") {
    if (
      node.type !== "object" ||
      node.additionalProperties !== false ||
      !node.properties ||
      typeof node.properties !== "object" ||
      Array.isArray(node.properties) ||
      !Array.isArray(node.required) ||
      JSON.stringify([...node.required].sort()) !== JSON.stringify(Object.keys(node.properties).sort())
    ) {
      addError(errors, `JSON Schema object is fail-open at ${pointer || "/"} in ${file.filename}`);
    }
  }
  for (const [key, value] of Object.entries(node)) {
    inspectJsonSchemaNode(value, `${pointer}/${key}`, file, errors);
  }
}

function inspectSchemaStrings(value, pointer, file, errors) {
  if (typeof value === "string") {
    const keyword = pointer.split("/").at(-1);
    if (
      ["$schema", "$id", "$ref", "pattern", "const", "title"].includes(keyword) ||
      pointer.includes("/required/")
    ) return;
    const looksEncoded = /^[A-Za-z0-9+/_-]{32,}={0,2}$/.test(value);
    if (looksEncoded || (value.length >= 32 && shannonEntropy(value) >= 4.2)) {
      addError(errors, `Encoded or high-entropy JSON Schema text at ${pointer} in ${file.filename}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => inspectSchemaStrings(entry, `${pointer}/${index}`, file, errors));
  } else if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      inspectSchemaStrings(entry, `${pointer}/${key}`, file, errors);
    }
  }
}

function schemaSubsetMatches(actual, expected) {
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && JSON.stringify(actual) === JSON.stringify(expected);
  }
  if (expected && typeof expected === "object") {
    return (
      actual &&
      typeof actual === "object" &&
      !Array.isArray(actual) &&
      Object.entries(expected).every(([key, value]) => schemaSubsetMatches(actual[key], value))
    );
  }
  return actual === expected;
}

function inspectSchemaProfile(file, parsed, contract, errors) {
  const sha256 = { type: "string", pattern: "^[0-9a-f]{64}$" };
  const gitSha = { type: "string", pattern: "^[0-9a-f]{40}$" };
  const canonicalUtc = {
    type: "string",
    pattern: "^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$",
  };
  const ref = (name) => ({ $ref: `#/$defs/${name}` });
  const expected = { schemaVersion: { const: `bury-p1-${contract.schemaProfile}-v2` } };

  if (contract.schemaProfile === "attestation-manifest-v2") {
    expected.schemaVersion = { const: "bury-p1-attestation-manifest-v2" };
    Object.assign(expected, {
      recordId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
      trustModel: { const: "BURY-P1-MODE-A-GITHUB-ATTESTATION-SINGLE-OWNER-V2" },
      repository: { const: "AlexM999911/singingattitude-release-attestations" },
      authorization: {
        type: "object",
        additionalProperties: false,
        properties: {
          authorizationId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
          oneUse: { const: true },
          p1Authorized: { const: true },
          g2Authorized: { const: false },
          productionBookingAuthorized: { const: false },
        },
      },
      candidate: {
        type: "object",
        additionalProperties: false,
        properties: {
          commit: ref("gitSha"),
          tree: ref("gitSha"),
          pathListSha256: ref("sha256"),
          contentLedgerSha256: ref("sha256"),
          completeBundleSha256: ref("sha256"),
          migrationLedgerSha256: ref("sha256"),
        },
      },
      target: {
        type: "object",
        additionalProperties: false,
        properties: {
          profile: { const: "isolated-localhost-disposable-v1" },
          reference: { type: "string", pattern: "^local-supabase://[a-z0-9-]{8,96}$" },
          nonProduction: { const: true },
          noCustomerData: { const: true },
          exclusiveLocalhost: { const: true },
        },
      },
      executionWindow: ref("window"),
      migrations: {
        type: "array",
        minItems: 1,
        maxItems: 16,
        items: {
          type: "object",
          additionalProperties: false,
          properties: {
            order: { type: "integer", minimum: 1, maximum: 16 },
            path: {
              type: "string",
              pattern: "^(tests/sql/bury-acuity-authority/(?:00_baseline|10_p1_noncustomer_identity_approval)\\.sql|supabase/migrations/[0-9]{14}_[a-z0-9_]+\\.sql)$",
            },
            sha256: ref("sha256"),
          },
        },
      },
      owner: ref("owner"),
      boundaries: {
        type: "object",
        additionalProperties: false,
        properties: Object.fromEntries(
          ["production", "providers", "payments", "email", "deployment", "publicBooking", "g2"].map((key) => [key, { const: false }]),
        ),
      },
    });
  } else if (contract.schemaProfile === "owner-authorization-v2") {
    expected.schemaVersion = { const: "BURY_P1_OWNER_AUTHORIZATION_V2" };
    Object.assign(expected, {
      ownerIdentity: ref("owner"),
      candidateCommit: ref("gitSha"), candidateTree: ref("gitSha"), manifestSha256: ref("sha256"),
      migrationHashes: {
        type: "array", minItems: 1, maxItems: 16,
        items: { type: "object", additionalProperties: false, properties: {
          order: { type: "integer", minimum: 1, maximum: 16 },
          path: { type: "string", pattern: "^(tests/sql/bury-acuity-authority/(?:00_baseline|10_p1_noncustomer_identity_approval)\\.sql|supabase/migrations/[0-9]{14}_[a-z0-9_]+\\.sql)$" },
          sha256: ref("sha256"),
        } },
      },
      executionWindow: ref("window"), recoveryOwner: ref("owner"), rollbackAuthority: ref("owner"),
      oneUse: { const: true }, g2Authorized: { const: false }, productionBookingAuthorized: { const: false },
    });
  } else if (contract.schemaProfile === "consumption-claim-v2") {
    expected.schemaVersion = { const: "bury-p1-consumption-claim-v2" };
    Object.assign(expected, {
      authorizationId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
      repository: { const: "AlexM999911/singingattitude-release-attestations" },
      claimTag: { type: "string", pattern: "^bury-p1-consumed/BURY-P1-[A-Z0-9-]{8,120}$" },
      manifestSha256: ref("sha256"),
      attestationBundleSha256: ref("sha256"),
      candidateCommit: ref("gitSha"),
      ownerAuthorizationSha256: ref("sha256"),
      executionWindow: ref("window"),
      workflowRun: ref("workflowRun"),
      oneUse: { const: true },
      p1Authorized: { const: true },
      g2Authorized: { const: false },
      productionBookingAuthorized: { const: false },
      issuedAtUtc: ref("canonicalUtc"),
    });
  } else if (contract.schemaProfile === "verification-receipt-v2") {
    expected.schemaVersion = { const: "bury-p1-verification-receipt-v2" };
    Object.assign(expected, {
      recordId: { type: "string", pattern: "^BURY-P1-[A-Z0-9-]{8,120}$" },
      result: { const: "PASS" },
      verifiedAtUtc: ref("canonicalUtc"),
      repository: { const: "AlexM999911/singingattitude-release-attestations" },
      candidateCommit: ref("gitSha"),
      manifestSha256: ref("sha256"),
      attestationBundleSha256: ref("sha256"),
      ownerAuthorizationSha256: ref("sha256"),
      claim: {
        type: "object",
        additionalProperties: false,
        properties: {
          tag: { type: "string", pattern: "^bury-p1-consumed/BURY-P1-[A-Z0-9-]{8,120}$" },
          claimSha256: ref("sha256"),
        },
      },
      finalizerWorkflowRun: ref("workflowRun"),
      checks: { type: "object", additionalProperties: false },
      authorityGrants: { type: "array", maxItems: 0 },
    });
  } else {
    addError(errors, `Unknown protected JSON Schema profile: ${contract.schemaProfile}`);
    return;
  }

  for (const [key, spec] of Object.entries(expected)) {
    if (!schemaSubsetMatches(parsed.properties?.[key], spec)) {
      addError(errors, `JSON Schema semantic contract mismatch for property ${key} in ${file.filename}`);
    }
  }
  const requiredDefs = ["sha256", "gitSha", "canonicalUtc"];
  if (["attestation-manifest-v2", "owner-authorization-v2", "consumption-claim-v2"].includes(contract.schemaProfile)) {
    requiredDefs.push("window");
  }
  if (["attestation-manifest-v2", "owner-authorization-v2"].includes(contract.schemaProfile)) requiredDefs.push("owner");
  if (["consumption-claim-v2", "verification-receipt-v2"].includes(contract.schemaProfile)) requiredDefs.push("workflowRun");
  if (JSON.stringify(Object.keys(parsed.$defs ?? {}).sort()) !== JSON.stringify(requiredDefs.sort())) {
    addError(errors, `JSON Schema definitions do not match its profile in ${file.filename}`);
  }
  if (!schemaSubsetMatches(parsed.$defs?.sha256, sha256)) addError(errors, `JSON Schema sha256 format is unsafe in ${file.filename}`);
  if (!schemaSubsetMatches(parsed.$defs?.gitSha, gitSha)) addError(errors, `JSON Schema git SHA format is unsafe in ${file.filename}`);
  if (!schemaSubsetMatches(parsed.$defs?.canonicalUtc, canonicalUtc)) addError(errors, `JSON Schema UTC format is unsafe in ${file.filename}`);
  if (requiredDefs.includes("window")) {
    const window = {
      type: "object",
      additionalProperties: false,
      properties: { startsAtUtc: ref("canonicalUtc"), expiresAtUtc: ref("canonicalUtc") },
    };
    if (!schemaSubsetMatches(parsed.$defs?.window, window)) {
      addError(errors, `JSON Schema execution window is unsafe in ${file.filename}`);
    }
  }
  if (requiredDefs.includes("owner")) {
    const owner = { type: "object", additionalProperties: false, properties: {
      githubLogin: { const: "AlexM999911" }, githubAccountId: { const: "234956861" },
      businessOwner: { const: true }, technicalOwner: { const: true },
    } };
    if (!schemaSubsetMatches(parsed.$defs?.owner, owner)) addError(errors, `JSON Schema owner identity is unsafe in ${file.filename}`);
  }
  if (requiredDefs.includes("workflowRun")) {
    const workflowRun = { type: "object", additionalProperties: false, properties: {
      repository: { const: "AlexM999911/singingattitude-release-attestations" },
      workflow: { const: ".github/workflows/bury-p1-one-use-consumption.yml" }, ref: { const: "refs/heads/main" },
      sha: ref("gitSha"), runId: { type: "string", pattern: "^[1-9][0-9]{0,19}$" },
      runAttempt: { type: "string", pattern: "^[1-9][0-9]{0,9}$" }, actor: { const: "AlexM999911" }, actorId: { const: "234956861" },
    } };
    if (!schemaSubsetMatches(parsed.$defs?.workflowRun, workflowRun)) addError(errors, `JSON Schema workflow identity is unsafe in ${file.filename}`);
  }
}

function inspectJson(file, text, policy, errors) {
  const contract = policy.approvedJsonContracts[file.filename];
  if (!contract) {
    addError(errors, `JSON path is not explicitly base-authorized by an exact contract: ${file.filename}`);
    return;
  }
  if (!exactKeys(contract, ["requiredRootProperties", "requiredTrueCheckProperties", "schemaId", "schemaProfile"])) {
    addError(errors, `JSON contract is malformed for ${file.filename}`);
    return;
  }
  if (
    typeof contract.schemaId !== "string" ||
    typeof contract.schemaProfile !== "string" ||
    !Array.isArray(contract.requiredRootProperties) ||
    !contract.requiredRootProperties.every((key) => typeof key === "string") ||
    !Array.isArray(contract.requiredTrueCheckProperties) ||
    !contract.requiredTrueCheckProperties.every((key) => typeof key === "string")
  ) {
    addError(errors, `JSON contract is malformed for ${file.filename}`);
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    addError(errors, `Invalid JSON in ${file.filename}`);
    return;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    addError(errors, `JSON root must be an object in ${file.filename}`);
    return;
  }
  const allowedSchemaKeys = [
    "$defs",
    "$id",
    "$schema",
    "additionalProperties",
    "properties",
    "required",
    "title",
    "type",
  ];
  if (JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(allowedSchemaKeys.sort())) {
    addError(errors, `JSON Schema top-level keys do not match the closed contract: ${file.filename}`);
  }
  if (
    parsed.$schema !== "https://json-schema.org/draft/2020-12/schema" ||
    parsed.$id !== contract.schemaId ||
    parsed.type !== "object" ||
    parsed.additionalProperties !== false ||
    !parsed.properties ||
    typeof parsed.properties !== "object" ||
    Array.isArray(parsed.properties) ||
    JSON.stringify(Object.keys(parsed.properties).sort()) !==
      JSON.stringify([...contract.requiredRootProperties].sort()) ||
    JSON.stringify([...(parsed.required ?? [])].sort()) !==
      JSON.stringify([...contract.requiredRootProperties].sort())
  ) {
    addError(errors, `JSON Schema root does not match its immutable path contract: ${file.filename}`);
  }
  for (const [key, propertySchema] of Object.entries(parsed.properties ?? {})) {
    if (
      !propertySchema ||
      typeof propertySchema !== "object" ||
      Array.isArray(propertySchema) ||
      Object.keys(propertySchema).length === 0 ||
      !["type", "$ref", "const", "enum"].some((schemaKey) => Object.hasOwn(propertySchema, schemaKey))
    ) {
      addError(errors, `JSON Schema property lacks a closed type, format, const, enum, or ref: ${key}`);
    }
  }
  if (contract.requiredTrueCheckProperties.length > 0) {
    const checks = parsed.properties?.checks;
    if (
      checks?.type !== "object" ||
      checks.additionalProperties !== false ||
      JSON.stringify(Object.keys(checks.properties ?? {}).sort()) !==
        JSON.stringify([...contract.requiredTrueCheckProperties].sort()) ||
      JSON.stringify([...(checks.required ?? [])].sort()) !==
        JSON.stringify([...contract.requiredTrueCheckProperties].sort()) ||
      contract.requiredTrueCheckProperties.some((key) => checks.properties?.[key]?.const !== true)
    ) {
      addError(errors, `Verification checks must be closed and const true in ${file.filename}`);
    }
  }
  inspectJsonSchemaNode(parsed, "", file, errors);
  inspectSchemaProfile(file, parsed, contract, errors);
  inspectSchemaStrings(parsed, "", file, errors);
}

function decodeTextBlob(file, blob, errors) {
  if (blob?.encoding !== "base64" || typeof blob.content !== "string") {
    addError(errors, `Missing or unsupported blob for ${file.filename}`);
    return null;
  }

  const compact = blob.content.replace(/\s/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
    addError(errors, `Malformed base64 blob for ${file.filename}`);
    return null;
  }

  const bytes = Buffer.from(compact, "base64");
  if (blob.size !== bytes.length) {
    addError(errors, `Blob size mismatch for ${file.filename}`);
    return null;
  }

  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
      addError(errors, `Binary blob prohibited for ${file.filename}`);
      return null;
    }
    return { text, bytes: bytes.length };
  } catch {
    addError(errors, `Blob is not valid UTF-8 text: ${file.filename}`);
    return null;
  }
}

function inspectContent(file, text, policy, errors) {
  for (const { name, pattern } of SENSITIVE_CONTENT_PATTERNS) {
    if (pattern.test(text)) {
      addError(errors, `Sensitive or PII pattern (${name}) in ${file.filename}`);
    }
  }
  inspectEncodedSecrets(file, text, errors);

  if (file.filename.startsWith("schemas/") && file.filename.endsWith(".json")) {
    inspectJson(file, text, policy, errors);
  } else if (file.filename.endsWith(".json")) {
    try {
      const value = JSON.parse(text);
      if (!value || typeof value !== "object" || Array.isArray(value)) addError(errors, `Public data JSON root must be an object: ${file.filename}`);
    } catch {
      addError(errors, `Invalid public data JSON: ${file.filename}`);
    }
  }

  if (file.filename.startsWith(".github/workflows/")) {
    inspectWorkflow(file, text, policy, errors);
  }
}

export function validatePullRequestSnapshot(input) {
  const errors = [];
  const decodedFiles = new Map();

  if (!input || typeof input !== "object") {
    return { ok: false, errors: ["Validator input is missing"] };
  }

  const {
    expectedRepository,
    event,
    compare,
    headCommit,
    tree,
    blobs,
    policy,
  } = input;
  const pullRequest = event?.pull_request;
  const repositoryNames = [
    event?.repository?.full_name,
    pullRequest?.base?.repo?.full_name,
    pullRequest?.head?.repo?.full_name,
  ];

  if (
    typeof expectedRepository !== "string" ||
    repositoryNames.some((name) => name !== expectedRepository)
  ) {
    addError(errors, "Repository mismatch or forked pull request");
  }
  if (pullRequest?.base?.ref !== "main") {
    addError(errors, "Trusted validation is restricted to pull requests targeting main");
  }
  if (!SHA_PATTERN.test(pullRequest?.base?.sha ?? "")) {
    addError(errors, "Invalid protected base SHA");
  }
  if (
    !SHA_PATTERN.test(pullRequest?.head?.sha ?? "") ||
    headCommit?.sha !== pullRequest?.head?.sha
  ) {
    addError(errors, "Head commit does not match the pull request head SHA");
  }

  const compareFiles = Array.isArray(compare?.files) ? compare.files : [];
  if (
    !Number.isInteger(pullRequest?.changed_files) ||
    pullRequest.changed_files !== compareFiles.length
  ) {
    addError(errors, "Changed-file count does not match the complete comparison");
  }
  if (tree?.truncated !== false || !Array.isArray(tree?.tree)) {
    addError(errors, "Head Git tree is missing or truncated");
  }

  if (
    !policy ||
    !Number.isInteger(policy.maxChangedFiles) ||
    !Number.isInteger(policy.maxFileBytes) ||
    !Number.isInteger(policy.maxTotalBytes) ||
    !Array.isArray(policy.protectedPaths) ||
    !Array.isArray(policy.allowedPathPatterns) ||
    !Array.isArray(policy.reservedWorkflowPaths) ||
    !policy.approvedWorkflowContracts ||
    typeof policy.approvedWorkflowContracts !== "object" ||
    Array.isArray(policy.approvedWorkflowContracts) ||
    !policy.approvedJsonContracts ||
    typeof policy.approvedJsonContracts !== "object" ||
    Array.isArray(policy.approvedJsonContracts)
  ) {
    return { ok: false, errors: [...errors, "Trusted policy is malformed"] };
  }

  if (compareFiles.length > policy.maxChangedFiles) {
    addError(errors, `Changed-file count exceeds ${policy.maxChangedFiles}`);
  }

  const protectedPaths = new Set(policy.protectedPaths);
  const allowedPathPatterns = policy.allowedPathPatterns.map((pattern) => new RegExp(pattern));
  const treeByPath = new Map((tree?.tree ?? []).map((entry) => [entry.path, entry]));
  let totalBytes = 0;

  for (const file of compareFiles) {
    if (typeof file?.filename !== "string" || !SAFE_PATH_PATTERN.test(file.filename)) {
      addError(errors, `Unsafe changed path: ${String(file?.filename)}`);
      continue;
    }
    if (protectedPaths.has(file.filename)) {
      errors.push(`PR changes trusted baseline path: ${file.filename}`);
      continue;
    }
    if (!allowedPathPatterns.some((pattern) => pattern.test(file.filename))) {
      addError(errors, `Unknown or prohibited path: ${file.filename}`);
      continue;
    }
    if (!new Set(["added", "modified"]).has(file.status)) {
      addError(errors, `Removed, renamed, or unsupported path status for ${file.filename}`);
      continue;
    }

    const entry = treeByPath.get(file.filename);
    if (!entry) {
      addError(errors, `Changed path is missing from the head Git tree: ${file.filename}`);
      continue;
    }
    if (entry.type !== "blob" || entry.mode !== "100644") {
      addError(
        errors,
        `Symlink, submodule, executable, or unsupported Git type/mode for ${file.filename}`,
      );
      continue;
    }
    if (entry.sha !== file.sha || !SHA_PATTERN.test(entry.sha ?? "")) {
      addError(errors, `Comparison and Git tree blob mismatch for ${file.filename}`);
      continue;
    }
    if (!Number.isInteger(entry.size) || entry.size < 0 || entry.size > policy.maxFileBytes) {
      addError(errors, `File size exceeds policy for ${file.filename}`);
      continue;
    }

    const decoded = decodeTextBlob(file, blobs?.[entry.sha], errors);
    if (!decoded) continue;
    if (decoded.bytes !== entry.size) {
      addError(errors, `Git tree and blob size mismatch for ${file.filename}`);
      continue;
    }
    totalBytes += decoded.bytes;
    decodedFiles.set(file.filename, decoded.text);
    inspectContent(file, decoded.text, policy, errors);
  }

  const releasePaths = {
    manifest: "manifests/bury-p1-reviewed.json",
    completeBundle: "manifests/bury-p1-reviewed-complete-bundle.json",
    contentLedger: "manifests/bury-p1-reviewed-content-ledger.json",
    candidateTree: "manifests/bury-p1-reviewed-candidate-tree.json",
    ownerAuthorization: "authorizations/bury-p1-owner-authorization.json",
    ownerAuthorizationSidecar: "authorizations/bury-p1-owner-authorization.sha256",
  };
  const releaseChanged = Object.values(releasePaths).some((path) => decodedFiles.has(path));
  if (releaseChanged) {
    const missing = Object.values(releasePaths).filter((path) => !decodedFiles.has(path));
    if (missing.length > 0) {
      addError(errors, `Release data must change as one complete cross-record bundle; missing: ${missing.join(", ")}`);
    } else {
      try {
        const read = (path) => JSON.parse(decodedFiles.get(path));
        const manifest = read(releasePaths.manifest);
        const ownerAuthorizationBytes = decodedFiles.get(releasePaths.ownerAuthorization);
        validateReleaseBundle({
          manifest,
          ownerAuthorization: JSON.parse(ownerAuthorizationBytes),
          ownerAuthorizationBytes,
          ownerAuthorizationSha256Sidecar: decodedFiles.get(releasePaths.ownerAuthorizationSidecar),
          completeBundle: read(releasePaths.completeBundle),
          contentLedger: read(releasePaths.contentLedger),
          candidateTree: read(releasePaths.candidateTree),
          now: manifest?.executionWindow?.startsAtUtc,
          documentsOnly: true,
        });
      } catch (error) {
        addError(errors, error instanceof Error ? error.message : "Release cross-record validation failed");
      }
    }
  }

  if (totalBytes > policy.maxTotalBytes) {
    addError(errors, `Total changed bytes exceed ${policy.maxTotalBytes}`);
  }

  return { ok: errors.length === 0, errors };
}
