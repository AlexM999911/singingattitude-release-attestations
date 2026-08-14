import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const TRUSTED_WORKFLOW_PATH = ".github/workflows/bury-p1-trusted-pr-validation.yml";
const SPOOFABLE_STATUS_CONTEXT = "bury-p1/trusted-pr-validation";

export function buildImmutableConsumptionTagRuleset() {
  return {
    name: "bury-p1 immutable consumption records",
    target: "tag",
    enforcement: "active",
    bypass_actors: [],
    conditions: {
      ref_name: {
        include: ["refs/tags/bury-p1-consumed/*", "refs/tags/bury-p1-receipted/*"],
        exclude: [],
      },
    },
    rules: [{ type: "update", parameters: { update_allows_fetch_and_merge: false } }, { type: "deletion" }],
  };
}

export function buildRestrictedConsumptionTagCreationRuleset() {
  return {
    name: "bury-p1 workflow-only consumption tag creation",
    target: "tag",
    enforcement: "active",
    bypass_actors: [{ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" }],
    conditions: {
      ref_name: {
        include: ["refs/tags/bury-p1-consumed/*", "refs/tags/bury-p1-receipted/*"],
        exclude: [],
      },
    },
    rules: [{ type: "creation" }],
  };
}

export function buildRequiredWorkflowRuleset({
  repositoryId,
  workflowSha,
  previousWorkflowSha,
  existingRuleset,
}) {
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1) {
    throw new Error("Repository ID must be a positive integer");
  }
  if (!SHA_PATTERN.test(workflowSha ?? "")) {
    throw new Error("Workflow SHA must be the exact 40-character merged commit SHA");
  }
  if (previousWorkflowSha !== undefined && (!SHA_PATTERN.test(previousWorkflowSha) || previousWorkflowSha === workflowSha)) {
    throw new Error("Previous workflow SHA must be a distinct exact 40-character commit SHA");
  }
  if (
    !existingRuleset ||
    typeof existingRuleset !== "object" ||
    typeof existingRuleset.name !== "string" ||
    existingRuleset.target !== "branch" ||
    !["active", "disabled", "evaluate"].includes(existingRuleset.enforcement) ||
    !Array.isArray(existingRuleset.bypass_actors) ||
    !existingRuleset.conditions ||
    !Array.isArray(existingRuleset.rules)
  ) {
    throw new Error("Existing ruleset read-back is malformed");
  }
  if (existingRuleset.bypass_actors.length !== 0) {
    throw new Error("Trusted workflow ruleset must not contain bypass actors");
  }
  if (
    JSON.stringify(existingRuleset.conditions.ref_name?.include) !== JSON.stringify(["refs/heads/main"]) ||
    JSON.stringify(existingRuleset.conditions.ref_name?.exclude) !== JSON.stringify([])
  ) {
    throw new Error("Trusted workflow ruleset must target only refs/heads/main");
  }

  const rules = [];
  const existingWorkflows = [];
  for (const rule of existingRuleset.rules) {
    if (rule?.type === "workflows") {
      const workflows = rule.parameters?.workflows;
      if (!Array.isArray(workflows)) throw new Error("Existing workflows rule is malformed");
      existingWorkflows.push(
        ...workflows
          .filter((workflow) => workflow?.path !== TRUSTED_WORKFLOW_PATH)
          .map((workflow) => structuredClone(workflow)),
      );
      continue;
    }
    if (rule?.type !== "required_status_checks") {
      rules.push(structuredClone(rule));
      continue;
    }
    const checks = rule.parameters?.required_status_checks;
    if (!Array.isArray(checks)) throw new Error("Existing status-check rule is malformed");
    const remaining = checks.filter((check) => check?.context !== SPOOFABLE_STATUS_CONTEXT);
    if (remaining.length === 0) continue;
    rules.push({
      ...structuredClone(rule),
      parameters: {
        ...structuredClone(rule.parameters),
        required_status_checks: remaining,
      },
    });
  }
  rules.push({
    type: "workflows",
    parameters: {
      do_not_enforce_on_create: false,
      workflows: [
        ...existingWorkflows,
        ...(previousWorkflowSha ? [{
          path: TRUSTED_WORKFLOW_PATH,
          ref: "refs/heads/main",
          repository_id: repositoryId,
          sha: previousWorkflowSha,
        }] : []),
        {
          path: TRUSTED_WORKFLOW_PATH,
          ref: "refs/heads/main",
          repository_id: repositoryId,
          sha: workflowSha,
        },
      ],
    },
  });

  return {
    name: existingRuleset.name,
    target: "branch",
    enforcement: "active",
    bypass_actors: structuredClone(existingRuleset.bypass_actors),
    conditions: structuredClone(existingRuleset.conditions),
    rules,
  };
}

export function main({ env = process.env, readFileFn = readFileSync } = {}) {
  if (!env.EXISTING_RULESET_PATH) throw new Error("EXISTING_RULESET_PATH is required");
  const payload = buildRequiredWorkflowRuleset({
    repositoryId: Number(env.REPOSITORY_ID),
    workflowSha: env.WORKFLOW_SHA,
    previousWorkflowSha: env.PREVIOUS_WORKFLOW_SHA || undefined,
    existingRuleset: JSON.parse(readFileFn(env.EXISTING_RULESET_PATH, "utf8")),
  });
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  return payload;
}

const invokedUrl = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (invokedUrl === import.meta.url) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Ruleset payload construction failed");
    process.exitCode = 1;
  }
}
