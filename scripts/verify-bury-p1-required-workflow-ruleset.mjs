import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const REPOSITORY = "AlexM999911/singingattitude-release-attestations";
const WORKFLOW_PATH = ".github/workflows/bury-p1-trusted-pr-validation.yml";
const ACTIVATION_WORKFLOW_PATH = ".github/workflows/bury-p1-activation-probe.yml";
const ACTIVATION_SCRIPT_PATH = "scripts/run-bury-p1-activation-probe.mjs";
const SHA = /^[0-9a-f]{40}$/;

function fail(message) {
  throw new Error(`Required-workflow provenance verification failed: ${message}`);
}

export function verifyRequiredWorkflowRuleset({
  repositoryId,
  workflowSha,
  previousWorkflowSha,
  transitionState = "steady",
  repositoryReadback,
  branchReadback,
  commitReadback,
  workflowTreeReadback,
  workflowContentReadback,
  activationWorkflowContentReadback,
  activationScriptContentReadback,
  rulesetReadback,
}) {
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1 || !SHA.test(workflowSha ?? "")) fail("expected repository/SHA inputs");
  if (!["steady", "dual", "final"].includes(transitionState)) fail("unknown workflow transition state");
  if (["dual", "final"].includes(transitionState) && (!SHA.test(previousWorkflowSha ?? "") || previousWorkflowSha === workflowSha)) fail("transition requires a distinct previous workflow SHA");
  if (repositoryReadback?.id !== repositoryId || repositoryReadback?.full_name !== REPOSITORY || repositoryReadback?.default_branch !== "main") fail("repository identity/default-main provenance");
  if (branchReadback?.name !== "main" || branchReadback?.commit?.sha !== workflowSha || branchReadback?.protected !== true) fail("workflow SHA is not the protected main head");
  if (commitReadback?.sha !== workflowSha || !SHA.test(commitReadback?.commit?.tree?.sha ?? "") || workflowTreeReadback?.sha !== commitReadback.commit.tree.sha || workflowTreeReadback?.truncated !== false) fail("merged main commit/tree provenance");
  const protectedBlobs = [
    [WORKFLOW_PATH, workflowContentReadback],
    [ACTIVATION_WORKFLOW_PATH, activationWorkflowContentReadback],
    [ACTIVATION_SCRIPT_PATH, activationScriptContentReadback],
  ];
  for (const [path, content] of protectedBlobs) {
    if (content?.path !== path || content?.type !== "file" || !SHA.test(content?.sha ?? "")) fail(`protected blob read-back for ${path}`);
    const matches = (workflowTreeReadback.tree ?? []).filter((entry) => entry?.path === path && entry?.mode === "100644" && entry?.type === "blob" && entry?.sha === content.sha);
    if (matches.length !== 1) fail(`protected blob is not in the exact merged commit tree: ${path}`);
  }
  if (rulesetReadback?.source_type !== "Repository" || rulesetReadback?.source !== REPOSITORY || rulesetReadback?.target !== "branch" || rulesetReadback?.enforcement !== "active") fail("ruleset source/enforcement provenance");
  if (!Array.isArray(rulesetReadback?.bypass_actors) || rulesetReadback.bypass_actors.length !== 0) fail("ruleset bypass actors must be visibly empty");
  if (JSON.stringify(rulesetReadback?.conditions?.ref_name) !== JSON.stringify({ include: ["refs/heads/main"], exclude: [] })) fail("ruleset must target only protected main ref");
  const workflowRules = (rulesetReadback.rules ?? []).filter((rule) => rule?.type === "workflows");
  if (workflowRules.length !== 1 || workflowRules[0]?.parameters?.do_not_enforce_on_create !== false) fail("exactly one enforced workflows rule is required");
  const matches = (workflowRules[0].parameters.workflows ?? []).filter((workflow) =>
    workflow?.path === WORKFLOW_PATH &&
    workflow?.ref === "refs/heads/main" &&
    workflow?.repository_id === repositoryId &&
    workflow?.sha === workflowSha
  );
  if (matches.length !== 1) fail("exact path/ref/repository/SHA workflow provenance");
  const previousMatches = (workflowRules[0].parameters.workflows ?? []).filter((workflow) =>
    workflow?.path === WORKFLOW_PATH && workflow?.ref === "refs/heads/main" && workflow?.repository_id === repositoryId && workflow?.sha === previousWorkflowSha
  );
  if (transitionState === "dual" && previousMatches.length !== 1) fail("dual transition does not retain the exact previous workflow SHA");
  if (transitionState === "final" && previousMatches.length !== 0) fail("final transition still contains the previous workflow SHA");
  if (transitionState === "steady" && (workflowRules[0].parameters.workflows ?? []).filter((workflow) => workflow?.path === WORKFLOW_PATH).length !== 1) fail("steady ruleset contains ambiguous trusted workflow entries");
  return {
    ok: true,
    repositoryId,
    workflowSha,
    transitionState,
    workflowBlobSha: workflowContentReadback.sha,
    activationWorkflowBlobSha: activationWorkflowContentReadback.sha,
    activationScriptBlobSha: activationScriptContentReadback.sha,
  };
}

export function verifyImmutableConsumptionTagRuleset(value) {
  if (value?.target !== "tag" || value?.enforcement !== "active" || !Array.isArray(value?.bypass_actors) || value.bypass_actors.length !== 0) fail("immutable tag ruleset target/enforcement/bypass");
  if (JSON.stringify(value?.conditions?.ref_name) !== JSON.stringify({ include: ["refs/tags/bury-p1-consumed/*", "refs/tags/bury-p1-receipted/*"], exclude: [] })) fail("immutable claim/receipt tag ref conditions");
  const types = (value.rules ?? []).map((rule) => rule?.type).sort();
  if (JSON.stringify(types) !== JSON.stringify(["deletion", "update"])) fail("immutable tag rules must contain exactly update and deletion");
  if (value.rules.find((rule) => rule.type === "update")?.parameters?.update_allows_fetch_and_merge !== false) fail("tag update rule is fail-open");
  return { ok: true };
}

export function verifyRestrictedConsumptionTagCreationRuleset(value) {
  if (value?.target !== "tag" || value?.enforcement !== "active") fail("tag creation ruleset target/enforcement");
  if (JSON.stringify(value?.bypass_actors) !== JSON.stringify([{ actor_id: 15368, actor_type: "Integration", bypass_mode: "always" }])) fail("tag creation must be bypassable only by the GitHub Actions integration");
  if (JSON.stringify(value?.conditions?.ref_name) !== JSON.stringify({ include: ["refs/tags/bury-p1-consumed/*", "refs/tags/bury-p1-receipted/*"], exclude: [] })) fail("tag creation namespace conditions");
  if (JSON.stringify((value.rules ?? []).map((rule) => rule?.type)) !== JSON.stringify(["creation"])) fail("tag creation ruleset must contain only creation restriction");
  return { ok: true };
}

function verifyRulesetProvenance(value, { id, name }) {
  if (!Number.isSafeInteger(id) || id < 1 || value?.id !== id || value?.name !== name || value?.source_type !== "Repository" || value?.source !== REPOSITORY) fail(`tag ruleset ${name} repository/source/ID provenance`);
}

function verifyRuleSuite(suite, { repositoryId, ref, actor, result, rulesetId, ruleType, ruleResult }) {
  if (!Number.isSafeInteger(actor) || actor < 1 || !Number.isSafeInteger(suite?.id) || suite.id < 1 || suite.repository_id !== repositoryId || suite.repository_name !== "singingattitude-release-attestations" || suite.ref !== ref || suite.actor_id !== actor || suite.result !== result || suite.evaluation_result !== "fail") fail(`rule-suite identity/outcome mismatch for ${ref}`);
  const matches = (suite.rule_evaluations ?? []).filter((evaluation) =>
    evaluation?.rule_source?.type === "ruleset" && evaluation?.rule_source?.id === rulesetId && evaluation?.enforcement === "active" && evaluation?.rule_type === ruleType && evaluation?.result === ruleResult
  );
  if (matches.length !== 1) fail(`rule-suite does not prove ${ruleType}/${ruleResult} from exact ruleset ${rulesetId}`);
}

export function verifyTagRulesetActivation({
  repositoryId,
  creationRulesetId,
  immutabilityRulesetId,
  creationRulesetReadback,
  immutabilityRulesetReadback,
  actionsCreationRuleSuite,
  ordinaryCreationRuleSuite,
  updateRuleSuite,
  deletionRuleSuite,
}) {
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1) fail("tag activation repository ID");
  verifyRulesetProvenance(creationRulesetReadback, { id: creationRulesetId, name: "bury-p1 workflow-only consumption tag creation" });
  verifyRulesetProvenance(immutabilityRulesetReadback, { id: immutabilityRulesetId, name: "bury-p1 immutable consumption records" });
  verifyRestrictedConsumptionTagCreationRuleset(creationRulesetReadback);
  verifyImmutableConsumptionTagRuleset(immutabilityRulesetReadback);
  verifyRuleSuite(actionsCreationRuleSuite, { repositoryId, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor: 15368, result: "bypass", rulesetId: creationRulesetId, ruleType: "creation", ruleResult: "fail" });
  if (ordinaryCreationRuleSuite?.actor_id === 15368) fail("ordinary-writer creation probe used the authorized integration");
  verifyRuleSuite(ordinaryCreationRuleSuite, { repositoryId, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-WRITER", actor: ordinaryCreationRuleSuite?.actor_id, result: "fail", rulesetId: creationRulesetId, ruleType: "creation", ruleResult: "fail" });
  verifyRuleSuite(updateRuleSuite, { repositoryId, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor: 15368, result: "fail", rulesetId: immutabilityRulesetId, ruleType: "update", ruleResult: "fail" });
  verifyRuleSuite(deletionRuleSuite, { repositoryId, ref: "refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS", actor: 15368, result: "fail", rulesetId: immutabilityRulesetId, ruleType: "deletion", ruleResult: "fail" });
  return { ok: true, repositoryId, creationRulesetId, immutabilityRulesetId };
}

export function main({ env = process.env, readFileFn = readFileSync } = {}) {
  const required = ["REPOSITORY_READBACK_PATH", "BRANCH_READBACK_PATH", "COMMIT_READBACK_PATH", "WORKFLOW_TREE_READBACK_PATH", "WORKFLOW_CONTENT_READBACK_PATH", "ACTIVATION_WORKFLOW_CONTENT_READBACK_PATH", "ACTIVATION_SCRIPT_CONTENT_READBACK_PATH", "RULESET_READBACK_PATH", "REPOSITORY_ID", "WORKFLOW_SHA", "TAG_CREATION_RULESET_ID", "TAG_IMMUTABILITY_RULESET_ID", "TAG_CREATION_RULESET_PATH", "TAG_IMMUTABILITY_RULESET_PATH", "ACTIONS_CREATION_RULE_SUITE_PATH", "ORDINARY_CREATION_RULE_SUITE_PATH", "UPDATE_RULE_SUITE_PATH", "DELETION_RULE_SUITE_PATH"];
  for (const key of required) if (!env[key]) fail(`${key} is required`);
  const readJson = (path) => JSON.parse(readFileFn(path, "utf8"));
  const result = verifyRequiredWorkflowRuleset({
    repositoryId: Number(env.REPOSITORY_ID),
    workflowSha: env.WORKFLOW_SHA,
    previousWorkflowSha: env.PREVIOUS_WORKFLOW_SHA || undefined,
    transitionState: env.TRANSITION_STATE || "steady",
    repositoryReadback: readJson(env.REPOSITORY_READBACK_PATH),
    branchReadback: readJson(env.BRANCH_READBACK_PATH),
    commitReadback: readJson(env.COMMIT_READBACK_PATH),
    workflowTreeReadback: readJson(env.WORKFLOW_TREE_READBACK_PATH),
    workflowContentReadback: readJson(env.WORKFLOW_CONTENT_READBACK_PATH),
    activationWorkflowContentReadback: readJson(env.ACTIVATION_WORKFLOW_CONTENT_READBACK_PATH),
    activationScriptContentReadback: readJson(env.ACTIVATION_SCRIPT_CONTENT_READBACK_PATH),
    rulesetReadback: readJson(env.RULESET_READBACK_PATH),
  });
  const tagResult = verifyTagRulesetActivation({
    repositoryId: Number(env.REPOSITORY_ID),
    creationRulesetId: Number(env.TAG_CREATION_RULESET_ID),
    immutabilityRulesetId: Number(env.TAG_IMMUTABILITY_RULESET_ID),
    creationRulesetReadback: readJson(env.TAG_CREATION_RULESET_PATH),
    immutabilityRulesetReadback: readJson(env.TAG_IMMUTABILITY_RULESET_PATH),
    actionsCreationRuleSuite: readJson(env.ACTIONS_CREATION_RULE_SUITE_PATH),
    ordinaryCreationRuleSuite: readJson(env.ORDINARY_CREATION_RULE_SUITE_PATH),
    updateRuleSuite: readJson(env.UPDATE_RULE_SUITE_PATH),
    deletionRuleSuite: readJson(env.DELETION_RULE_SUITE_PATH),
  });
  const combined = { ok: true, workflow: result, tags: tagResult };
  process.stdout.write(`${JSON.stringify(combined)}\n`);
  return combined;
}

if ((process.argv[1] ? pathToFileURL(process.argv[1]).href : "") === import.meta.url) {
  try { main(); } catch (error) {
    console.error(error instanceof Error ? error.message : "Ruleset verification failed");
    process.exitCode = 1;
  }
}
