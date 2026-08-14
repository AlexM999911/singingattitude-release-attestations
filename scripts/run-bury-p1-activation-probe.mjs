import { pathToFileURL } from "node:url";

const REPOSITORY = "AlexM999911/singingattitude-release-attestations";
const REPOSITORY_ID = 1331425769;
const API = `https://api.github.com/repos/${REPOSITORY}/git`;
const TAG = "bury-p1-consumed/ACTIVATION-PROBE-ACTIONS";
const REF = `refs/tags/${TAG}`;
const SHA = /^[0-9a-f]{40}$/;

function fail(message) { throw new Error(`Bury P1 activation probe failed: ${message}`); }

export async function runActivationProbe({ token, workflowSha, repository, repositoryId, fetchFn = fetch }) {
  if (repository !== REPOSITORY || repositoryId !== REPOSITORY_ID) fail("fixed repository identity mismatch");
  if (!SHA.test(workflowSha ?? "")) fail("workflow SHA must be exact");
  if (typeof token !== "string" || token.length < 20) fail("ephemeral GitHub token is required");
  const request = async (method, path, body) => {
    const allowed = new Set(["/tags", "/refs", `/refs/tags/${TAG}`]);
    if (!allowed.has(path) || !["POST", "PATCH", "DELETE"].includes(method)) fail("request escaped the fixed activation-probe API surface");
    const response = await fetchFn(`${API}${path}`, {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2026-03-10",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    let value = null;
    try { value = await response.json(); } catch { /* A denial may not include JSON. */ }
    return { status: response.status, value };
  };

  const tagObject = await request("POST", "/tags", {
    tag: TAG,
    message: "Bury P1 activation probe; this tag grants no release authority.",
    object: workflowSha,
    type: "commit",
  });
  if (tagObject.status !== 201 || !SHA.test(tagObject.value?.sha ?? "")) fail(`annotated probe tag creation returned ${tagObject.status}`);
  const creation = await request("POST", "/refs", { ref: REF, sha: tagObject.value.sha });
  if (creation.status !== 201 || creation.value?.ref !== REF) fail(`probe ref creation was not allowed for Actions integration: ${creation.status}`);

  const update = await request("PATCH", `/refs/tags/${TAG}`, { sha: workflowSha, force: true });
  const deletion = await request("DELETE", `/refs/tags/${TAG}`);
  if (update.status >= 200 && update.status < 300) fail("immutable probe ref update unexpectedly succeeded");
  if (deletion.status >= 200 && deletion.status < 300) fail("immutable probe ref deletion unexpectedly succeeded");
  if (![403, 409, 422].includes(update.status) || ![403, 409, 422].includes(deletion.status)) fail("probe denial status was not a GitHub ruleset rejection");

  return {
    schemaVersion: "bury-p1-activation-probe-correlation-v1",
    repository: REPOSITORY,
    repositoryId: REPOSITORY_ID,
    ref: REF,
    workflowSha,
    creationStatus: creation.status,
    updateStatus: update.status,
    deletionStatus: deletion.status,
    ruleSuiteReadback: "REQUIRES_EXTERNAL_ADMINISTRATION_READ",
  };
}

export async function main({ env = process.env, fetchFn = fetch } = {}) {
  if (env.GITHUB_EVENT_NAME !== "workflow_dispatch" || env.GITHUB_REF !== "refs/heads/main" || env.GITHUB_WORKFLOW_REF !== `${REPOSITORY}/.github/workflows/bury-p1-activation-probe.yml@refs/heads/main`) fail("probe must run only from its protected main workflow");
  const result = await runActivationProbe({ token: env.GH_TOKEN, workflowSha: env.GITHUB_SHA, repository: env.GITHUB_REPOSITORY, repositoryId: Number(env.GITHUB_REPOSITORY_ID), fetchFn });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result;
}

if ((process.argv[1] ? pathToFileURL(process.argv[1]).href : "") === import.meta.url) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : "Activation probe failed"); process.exitCode = 1; });
}
