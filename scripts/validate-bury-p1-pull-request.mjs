import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { validatePullRequestSnapshot } from "./lib/bury-p1-trusted-pr-validator.mjs";

export async function collectPullRequestSnapshot({
  api,
  event,
  expectedRepository,
  policy,
}) {
  const pullRequest = event?.pull_request;
  const repositories = [
    event?.repository?.full_name,
    pullRequest?.base?.repo?.full_name,
    pullRequest?.head?.repo?.full_name,
  ];
  if (repositories.some((value) => value !== expectedRepository)) {
    throw new Error("Repository mismatch or forked pull request");
  }
  if (pullRequest?.base?.ref !== "main") {
    throw new Error("Pull request must target protected main");
  }
  if (!Number.isInteger(pullRequest?.number) || pullRequest.number < 1) {
    throw new Error("Pull request number is missing");
  }
  if (
    !Number.isInteger(pullRequest?.changed_files) ||
    pullRequest.changed_files < 0 ||
    pullRequest.changed_files > policy.maxChangedFiles
  ) {
    throw new Error("Pull request exceeds the trusted changed-file limit");
  }

  const files = [];
  for (let page = 1; files.length < pullRequest.changed_files; page += 1) {
    const pageFiles = await api(
      `/repos/${expectedRepository}/pulls/${pullRequest.number}/files?per_page=100&page=${page}`,
    );
    if (!Array.isArray(pageFiles)) {
      throw new Error("GitHub pull-request file response is malformed");
    }
    files.push(...pageFiles);
    if (pageFiles.length < 100) break;
  }

  const headCommit = await api(
    `/repos/${expectedRepository}/git/commits/${pullRequest.head.sha}`,
  );
  if (!headCommit?.tree?.sha) {
    throw new Error("GitHub head commit response is missing its tree");
  }
  const tree = await api(
    `/repos/${expectedRepository}/git/trees/${headCommit.tree.sha}?recursive=1`,
  );
  if (!Array.isArray(tree?.tree)) {
    throw new Error("GitHub head tree response is malformed");
  }

  const treeByPath = new Map(tree.tree.map((entry) => [entry.path, entry]));
  const blobs = {};
  for (const file of files) {
    if (!["added", "modified"].includes(file.status)) continue;
    const entry = treeByPath.get(file.filename);
    if (entry?.type !== "blob" || typeof entry.sha !== "string") continue;
    if (!Number.isInteger(entry.size) || entry.size > policy.maxFileBytes) continue;
    if (!Object.hasOwn(blobs, entry.sha)) {
      blobs[entry.sha] = await api(
        `/repos/${expectedRepository}/git/blobs/${entry.sha}`,
      );
    }
  }

  return {
    expectedRepository,
    event,
    compare: { files },
    headCommit,
    tree,
    blobs,
    policy,
  };
}

export async function runTrustedPullRequestValidation(options) {
  const snapshot = await collectPullRequestSnapshot(options);
  const result = validatePullRequestSnapshot(snapshot);
  if (!result.ok) {
    throw new Error(`Trusted PR validation failed:\n- ${result.errors.join("\n- ")}`);
  }
  return result;
}

export function createGitHubApi({ token, fetchFn = fetch }) {
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("GitHub token is required");
  }

  return async (path) => {
    if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) {
      throw new Error("Expected a relative GitHub API path");
    }
    const url = new URL(path, "https://api.github.com");
    if (url.origin !== "https://api.github.com") {
      throw new Error("Expected a relative GitHub API path");
    }
    const response = await fetchFn(url.href, {
      method: "GET",
      redirect: "error",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
    });
    if (!response.ok) {
      throw new Error(`GitHub API request failed with status ${response.status}`);
    }
    return response.json();
  };
}

export async function main({
  env = process.env,
  readFileFn = readFileSync,
  api,
} = {}) {
  if (typeof env.EXPECTED_REPOSITORY !== "string" || env.EXPECTED_REPOSITORY.length === 0) {
    throw new Error("EXPECTED_REPOSITORY is required");
  }
  if (typeof env.GITHUB_EVENT_PATH !== "string" || env.GITHUB_EVENT_PATH.length === 0) {
    throw new Error("GITHUB_EVENT_PATH is required");
  }

  const event = JSON.parse(readFileFn(env.GITHUB_EVENT_PATH, "utf8"));
  if (
    typeof env.TRUSTED_BASE_SHA !== "string" ||
    event?.pull_request?.base?.sha !== env.TRUSTED_BASE_SHA
  ) {
    throw new Error("Workflow checkout does not match the protected base SHA");
  }

  const repositoryPolicy = JSON.parse(
    readFileFn(
      new URL("../policy/bury-p1-public-content-policy-v1.json", import.meta.url),
      "utf8",
    ),
  );
  const resolvedApi = api ?? createGitHubApi({ token: env.GH_TOKEN });

  return runTrustedPullRequestValidation({
    api: resolvedApi,
    event,
    expectedRepository: env.EXPECTED_REPOSITORY,
    policy: repositoryPolicy.trustedPullRequestValidation,
  });
}

const invokedUrl = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (invokedUrl === import.meta.url) {
  main()
    .then(() => {
      console.log("Trusted Bury P1 pull-request validation passed.");
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : "Trusted validation failed");
      process.exitCode = 1;
    });
}
