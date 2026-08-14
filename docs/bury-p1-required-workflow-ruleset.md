# Bury P1 trusted validation ruleset

The trusted validator must be enforced with GitHub's repository ruleset `workflows`
rule. A required status or check name is not sufficient: another workflow in the
same repository can report the same name through the GitHub Actions app.

The repository rule must bind all of these immutable coordinates:

- path: `.github/workflows/bury-p1-trusted-pr-validation.yml`
- repository ID: the numeric ID read from the public repository API
- SHA: the exact merged commit containing the protected workflow
- ref: `refs/heads/main`
- target: `refs/heads/main`
- bypass actors: none
- enforcement: `active`

After the baseline is merged, read back the existing ruleset and repository ID.
Run `scripts/build-bury-p1-required-workflow-ruleset.mjs` credentiallessly to
construct the proposed update. Review the output, then apply it through the
GitHub REST ruleset endpoint using API version `2026-03-10`. This repository does
not authorize that provider mutation from the builder.

Read the ruleset back again and run
`scripts/verify-bury-p1-required-workflow-ruleset.mjs` against repository, main
branch, tree, trusted-workflow content, activation-probe workflow content,
activation-probe script content, and ruleset API read-backs. Supply the latter
two content responses through `ACTIVATION_WORKFLOW_CONTENT_READBACK_PATH` and
`ACTIVATION_SCRIPT_CONTENT_READBACK_PATH`. The verifier proves all three blobs
are ordinary files in the exact merged-main tree, then verifies the exact
required-workflow path, ref, repository ID, merged protected-main SHA, active
enforcement, main target, and visibly empty bypass list. Until that read-back exists, the
baseline state is `BLOCKED_UNTIL_POST_MERGE_ACTIVE_RULESET_READBACK`. If GitHub
rejects the repository `workflows` rule for the account or plan, remain blocked;
never fall back to the spoofable `bury-p1/trusted-pr-validation` status context.

For an exact-SHA successor, use a two-phase update: provide both
`PREVIOUS_WORKFLOW_SHA` and `WORKFLOW_SHA`, apply the resulting rule while the
previous pinned workflow remains required, and read back both entries before
relying on the successor. Verify that read-back with `TRANSITION_STATE=dual`.
Remove the old entry only in a later reviewed update after the successor has
passed, then verify its absence with `TRANSITION_STATE=final`. GitHub's published schema permits an array of
path/ref/repository/SHA entries but does not document same-path de-duplication;
if the live endpoint rejects or rewrites the dual entry, leave the old rule
active and remain blocked. Do not disable or retarget it.

The protected runtime implements the full five-finding gate before creating an
annotated claim tag. It binds the manifest, two external approval records,
candidate commit/tree, path/content/migration/complete-bundle ledgers, actor,
window, native GitHub/Sigstore attestation, and unused authorization. The later
workflow files are limited to exact calls to the protected validator/consumer;
feature PR code is never executed by the trusted PR validator.

Consumption is recoverable: preflight creates an annotated tag object and then
atomically creates `refs/tags/bury-p1-consumed/<authorization>`. Exact retries
read and compare the winning claim. A pinned native attestation signs the fixed
claim file. The always-running finalizer cryptographically verifies it and
atomically creates `refs/tags/bury-p1-receipted/<authorization>` containing an
all-true PASS receipt. A conflicting tag fails permanently; exact receipts are
idempotent. No downstream P1 executor may accept a claim without the receipt.

Activate two separate tag rulesets. The first is produced by
`buildRestrictedConsumptionTagCreationRuleset()`: it prohibits namespace
creation for ordinary contents-write principals and permits only the GitHub
Actions integration (`15368`) to cross that creation rule. This remains safe
only while the immutable validator prohibits every other contents-write
workflow. Verify the exact integration-only bypass and rule-suite behaviour
with `verifyRestrictedConsumptionTagCreationRuleset()`.

Activation is not established by ruleset JSON alone. Run the executable
post-activation verifier with the exact creation/immutability ruleset IDs and
full repository rule-suite read-backs for these fixed probes:

- Actions integration `15368` creation at
  `refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS` must be `bypass`, with
  the active creation rule evaluating `fail` from the exact creation ruleset.
- An ordinary non-15368 writer creation at
  `refs/tags/bury-p1-consumed/ACTIVATION-PROBE-WRITER` must be `fail`.
- Actions integration update and deletion attempts against the Actions probe
  must both be `fail`, each attributed to the exact independent immutability
  ruleset.

The Actions-side event is generated only by the protected
`.github/workflows/bury-p1-activation-probe.yml` workflow on protected `main`,
behind the `bury-p1-attestation` environment. It has no dispatch inputs. It
checks out the exact dispatch SHA without credentials and invokes only the
protected `scripts/run-bury-p1-activation-probe.mjs`. That script can create
only the fixed annotated object and
`refs/tags/bury-p1-consumed/ACTIVATION-PROBE-ACTIONS`, then performs the fixed
update and deletion attempts and fails if either succeeds. Its fixed
correlation JSON is retained in the workflow log. The protected PR validator
rejects any change or deletion of either file.

Before dispatch, read back the environment and its deployment-branch policies:
it must have administrator bypass disabled and an exact custom branch policy
allowing only `main`. Liuba and Matthew are evidence approvers, not GitHub
accounts, so do not invent environment-reviewer identities or store approval
credentials. The workflow and script independently reject any event/ref other
than `workflow_dispatch` on `refs/heads/main`; environment configuration is an
additional provider gate. Until its exact live read-back exists, remain blocked.

GitHub documents repository rule-suite retrieval as requiring repository
Administration read permission, which `GITHUB_TOKEN` cannot be granted through
workflow `permissions`. Therefore this workflow deliberately has only
`contents: write` and does not accept or store a PAT. After it completes, the
operator must fetch the three correlated Actions rule-suite records with
external Administration-read authority and save their complete API JSON for
the verifier. The ordinary-writer denied-creation event must likewise be
performed separately with a non-15368 writer credential. This human/provider
evidence step is mandatory; absence of any record remains a blocked activation,
not a reason to widen the workflow token.

Supply the four full rule-suite JSON files through
`ACTIONS_CREATION_RULE_SUITE_PATH`, `ORDINARY_CREATION_RULE_SUITE_PATH`,
`UPDATE_RULE_SUITE_PATH`, and `DELETION_RULE_SUITE_PATH`. Also supply both tag
ruleset JSON paths and numeric IDs. The CLI now refuses completion without all
of them and verifies repository ID/name, ruleset ID/name/source, actor ID,
fixed ref, overall result, evaluation result, enforcement, rule type, rule
source ID, and rule result. Until this behavioural evidence passes, activation
remains blocked.

The second is produced by
`buildImmutableConsumptionTagRuleset()`. It targets only the consumed and
receipted prefixes, is active, has no bypass actors, and prohibits update and
deletion. Verify it with `verifyImmutableConsumptionTagRuleset()` after API
read-back. Separating the rules is deliberate: the Actions integration may
create a ref but cannot bypass the independent no-bypass update/deletion rule.
Tag-object creation before ref creation is intentionally recoverable;
an orphan object has no authority.

Official schema reference:
https://docs.github.com/en/rest/repos/rules?apiVersion=2026-03-10

Git references and annotated tags:
https://docs.github.com/en/rest/git/refs?apiVersion=2026-03-10
https://docs.github.com/en/rest/git/tags?apiVersion=2026-03-10

GitHub attestation verification:
https://cli.github.com/manual/gh_attestation_verify
