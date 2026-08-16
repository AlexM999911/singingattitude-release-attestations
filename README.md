# Singing Attitude Release Attestations

This is a public, attestation-only repository for non-sensitive cryptographic evidence from controlled Singing Attitude validation.

The Singing Attitude application source remains private. This repository must never contain private source code, source patches, customer or student data, database contents, production values, provider configuration, credentials, API tokens, raw email addresses, raw authentication identifiers, or private signing material.

Permitted artifacts are limited by [`policy/bury-p1-public-content-policy-v1.json`](policy/bury-p1-public-content-policy-v1.json). They may include deterministic manifests, hashes, Alex Mason's non-sensitive owner-authorization receipt and SHA-256 sidecar, credentialless policy files, GitHub-native attestations, and redacted verification or one-use consumption receipts.

The V2 governance model recognises Alex Mason as both business owner and technical owner. A candidate-specific `BURY_P1_OWNER_AUTHORIZATION_V2` receipt may authorise only an exact, one-use disposable P1 execution. It must bind the candidate commit and tree, manifest digest, ordered migration hashes, execution window, recovery owner, and rollback authority while keeping `g2Authorized=false` and `productionBookingAuthorized=false`.

Repository attestations establish cryptographic provenance; the owner receipt establishes bounded authority. Neither can bypass a failed technical check, approve a changed candidate, skip recovery or rollback controls, or enable public booking without a passed lifecycle canary. P1 remains blocked until every protected validation, source-bound required check, immutable-candidate, manifest, disposable-environment, one-use claim, deterministic read-back, and teardown gate passes.
