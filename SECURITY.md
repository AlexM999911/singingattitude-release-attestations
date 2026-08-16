# Security policy

This repository is public. Never disclose or commit:

- private Singing Attitude source code or application patches;
- credentials, tokens, secrets, private keys, or production environment values;
- customer or student data, raw email addresses, or authentication identifiers;
- database contents, dumps, rows, connection information, or migration output containing data;
- Stripe, Supabase, Acuity, Cal.com, Resend, SendPulse, or other provider configuration.

Do not place sensitive material in commits, pull requests, discussions, or repository metadata. Issues, the wiki, and discussions are disabled. If sensitive material is discovered, do not quote or reproduce it publicly; use GitHub's private security-reporting channel for the repository owner.

Attestation and owner-authorization verification failures must fail closed. The V2 owner receipt can authorise only the exact candidate and bounded disposable P1 scope recorded in it; it cannot authorise G2, production credentials, provider operations, payment, booking, email, deployment, or public-booking actions.
