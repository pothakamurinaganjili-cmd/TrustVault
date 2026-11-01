# PROMPTS.md — AI assistance log

Keep this file updated on the day each AI-assisted change happens. The entries below are a starting template for the project owner to complete truthfully. Do not invent commit hashes or claim a test passed unless you ran it.

## Reusable project context
Build TrustVault for the Snovasys Fresher Hiring Challenge (1–7 November 2026). The security requirements are more important than UI polish. Use Python/Flask, SQLite/SQLAlchemy, per-document named-user grants, private file storage, immediate revocation, and an auditable event trail. Never let AI make permission decisions automatically. Explain code in beginner-friendly language. Treat all untrusted input as hostile. Tests must demonstrate denied access.

## Dated work log

### 2026-11-01 — Initial architecture and scaffolding
- Asked: "Build a Flask starter for TrustVault with Admin, Owner and Viewer roles, per-document read/edit grants, private uploads, audit events and security tests."
- Produced: Flask app structure, models, routes, templates, documentation and initial tests.
- What needs checking: verify every route and HTTP method has server-side authorisation; check audit HMAC canonicalisation and file handling; run tests and inspect failures.
- What I changed instead: record the actual corrections made after review here.
- Fix commit: TODO — add the real commit URL after committing.

### 2026-11-01 — Authorisation review (required security review)
- Asked: "Review the document download and edit routes for IDOR and ensure permission checks happen on every request, including direct URL requests."
- Produced: central access-check helper and route decorators.
- What was wrong / what I verified: TODO — document concrete findings from code review and tests; do not leave this generic.
- What I changed instead: TODO — record actual correction and test.
- Fix commit: TODO — add the real commit URL.

### 2026-11-01 — Audit trail review (required security review)
- Asked: "Review the audit log for tampering risks, including edits, deletion, reordering and key compromise."
- Produced: HMAC-linked audit events and chain verification.
- What was wrong / what I verified: TODO — specifically test event modification and discuss tail truncation / key custody.
- What I changed instead: TODO — record actual correction and test.
- Fix commit: TODO — add the real commit URL.

### 2026-11-02 — Upload validation review
- Asked: "Review upload handling for filename traversal, extension spoofing, oversized files and public file exposure."
- Produced: TODO — record actual output.
- What was wrong: TODO — record a specific issue.
- What I changed instead: TODO — record actual fix and test.
- Fix commit: TODO — add the real commit URL.

### 2026-11-03 — Security test review
- Asked: "Try to break the access-control tests by removing an authorisation check; identify missing negative tests."
- Produced: TODO — record actual output.
- What was wrong: TODO — record a specific weakness in the proposed tests.
- What I changed instead: TODO — record actual fix and mutation-test result.
- Fix commit: TODO — add the real commit URL.

## Important
This scaffold does not prove that these prompts were all run or that the review has been completed. Update the entries honestly as you work. Commit this file throughout the week, not only at the end.
