# THREATS.md — TrustVault threat model

Review this file as implementation and testing progress. Do not claim a mitigation is complete until the corresponding test has been run against the deployed build.

| Threat / attack | Mitigation in this build | Evidence / test | Residual risk |
|---|---|---|---|
| Guess another document's numeric ID (IDOR) | Central `get_document_access` check on download/edit; owner/admin checks for permissions/delete | `tests/test_authorization.py` | Add tests for every route and HTTP method |
| Call download URL directly without using UI | Download endpoint checks access on every request | Ungranted-viewer test | Reverse proxy must not expose upload directory |
| Reuse URL after permission revoked | Grant is read from DB on each request; no public signed links | Revocation test | Existing downloaded copies cannot be recalled |
| Viewer attempts edit | Edit route requires `edit` grant or ownership/admin | Viewer edit test | Expand tests for all roles |
| User changes document ID in permission URL | Owner/admin ownership check is server-side | Manual negative test needed | Add automated permission-management IDOR tests |
| Guess stored filename | Random UUID storage names; files are outside static/public directory | Inspect storage layout | Host filesystem access remains privileged |
| Upload executable or unexpected file | Extension allowlist, secure filename, 10 MB request cap, random storage name | Manual upload tests needed | Extension checks are not malware scanning or content-type validation |
| Path traversal in filename | `secure_filename`; stored path uses generated UUID, never user path | Code review | Add adversarial filename tests |
| CSRF on state-changing actions | Flask-WTF global CSRF protection and tokens in forms | CSRF tests to add | API clients need explicit CSRF/session strategy |
| Password disclosure | Werkzeug password hashing; no plaintext password column | Model/code review | Add rate limiting, MFA and password reset hardening |
| Brute-force login | Failed attempts are audited | Login audit event | Rate limiting / lockout not yet implemented |
| Audit record edited in database | HMAC hash chain detects changes if external key remains secret | `tests/test_audit.py` | Local DB + key on same host is not independently immutable |
| Audit event deletion / truncation | Hash chain detects changed links among remaining events | Chain verification | Truncation of tail may not be detectable without remote checkpoints |
| Admin account misuse | Admin actions are logged; admin routes protected by role | Manual role tests needed | Add MFA, dual control and alerting |
| Session theft | HttpOnly and SameSite cookies; Secure flag configurable for HTTPS | Configuration review | Add short session lifetime, rotation, CSP and secure deployment |
| Sensitive metadata exposure | Dashboard only lists authorised documents; unauthorised IDs return 404 | Access tests | Search filtering currently runs over already-authorised list |
| File malware / malicious PDF | Type allowlist and size limit | Upload checks | No antivirus/CDR; accepted for challenge prototype only |

## Deliberately accepted limitations
- No external sharing links: avoids bearer-link complexity in the seven-day build.
- No folder inheritance: explicit per-document grants are easier to reason about and test.
- No version history or recycle bin: deletion is permanent in this prototype.
- No malware scanning: requires a separate scanning service; uploads are limited but not proven safe.
- SQLite is suitable for a demo, not concurrent enterprise workloads.
- Audit chain is tamper-evident, not a fully independent immutable log. Production should export signed events to separate append-only storage and protect keys separately.
- No MFA or login rate limiting yet; must be added before production use.
