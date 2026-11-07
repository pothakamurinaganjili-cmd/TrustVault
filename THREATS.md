# THREATS.md — TrustVault Threat Model

Review this file as implementation and testing progress. Do not claim a mitigation is complete until the corresponding test has been run against the deployed build.

| Threat / attack | Mitigation in this build | Evidence / test | Residual risk |
|---|---|---|---|
| Guess another document's numeric ID (IDOR) | Central `get_document_access` check on download/edit; owner/admin checks for permissions/delete | `tests/test_authorization.py` — authorization tests passed locally as part of the 18-test suite | Add tests for every route and HTTP method |
| Call download URL directly without using UI | Download endpoint checks access on every request | Ungranted-viewer test passed locally | Reverse proxy must not expose upload directory |
| Reuse URL after permission revoked | Grant is read from DB on each request; no public signed links | Revocation test passed locally | Existing downloaded copies cannot be recalled |
| Viewer attempts edit | Edit route requires `edit` grant or ownership/admin | Viewer edit test passed locally | Expand tests for all roles |
| User changes document ID in permission URL | Owner/admin ownership check is server-side | Manual negative test still needed; automated permission-management IDOR coverage should be added | Add automated permission-management IDOR tests |
| Guess stored filename | Random UUID storage names; files are outside static/public directory | Storage layout reviewed | Host filesystem access remains privileged |
| Upload executable or unexpected file | Extension allowlist, MIME detection, PDF signature validation, PNG/JPEG type checks, DOCX/XLSX ZIP structure checks, 10 MB request limit, secure filename and random storage name | `tests/test_file_validation.py` — file-validation tests passed locally; manual genuine TXT/PDF uploads and fake PDF rejection passed | MIME and signature checks do not guarantee malware-free files; no antivirus or content disarm and reconstruction (CDR) |
| Path traversal in filename | `secure_filename`; stored path uses generated UUID, never user path | Code review | Add adversarial filename tests |
| CSRF on state-changing actions | Flask-WTF global CSRF protection and tokens in forms | Manual form testing; automated CSRF tests still needed | API clients need explicit CSRF/session strategy |
| Password disclosure | Werkzeug password hashing; no plaintext password column | Model/code review | Add MFA and password reset hardening |
| Brute-force login | Failed attempts are audited; Flask-Limiter restricts login to 5 attempts per minute per IP | Manual rate-limit test returned HTTP 429 | In-memory limiter resets on restart and is not shared across workers; production needs Redis or another shared store |
| Audit record edited in database | HMAC hash chain detects changes if the external key remains secret | `tests/test_audit.py` — audit-chain tests passed locally as part of the 18-test suite. However, the existing local database currently reports `INVALID`; verification identified an HMAC mismatch at event ID 8. | Root cause is unresolved. Do not regenerate hashes or delete historical events. Local DB and key on same host are not independently immutable |
| Audit event deletion / truncation | HMAC hash chain plus a signed checkpoint is designed to detect tail deletion when the checkpoint remains intact | `tests/test_audit.py` — last-event deletion test and audit-chain tests passed locally. Existing database checkpoint signature and latest event hash match, but the overall chain currently reports `INVALID` because of the event ID 8 mismatch. | Checkpoint is stored on the same host; an attacker who can modify both the database and checkpoint storage may tamper with both |
| Admin account misuse | Admin actions are logged; admin routes protected by role | Manual role tests still needed | Add MFA, dual control and alerting |
| Session theft | HttpOnly and SameSite cookies; Secure flag configurable for HTTPS | Configuration review | Add short session lifetime, rotation, CSP and secure deployment |
| Sensitive metadata exposure | Dashboard only lists authorised documents; unauthorised IDs return 404 | Access tests passed locally | Search filtering currently runs over already-authorised list |
| File malware / malicious PDF | Extension allowlist, MIME detection, basic file signature and structure validation, and size limit | File-validation tests passed locally | No antivirus scanning or CDR; accepted for challenge prototype only |

## Deliberately accepted limitations

- No external sharing links: avoids bearer-link complexity in the seven-day build.
- No folder inheritance: explicit per-document grants are easier to reason about and test.
- No version history or recycle bin: deletion is permanent in this prototype.
- No malware scanning: requires a separate scanning service; file-type validation does not prove that uploads are safe.
- SQLite is suitable for a demo, not concurrent enterprise workloads.
- Audit chain is tamper-evident, not a fully independent immutable log. The signed checkpoint is stored on the same host as the database. Production should export signed events to separate append-only storage and protect keys separately.
- No MFA or account lockout yet. Login rate limiting is implemented using in-memory storage for local testing; production requires shared rate-limit storage.
- The automated test suite passed locally (18 tests). Deployment-specific security verification has not yet been completed, so local test results must not be treated as proof that the deployed build is secure.
- Current audit verification status: INVALID in the existing local database. Audit events are being recorded and displayed, but historical chain integrity is not currently verified. The mismatch at event ID 8 remains under investigation. Do not treat passing automated tests as proof that the existing audit history is valid.
| Permission revocation | Access check rejects revoked grants | Viewer attempted direct download using a previously copied URL after permission revocation; server returned HTTP 404 and no file was downloaded | Previously downloaded copies cannot be revoked |

## Deliberately accepted limitations
- No external sharing links: avoids bearer-link complexity in the seven-day build.
- No folder inheritance: explicit per-document grants are easier to reason about and test.
- No version history or recycle bin: deletion is permanent in this prototype.
- No malware scanning: requires a separate scanning service; file-type validation does not prove that uploads are safe.
- SQLite is suitable for a demo, not concurrent enterprise workloads.
- Audit chain is tamper-evident, not a fully independent immutable log. The signed checkpoint is stored on the same host as the database. Production should export signed events to separate append-only storage and protect keys separately.
- No MFA or account lockout yet. Login rate limiting is implemented using in-memory storage for local testing; production requires shared rate-limit storage.
- The automated test suite passed locally (18 tests). Deployment-specific security verification has not yet been completed, so local test results must not be treated as proof that the deployed build is secure.
- Current audit verification status: INVALID in the existing local database. Audit events are being recorded and displayed, but historical chain integrity is not currently verified. The mismatch at event ID 8 remains under investigation. Do not treat passing automated tests as proof that the existing audit history is valid.