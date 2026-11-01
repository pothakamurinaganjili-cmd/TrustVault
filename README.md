# TrustVault — Secure Document Sharing

A Flask application demonstrating per-document permissions, private file storage, immediate revocation and a tamper-evident audit log.

## Requirements
- Python 3.10+
- pip

## Local setup (Windows PowerShell)
```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python seed.py
python app.py
```
Open http://127.0.0.1:5000

If PowerShell blocks activation, use `venv\Scripts\activate.bat` in Command Prompt, or follow your organisation's approved PowerShell policy.

## Demo credentials
These are local demonstration credentials only. Change all passwords and set strong environment secrets before deployment.

| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.local | AdminDemo!2026 |
| Owner | owner@trustvault.local | OwnerDemo!2026 |
| Viewer | viewer@trustvault.local | ViewerDemo!2026 |

## Security configuration before deployment
Set unique random values outside source control:
- `TRUSTVAULT_SECRET_KEY`
- `TRUSTVAULT_AUDIT_KEY`
- `DATABASE_URL`
- `TRUSTVAULT_UPLOAD_DIR`
- `COOKIE_SECURE=1` when served only over HTTPS

Do not use the demo keys or demo passwords in production. Keep private uploads outside the web root. Use a production WSGI server (for example gunicorn) behind HTTPS. Restrict filesystem and database access.

## Tests
```powershell
pytest -q
```

## Permission model
- Admin: user administration, global document visibility, audit dashboard.
- Owner: full control over documents they upload; can grant/revoke named-user access.
- Viewer: read/download only when an explicit document grant exists.
- Edit grant: permits read/download and metadata edit. It does not permit permission administration or deletion.
- Only the owner or admin can grant/revoke access or delete a document.
- Each document route checks access on the server. Unknown and unauthorised document IDs both return 404 to reduce ID enumeration.

## Storage and audit
Uploaded files receive random storage names and are stored in a private directory; original filenames are only display/download names. Download routes stream a file only after a fresh permission check.

Audit events form an HMAC chain. The HMAC key is configured outside the database. This detects modification when the key is protected, but a single-host database and key are not a fully independent immutable audit service. Production hardening should export events to append-only remote storage/SIEM and separate key custody.

## API / route access summary
See `API.md`.

## Known limitations
This is a challenge starter implementation, not a certified enterprise document vault. See `THREATS.md` for accepted risks and hardening work. Review and run the tests, add integration tests for your deployment, and never deploy demo credentials.
