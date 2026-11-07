
# TrustVault — Secure Document Sharing

TrustVault is a Flask-based secure document-sharing application demonstrating role-based access, per-document permissions, private file storage, immediate access revocation, and a tamper-evident audit log.

## Features

- Admin, Owner, and Viewer roles.
- Private document uploads and downloads.
- Per-document Read and Edit permissions.
- Immediate permission revocation.
- Server-side document authorization.
- User account activation and deactivation.
- HMAC-based tamper-evident audit logging.
- Signed audit checkpoint verification.
- Audit verification endpoint.
- Login rate limiting.
- File extension, MIME type, signature, and structure validation.
- CSRF protection and secure session-cookie settings.

## Requirements

- Python 3.10+
- pip
- Windows PowerShell or another supported terminal

## Local Setup (Windows PowerShell)

Open the project root directory in PowerShell.

Create a virtual environment:

```powershell
py -m venv venv
```

Activate it:

```powershell
venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Initialize demo accounts only when setting up a fresh demo database:

```powershell
python seed.py
```

**Warning:** Do not run `seed.py` against your existing database without checking its behavior, because it may reset demo account data.

## Run the Application

```powershell
python app.py
```

Open this address in your browser:

http://127.0.0.1:5000

## Demo Accounts

### Admin
- Email: admin@example.com
- Password: AdminDemo!2026

### Owner
- Email: owner@example.com
- Password: OwnerDemo!2026

### Viewer
- Email: viewer@example.com
- Password: ViewerDemo!2026

These credentials are for local demonstration only.
Change demo passwords before deployment.

## Run Tests

Run the automated test suite:

```powershell
python -m pytest -q
```

Current local test result: 18 tests passed.

## Audit Integrity Status

The current local database audit verification reports INVALID.

The first detected HMAC mismatch is Event ID 8.
Events 8–35 fail HMAC verification, while the
latest checkpoint matches the latest event hash.

The historical mismatch remains unresolved.
No historical audit events were regenerated or deleted.

This limitation is disclosed rather than hidden.

## Security Notes

- Uploaded files are stored in a private folder.
- Document access is checked on the server.
- Revoked permissions are denied on subsequent requests.
- Production deployment requires secure environment variables,
  HTTPS, and shared rate-limit storage such as Redis.
- Local testing does not establish production security.

