
# TrustVault — API and Route Documentation

## 1. Overview

TrustVault is a Flask-based secure document-sharing application.

It uses session-based authentication, role-based access control, per-document permissions, CSRF protection, private file storage, and tamper-evident audit logging.

All state-changing browser routes require a valid CSRF token.

Login is publicly accessible. Protected operations require an authenticated session.

## 2. User Roles

| Role | Description |
|---|---|
| Admin | Global document visibility, user administration, audit monitoring, and document access management |
| Owner | Uploads and manages documents they own and controls access grants |
| Viewer | Reads and downloads documents shared with them |
 
## 3. Permission Types

| Permission | Read | Download | Edit Metadata | Grant/Revoke | Delete |
|---|---|---|---|---|---|
| Owner | Yes | Yes | Yes | Yes | Yes |
| Admin | Yes | Yes | Yes | Yes | Yes |
| Read grant | Yes | Yes | No | No | No |
| Edit grant | Yes | Yes | Yes | No | No |

Important:

- Edit permission does not grant document deletion rights.
- Only the document owner or an admin can grant or revoke access.
- Only the document owner or an admin can delete a document.
- Permissions are checked on the server, not only through the user interface.

## 4. Route Documentation

| Method | Route | Allowed Caller | Description |
|---|---|---|---|
| GET | `/` | Anyone | Redirects to login or dashboard |
| GET, POST | `/login` | Anyone | Authenticates users |
| POST | `/logout` | Authenticated user | Ends the current session |
| GET | `/dashboard` | Authenticated user | Displays accessible documents |
| GET, POST | `/upload` | Owner, Admin | Uploads a document |
| GET | `/documents/<id>/download` | Owner, Admin, Read/Edit grantee | Downloads a document |
| GET, POST | `/documents/<id>/edit` | Owner, Admin, Edit grantee | Updates document metadata |
| POST | `/documents/<id>/delete` | Owner, Admin | Deletes a document and its grants |
| GET, POST | `/documents/<id>/permissions` | Owner, Admin | Grants or changes document permissions |
| POST | `/documents/<id>/permissions/<grant_id>/revoke` | Owner, Admin | Revokes a document permission |
| GET | `/admin/users` | Admin | Displays registered users |
| POST | `/admin/users/<user_id>/toggle` | Admin | Enables or disables a user |
| GET | `/admin/activity` | Admin | Displays recent audit events and chain status |
| GET | `/admin/audit/verify` | Admin | Verifies the audit chain and returns JSON |

## 5. Route Details

### 5.1 Login

**Endpoint:** `/login`

**Methods:** GET, POST

**Access:** Public

Authenticates a user using email and password.

Security controls:

- Password hash verification.
- Account activation check.
- Failed login attempts recorded in the audit log.
- Rate limit of 5 requests per minute per IP address.

### 5.2 Logout

**Endpoint:** `/logout`

**Method:** POST

**Access:** Authenticated users

Ends the current user's session.

A valid CSRF token is required.

### 5.3 Dashboard

**Endpoint:** `/dashboard`

**Method:** GET

**Access:** Authenticated users

Displays documents according to the user's role:

- Admin: All documents.
- Owner: Documents owned by the user and documents shared with them.
- Viewer: Documents explicitly shared with them.

### 5.4 Upload Document

**Endpoint:** `/upload`

**Methods:** GET, POST

**Access:** Owner, Admin

Allows an authorized user to upload a document.

Supported file extensions:

- PDF
- DOCX
- XLSX
- TXT
- PNG
- JPG
- JPEG

Upload security:

- Maximum file size: 10 MB.
- File extension allowlist.
- MIME type validation.
- PDF signature validation.
- Image type validation.
- DOCX/XLSX ZIP structure checks.
- Random storage filenames.
- Private file storage.

These checks do not guarantee that uploaded files are malware-free. Antivirus scanning is not currently implemented.

### 5.5 Download Document

**Endpoint:** `/documents/<id>/download`

**Method:** GET

**Access:**

- Document owner.
- Admin.
- User with explicit Read permission.
- User with explicit Edit permission.

The application checks the user's current permission before sending the file.

A successful download is recorded in the audit log.

### 5.6 Edit Document

**Endpoint:** `/documents/<id>/edit`

**Methods:** GET, POST

**Access:**

- Document owner.
- Admin.
- User with explicit Edit permission.

Allows updates to:

- Document display name.
- Document category.

A successful metadata update is recorded in the audit log.

### 5.7 Delete Document

**Endpoint:** `/documents/<id>/delete`

**Method:** POST

**Access:**

- Document owner.
- Admin.

Users with Edit permission cannot delete documents they do not own.

Deleting a document also removes its associated permission grants and private file.

### 5.8 Manage Permissions

**Endpoint:** `/documents/<id>/permissions`

**Methods:** GET, POST

**Access:**

- Document owner.
- Admin.

Allows authorized users to:

- Grant Read permission.
- Grant Edit permission.
- Change an existing permission.

Permission changes are recorded in the audit log.

### 5.9 Revoke Permission

**Endpoint:** `/documents/<id>/permissions/<grant_id>/revoke`

**Method:** POST

**Access:**

- Document owner.
- Admin.

Removes a user's permission grant.

Subsequent protected document requests check the database again, so revoked access is denied.

### 5.10 Admin User Management

**Endpoint:** `/admin/users`

**Method:** GET

**Access:** Admin

Displays registered user accounts.

### 5.11 Enable or Disable User

**Endpoint:** `/admin/users/<user_id>/toggle`

**Method:** POST

**Access:** Admin

Changes a user's active-account status.

Disabled users cannot authenticate through the login route.

### 5.12 Admin Activity

**Endpoint:** `/admin/activity`

**Method:** GET

**Access:** Admin

Displays up to 300 recent audit events and the audit-chain verification status.

### 5.13 Audit Verification

**Endpoint:** `/admin/audit/verify`

**Method:** GET

**Access:** Admin

Returns a JSON response indicating whether the audit chain verifies.

Example successful response:

```json
{
  "audit_chain_valid": true
}
```

The response indicates whether the stored events match the current HMAC chain and configured audit key.

## 6. Authorization and Error Responses

| HTTP Status | Meaning |
|---|---|
| 200 | Request successful |
| 302 | Redirect |
| 400 | Invalid request or CSRF failure |
| 403 | Forbidden operation |
| 404 | Resource not found or unauthorized document access |
| 413 | Uploaded file exceeds the configured size limit |
| 429 | Login rate limit exceeded |

Security behavior:

- Unauthorized document access returns 404.
- Non-admin access to admin-only routes returns 403.
- Login requires valid credentials and an active account.
- Protected routes require authentication.
- State-changing browser requests require CSRF validation.
- Authorization is checked on the server.

## 7. Audit Events

The application records security-relevant activities, including:

- `LOGIN_SUCCESS`
- `LOGIN_FAILED`
- `LOGOUT`
- `UPLOAD`
- `UPLOAD_REJECTED`
- `DOWNLOAD`
- `DOCUMENT_EDIT`
- `DELETE`
- `PERMISSION_GRANT`
- `PERMISSION_CHANGE`
- `PERMISSION_REVOKE`
- `DENIED_DOCUMENT_ACCESS`
- `DENIED_PERMISSION_MANAGEMENT`
- `DENIED_PERMISSION_REVOKE`
- `DENIED_ADMIN_ROUTE`
- `USER_ENABLED`
- `USER_DISABLED`

Audit events are linked using HMAC-SHA256.

The current implementation provides tamper-evident verification but is not an independent immutable audit service.

## 8. Rate Limiting

The login route is configured with:

`5 per minute`

The current limiter uses in-memory storage.

Limitations:

- Counters reset when the application restarts.
- Counters are not shared across multiple application workers.
- Production deployment should use shared storage such as Redis.

## 9. Security Limitations

The current implementation does not provide:

- Multi-factor authentication.
- Antivirus or malware scanning.
- Independent remote immutable audit storage.
- Document version history.
- External document-sharing links.
- Distributed production rate limiting.

See `THREATS.md` for the threat model, implemented mitigations, accepted risks, and future hardening work.

## 10. Testing

Run the automated tests from the project root:

```powershell
python -m pytest -v
```

The previously recorded local test result was 11 passed. Run the suite again after code changes to verify the current implementation.

## 11. Documentation Files

- `README.md` — setup and project overview.
- `API.md` — route and permission documentation.
- `THREATS.md` — security threat model.
- `PROMPTS.md` — development prompts and implementation notes.
