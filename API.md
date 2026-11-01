# Route and API access documentation

All state-changing browser routes require a valid CSRF token. Login is public; all document operations require an authenticated session.

| Method | Route | Allowed caller | Notes |
|---|---|---|---|
| GET, POST | `/login` | Anyone | Password verification; failed attempts audited |
| POST | `/logout` | Authenticated user | Ends session |
| GET | `/dashboard` | Authenticated user | Lists own, granted, or (admin) all documents |
| GET, POST | `/upload` | Owner, Admin | Extension allowlist, size cap, private storage |
| GET | `/documents/<id>/download` | Owner, Admin, explicit Read/Edit grantee | Fresh server-side permission check |
| GET, POST | `/documents/<id>/edit` | Owner, Admin, explicit Edit grantee | Metadata only |
| POST | `/documents/<id>/delete` | Owner, Admin | Removes database record and private file |
| GET, POST | `/documents/<id>/permissions` | Owner, Admin | Grant or change Read/Edit |
| POST | `/documents/<id>/permissions/<grant_id>/revoke` | Owner, Admin | Immediate revocation |
| GET | `/admin/users` | Admin | List users |
| POST | `/admin/users/<id>/toggle` | Admin | Enable/disable user |
| GET | `/admin/activity` | Admin | Recent audit activity and chain status |
| GET | `/admin/audit/verify` | Admin | JSON integrity result |

Unauthorised document access returns 404. Non-admin access to admin routes returns 403.
