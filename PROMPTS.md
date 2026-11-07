
# AI Development Log — TrustVault

This file records how AI assistance was used during the development of TrustVault. The entries describe the actual development and debugging work carried out during the project.

## 1. November 1, 2026 — Project planning

**Prompt / task:** Help me understand the document-management challenge and plan a Flask application with user roles, document permissions, private storage, and audit logging.

**AI assistance:** Helped break the requirements into application modules and suggested a Flask and SQLAlchemy structure.

**My work and decisions:** I reviewed the proposed structure and organized the project around authentication, document management, permissions, and audit activity.

## 2. November 2, 2026 — Document upload and validation

**Prompt / task:** Help me implement secure document uploads with file type validation, size restrictions, and private file storage.

**AI assistance:** Explained file validation, MIME type checks, file signatures, safe filenames, and upload handling.

**My work and decisions:** I worked on the upload implementation and tested document uploads. I used private storage and UUID-based filenames rather than exposing original filenames as storage paths.

## 3. November 3, 2026 — Role-based access and permissions

**Prompt / task:** Help me implement document access permissions for different user roles and prevent unauthorized access.

**AI assistance:** Helped review role-based access checks and document permission logic.

**My work and decisions:** I tested the application flows and reviewed how access should be checked before document operations. I focused on preventing access when permission is not granted.

## 4. November 4, 2026 — Audit logging and integrity

**Prompt / task:** Help me implement an audit trail that records important application events and detects changes to previous audit records.

**AI assistance:** Explained hash chaining, HMAC verification, and audit event recording.

**My work and decisions:** I worked on recording login and document activity and verifying the audit chain. I treated integrity verification results as important and did not hide an invalid verification result.

## 5. November 5, 2026 — Testing and debugging

**Prompt / task:** Help me debug the Flask application, review security-related code, and run automated tests.

**AI assistance:** Helped explain errors, review code, and identify deployment and configuration issues.

**My work and decisions:** I ran the automated test suite and obtained 18 passing tests. I also checked the application manually and corrected issues found during development.

## 6. November 7, 2026 — Production deployment

**Prompt / task:** Help me deploy TrustVault and configure the initial administrator account securely.

**AI assistance:** Helped troubleshoot deployment errors involving environment variables, password length, and separate cryptographic keys.

**My work and decisions:** I configured separate Flask session and audit HMAC keys, set the initial administrator credentials through environment variables, deployed the application, and manually tested login, upload, download, and audit verification.

---

## Developer responsibility

AI was used as a development assistant for planning, explanations, debugging, and code review. I reviewed the suggested changes, made configuration decisions, ran tests, and manually verified the deployed application. The entries above describe the development activities and testing performed during the project.
