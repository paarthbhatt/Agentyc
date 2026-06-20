# Security Policy

## Reporting a Vulnerability

Agent Sentinel is a security product and we take vulnerabilities in the project
itself seriously. If you believe you have found a security issue, **please do not
open a public GitHub issue**.

Instead, report it privately using GitHub's advisory feature:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability** (under "Security Advisories").
3. Provide a clear description, steps to reproduce, and the impact.

Please include:
- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept, logs, or screenshots).
- Affected version / commit.

We will acknowledge receipt within **5 business days** and aim to send a
preliminary assessment within **14 days**.

## Supported Versions

Only the latest release line on the `main` branch receives security fixes.

## Known Hardening Status

This project is a working prototype and is **not yet production-hardened**. Before
any real deployment you MUST:

- **Rotate all credentials** — set real, strong values for `ADMIN_API_KEY`,
  `JWT_SECRET_KEY`, and `API_KEY_PEPPER` in your `.env` (never commit them).
- Set `ENVIRONMENT=production` — this enables fail-closed startup checks that
  refuse to run without the required secrets and refuse to seed the default
  `admin@admin` / `admin` user.
- Be aware that the demo seeds a default admin user (`admin@admin` / `admin`)
  **in development only**. This credential is disabled in production.
- Several API routes are not yet protected by JWT authentication and rely on
  API-key gating. Do not expose the service to untrusted networks until full
  route-level auth is in place.

## Historical Credential Exposure

A Google OAuth client secret was previously committed to this repository's
git history and pushed to the remote. **That credential was revoked and
rotated.** Git history was rewritten to purge the secret. If you have an old
clone, please re-clone from the current `main` branch.
