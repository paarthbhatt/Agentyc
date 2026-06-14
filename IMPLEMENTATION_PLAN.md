# Agent Sentinel Implementation Plan

## Goal Description

Ensure Agent Sentinel runs flawlessly in production: the dashboard loads, agents can be registered, and enforcement (allow/block) works as expected. Execute the full test suite, verify Docker deployment, integrate Google Sign‑In, set up CI/CD, add performance testing, and apply required security hardening.

## User Review Completed

- **Database**: Continue using the default SQLite (`backend/agent_sentinel.db`).
- **Docker Image**: No separate production‑grade image; the current `docker-compose.yml` setup will be used privately.
- **Authentication**: Enable Google Sign‑In for user authentication.
- **CI/CD**: Add a GitHub Actions workflow to run tests, builds, and security scans on each push.
- **Observability**: Not required at this stage.
- **TLS/HTTPS**: Recommend terminating TLS via a reverse‑proxy (Nginx) with a self‑signed certificate for local testing, configurable for a production certificate later.
- **Performance Testing**: Include a simple load test using `hey` after services are healthy.
- **Security Hardening**: Enforce security scanning, rate limiting, secret management, and strict CORS.

## Proposed Changes

### 1. Test Execution

#### Backend
- Unit tests: `python -m unittest discover -s backend/tests`
- Security scan: `bandit -r backend/`

#### Frontend
- Build verification: `npm install && npm run build`
- (If a test suite exists) run `npm test`.

#### End‑to‑End Enforcement Demo
- Use `demo/attack_demo.py` to perform an allowed action and a blocked action, then verify an incident appears via `/api/v1/incidents`.

### 2. Docker Deployment Verification

```bash
# Start services in detached mode
docker compose up --build -d

# Wait for containers to be healthy (backend on 8000, frontend on 5173)
# Simple health checks
curl -f http://localhost:8000/health || exit 1
curl -f http://localhost:5173/ || exit 1
```

#### TLS via Reverse Proxy
- Add an `nginx` service in `docker-compose.yml` that forwards to the backend and terminates TLS.
- Generate a self‑signed cert (`openssl req -newkey rsa:2048 -nodes -keyout nginx.key -x509 -days 365 -out nginx.crt`).
- Mount the certs into the `nginx` container and configure `proxy_ssl_certificate`.
- Expose port `443` for the API; the frontend will call `https://localhost/api/...`.

### 3. Google Sign‑In Integration

1. Create a Google Cloud OAuth 2.0 client (Web application) and obtain **Client ID** and **Client Secret**.
2. Add the following env vars to `.env` (or set in Docker):
   ```
   GOOGLE_CLIENT_ID=<your-client-id>
   GOOGLE_CLIENT_SECRET=<your-client-secret>
   OAUTH_REDIRECT_URI=http://localhost:5173/auth/callback
   ```
3. In the frontend (`src/lib/api.ts` and auth context), add the Google Sign‑In flow using the `@react-oauth/google` package.
4. Backend: use `fastapi.security.OAuth2AuthorizationCodeBearer` to validate the token and map Google accounts to internal agent identities.
5. Ensure the `ADMIN_API_KEY` is still required for privileged endpoints.

### 4. CI/CD Workflow

A GitHub Actions workflow (`.github/workflows/ci.yml`) will:
- Checkout code.
- Set up Python and Node.
- Run backend unit tests and `bandit` scan.
- Run frontend build and optional tests.
- Build Docker image (using existing compose config) and run integration tests inside the containers.
- Execute the end‑to‑end demo script.
- Run performance test with `hey` against the running API.
- On success, push the Docker image to a private registry (optional).

### 5. Performance Testing

After containers are up and healthy:
```bash
hey -n 500 -c 20 http://localhost:8000/api/v1/agents
```
- Verify average latency ≤ 200 ms and error rate = 0.

### 6. Security Hardening

- **Rate Limiting**: Add `slowapi` middleware (e.g., 100 requests/min per IP).
- **Secret Management**: Recommend storing `ADMIN_API_KEY`, Google credentials, and any future DB passwords in a secrets manager (AWS Secrets Manager, Azure Key Vault) and injecting via environment variables.
- **CORS**: Restrict allowed origins to the production frontend URL only.
- **Container Scanning**: Run `trivy image agent-sentinel_backend` (or `docker scan`) in CI.
- **Dependency Auditing**: `npm audit` for frontend, `pip-audit` for backend.
- **Static Code Analysis**: `ruff` for Python linting and security lint checks.

### 7. Documentation Updates

- Extend `README.md` with a **Production Deployment** section covering the TLS reverse‑proxy setup, Google Sign‑In configuration, and CI/CD instructions.
- Add badges for CI status and Docker image version.

## Verification Plan

### Automated Tests
- Execute all commands listed in **Test Execution** and confirm exit code 0.
- Ensure security scans report no high‑severity findings.

### Manual Verification
- Open `https://localhost` (through Nginx) and confirm the dashboard loads without console errors.
- Register a user via Google Sign‑In, then create an agent.
- Run the demo attack script; verify the blocked action creates an incident visible in the UI.
- Check rate‑limit headers when exceeding the request threshold.

### Post‑Run Cleanup
- `docker compose down` to stop all containers.
- Remove the temporary SQLite file if created during tests.
- Delete generated TLS certs if no longer needed.

---

This plan reflects your preferences and adds the required security, authentication, CI/CD, performance, and TLS steps. Let me know if any further tweaks are needed before I start executing the test suite and deployment verification.
