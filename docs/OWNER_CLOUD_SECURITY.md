# Secure Owner Dashboard Cloud Boundary

The cloud Owner Dashboard is a separate Railway service built from
`Dockerfile.owner-dashboard`. The original local dashboard remains bound to
`127.0.0.1:8775` and is not started by this deployment.

## First-release authority

- The cloud surface is read-only.
- `OWNER` and `ADMIN` may read fleet state.
- Only `OWNER` may read the access audit.
- Every `/api/v1/actions/*` request is denied with `READ_ONLY_MODE`.
- Risk, AI output, and UI state never grant action authority.

## Authentication boundary

- Passwords use bounded scrypt hashes supplied through Railway Variables.
- Session tokens and CSRF tokens are generated with the operating system CSPRNG.
- Only token hashes are stored in the Owner service SQLite database.
- Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, host-only,
  and expire after eight hours with a 30-minute idle timeout.
- Login and logout are CSRF-protected.
- Login attempts are rate-limited and repeated failures are locked.
- Authentication events, authorization denials, logout, and denied privileged
  actions are stored in the separate Owner audit database.

## Service-to-service boundary

The Owner service calls:

`http://cyberdefender.railway.internal:8080/api/v1/owner/summary`

The request uses a dedicated bearer credential. The distribution service
rejects the Owner read token on fleet enrollment routes and rejects the fleet
token on the Owner read route. The Owner client refuses a public distribution
URL in staging and production.

## Required Railway variables

### Owner Dashboard service

- `CYBERDEFENDER_ENVIRONMENT=staging|production`
- `CYBERDEFENDER_OWNER_ACCOUNTS_JSON=<secret JSON>`
- `CYBERDEFENDER_DISTRIBUTION_PRIVATE_URL=http://cyberdefender.railway.internal:8080`
- `CYBERDEFENDER_DISTRIBUTION_READ_TOKEN=<secret>`
- `CYBERDEFENDER_OWNER_DB=/data/owner.db`
- `CYBERDEFENDER_OWNER_ALLOWED_HOSTS=<Railway domain,custom domain>`
- `CYBERDEFENDER_OWNER_CUSTOM_DOMAIN=app.cyberdefender-sec.uz` in production

### Distribution service

- `CYBERDEFENDER_DISTRIBUTION_READ_TOKEN=<same secret>`
- `CYBERDEFENDER_PACKAGE_VERSION=<reviewed commit or release>`
- `CYBERDEFENDER_PACKAGE_CHANNEL=stable`

No variable value belongs in Git, logs, build arguments, or image layers.
