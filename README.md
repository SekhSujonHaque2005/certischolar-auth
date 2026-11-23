# CertiScholar Auth & Identity Service (Golang)

High-performance, lightweight Identity Gateway and Token Service for CertiScholar.
Governed by **CS-SRS-002 v3.2 (§9.2, §12.1, ADR-004)**.

## Responsibilities
- OIDC IdP token exchange & session cookie management.
- Cryptographic JWT issuance & validation with tenant-scoped claims.
- Role-Based Access Control (RBAC) validation (Student, Reviewer, Committee, Admin, Agency).
- Zero database overhead for session validation via stateless EdDSA/RSA JWTs.

## Endpoints
- `GET /healthz` - Liveness probe
- `GET /readyz` - Readiness probe
- `POST /v1/auth/token` - Token exchange / refresh
- `POST /v1/auth/validate` - Fast internal token introspection for API Gateway
- `POST /v1/auth/logout` - Revoke session

## Local Run
```bash
go run cmd/server/main.go
# Server listens on port 8080
```
