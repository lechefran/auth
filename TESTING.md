# Testing Matrix

This matrix is part of the package contract. Update it in the same change that
adds or changes API behavior, persistence behavior, database migrations,
security invariants, dependencies, or verification commands.

## Baseline Commands

| Scope | Command | When to run |
| --- | --- | --- |
| Full Go suite | `go test ./...` | Before handoff for Go changes |
| Static sanity | `go vet ./...` | Public API, adapter, migration, or security-sensitive changes when practical |
| Core package | `go test .` | Service, config, pagination, store interface, and error behavior |
| SQLite adapter | `go test ./sqlite` | SQLite migration or store behavior |
| Migration-only adapters | `go test ./mysql ./postgres ./redis ./mongodb` | Adapter migration, open-helper, schema, index, or namespace behavior |
| Support packages | `go test ./keys ./token ./migrate` | Key generation, token hashing, or migration engine changes |
| Test bench | `go run ./cmd/testbench` | Manual smoke checks after service workflow changes |

## Package Coverage

| Package | Current coverage | Primary command | Notes |
| --- | --- | --- | --- |
| `github.com/lechefran/auth` | Config validation, service construction, API key create/verify/revoke/list flows, HMAC lookup hashing, raw-key redaction, scope normalization, missing-scope audit events, expiration and revocation handling, best-effort audit behavior, atomic create/revoke paths, cursor pagination limits and validation | `go test .` | This is the security boundary for API-key lifecycle behavior |
| `github.com/lechefran/auth/token` | Opaque API key generation, lookup hash derivation, malformed token handling, hash comparison behavior | `go test ./token` | Raw API keys must never be stored as lookup material |
| `github.com/lechefran/auth/keys` | Key generation helpers and compatibility behavior | `go test ./keys` | Keep this package focused on API-key material only |
| `github.com/lechefran/auth/migrate` | Migration ordering, applied-version tracking contracts, conflict detection, and idempotence behavior | `go test ./migrate` | Shared migration behavior for adapter packages |
| `github.com/lechefran/auth/sqlite` | Live in-memory migrations, non-destructive `CREATE TABLE IF NOT EXISTS` behavior, incompatible schema rejection, drift detection, explicit `DeleteData`, principal store, API-key store, audit store, cursor pagination, touch/revoke semantics, atomic create/revoke with audit rollback, and service integration | `go test ./sqlite` | This is the reference full store adapter today |
| `github.com/lechefran/auth/mysql` | Migration SQL shape, non-destructive DDL checks, inline MySQL index definitions, schema validator coverage for security-critical columns and indexes, time parsing | `go test ./mysql` | Live MySQL/MariaDB integration tests are a future matrix row |
| `github.com/lechefran/auth/postgres` | Migration SQL shape, non-destructive DDL checks, schema validator coverage for security-critical columns and indexes, time parsing | `go test ./postgres` | Live Postgres integration tests are a future matrix row |
| `github.com/lechefran/auth/redis` | Namespace validation, open-helper behavior, non-destructive migration marker coverage, delete-data contract for namespaced data | `go test ./redis` | Full Redis store behavior is not implemented yet |
| `github.com/lechefran/auth/mongodb` | Collection-name validation, index specs, security-critical unique indexes, pagination indexes, simple collation for string identity indexes, open-helper behavior, non-destructive migration markers | `go test ./mongodb` | Full MongoDB store behavior is not implemented yet |
| `github.com/lechefran/auth/cmd/testbench` | Manual API-key workflow exercise | `go run ./cmd/testbench` | Keep lightweight; do not rely on it instead of automated tests |

## Security Invariants

| Invariant | Expected coverage |
| --- | --- |
| Raw API keys are returned once and not exposed by stored or listed API-key records | Core workflow tests and SQLite service integration |
| API-key lookup hashes use keyed HMAC material, not plain SHA-256 of the raw key | Core workflow and token tests |
| Invalid credentials, malformed raw keys, and missing scopes produce audit events | Core workflow tests |
| Missing required scopes fail closed with `ErrPermissionDenied` | Core workflow tests |
| Revoked and expired API keys cannot authenticate | Core workflow tests |
| Last-used updates are best effort and cannot block successful authentication | Core workflow tests and SQLite store tests |
| Create/revoke plus audit is atomic when one store implements `AtomicAPIKeyAuditStore` | Core workflow tests and SQLite transaction tests |
| Separate audit stores use best-effort behavior and do not claim atomicity | Core workflow tests |
| Cursor pagination validates cursors, applies default and maximum limits, and returns stable order | Core pagination tests, workflow tests, and SQLite store tests |
| Migrations are non-destructive and only create missing package-managed schema | Adapter migration tests |
| Existing SQL schema is compatibility-checked before applying migrations | SQLite live tests plus MySQL/Postgres validator tests |
| Explicit data deletion is separate from migration and preserves schema | SQLite live tests plus Redis/MongoDB delete-data contract tests |
| String identity indexes use binary/simple equality where the database supports collation control | MongoDB index tests and SQL schema/index definitions |

## Known Gaps

| Gap | Reason | Add when |
| --- | --- | --- |
| Live MySQL/MariaDB migration integration tests | Current package has migration/open/schema support but no live test harness | Add Docker or externally configured integration test support |
| Live Postgres migration integration tests | Current package has migration/open/schema support but no live test harness | Add Docker or externally configured integration test support |
| Live Redis migration and delete-data integration tests | Current coverage is offline namespace and marker behavior | Add Redis-backed integration test support |
| Live MongoDB migration, index, collation, and delete-data integration tests | Current coverage validates specs without a MongoDB server | Add MongoDB-backed integration test support |
| Full MySQL/Postgres/Redis/MongoDB store adapter lifecycle tests | Full store adapters are not implemented yet | Add alongside each full adapter implementation |
| Concurrency stress tests for duplicate key creation and revoke races | Current tests cover deterministic rollback and duplicate cases | Add when production store concurrency behavior is implemented beyond SQLite |
| Fuzz tests for public parsing surfaces | Current parsing surface is small and deterministic | Add if token, cursor, policy, or migration parsing becomes richer |

## Maintenance Rule

For every future change:

1. Check whether the package coverage table needs a new row or revised coverage text.
2. Check whether a security invariant was added, removed, or changed.
3. Add or update tests in the same package as the behavior when practical.
4. If a test is intentionally deferred, add or update a known-gap row with the reason and the trigger for closing it.
5. Keep commands accurate so a contributor can run the right subset without guessing.
