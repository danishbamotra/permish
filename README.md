# permish

Permish is a dependency-free authorization regression testing engine for multi-tenant applications. It runs explicit, deterministic in-memory checks; it does not connect to databases, networks, or production systems.

## Quick start

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

# Discover commands and exit codes
permish --help

# Safe synthetic check; exit 0 and report no findings
permish check --mode safe
permish check --mode safe --json

# Intentionally vulnerable check; exit 1 and report findings
permish check --mode vulnerable
permish check --mode vulnerable --json

# Standalone safe/vulnerable demonstration
python3 examples.py

# Unit tests only; PostgreSQL integration tests are excluded by default
python3 -m pytest -q

# Opt-in disposable PostgreSQL integration suite
python3 -m pip install -e '.[postgres,demo,test]'
permish postgres check

# Equivalent explicit pytest command:
python3 -m pytest -q -m integration tests/integration
```

## Flask + PostgreSQL demo

The optional demo uses Flask's in-process test client against the same disposable
PostgreSQL container. It is not a public server and uses no real identities or
credentials.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[postgres,demo,test]'

# Start the disposable database, run all integration tests, and clean it up
python3 -m pytest -q -m integration tests/integration

# Run through the CLI wrapper
permish postgres check

# Stop and remove the disposable database and volumes explicitly
docker compose -f integration/docker-compose.yml down -v --remove-orphans
```

The demo has two repository implementations:

- `VulnerableRecordRepository` omits the tenant predicate, which is demonstrated
  only while the test fixture temporarily replaces RLS policies with permissive
  policies. This database exists only on local port `54329` and is destroyed at
  teardown.
- `FixedRecordRepository` includes `tenant_id = principal.tenant_id` in the SQL
  query. The test fixture also restores PostgreSQL RLS as defense in depth.

Synthetic principals are mapped to database roles explicitly inside
`permish.demo`: `alice -> permish_tenant_a -> tenant-a`, and
`bob -> permish_tenant_b -> tenant-b`. The HTTP principal header is a synthetic
test-context selector, not authentication and not an authorization tenant claim.
The Flask test client never opens a public port. `DemoHTTPPermissionPolicy` sends
the real HTTP request and reports `200-299` as observed access, so Permish
derives findings from executed behavior rather than labels.

`permish check` uses only synthetic in-memory principals and resources; it never connects to an identity provider or production database.

Exit codes:

- `0`: every executed check matched its expected result
- `1`: a confirmed authorization violation or integration test failure
- `2`: setup, argument, Docker, or runtime error

## Engine behavior

`PermissionEngine.run()` compares a policy's `can_read(principal, resource)` result with the expected result for every cross-tenant principal/resource pairing. A finding is emitted only when the policy unexpectedly allows access or does not match the expected result.

The built-in examples demonstrate both sides of the contract:

- `SafeTenantPolicy` allows private reads only when principal and resource tenant IDs match.
- `VulnerableTenantPolicy` intentionally allows every private read so the engine can prove that it detects the regression.
- `PermissionEngine.authorize()` fails closed for identities or resources outside the caller-supplied known sets. Policy exceptions are also denied.

```python
from permish import PermissionEngine, Principal, PrivateResource
from permish.examples import SafeTenantPolicy

engine = PermissionEngine()
report = engine.run(
    SafeTenantPolicy(),
    principals=(Principal("alice", "tenant-a"), Principal("bob", "tenant-b")),
    resources=(
        PrivateResource("private-a", "tenant-a"),
        PrivateResource("private-b", "tenant-b"),
    ),
)

assert report.passed
assert report.findings == ()
```

## Tests

The automated tests verify:

- A tenant-scoped policy denies all modeled cross-tenant reads and allows same-tenant reads.
- An intentionally vulnerable policy yields concrete findings for each violation.
- Unknown users and unknown resources are denied even when the policy always allows access.
- Policy exceptions fail closed.
- Same-tenant pairings are excluded from the default cross-tenant scan, but can be included with `cross_tenant_cases_only=False`.

## Current scope and remaining work

Implemented:

- Deterministic in-memory data model and policy protocol.
- Safe and intentionally vulnerable policy examples.
- Pass/fail report and structured violation findings.
- Local example and automated cross-tenant regression tests.

Not implemented yet:

- Adapter integrations for HTTP frameworks, most ORMs, identity providers, or production authorization systems.
- Authentication or integration with real identity stores, user role modeling, write/update/delete actions, public resources, policy mutation testing, and database-backed resource discovery.
- CI configuration and a persistent declarative test suite format.
- Coverage synthesis beyond the explicitly supplied tenant/principal/resource fixtures.

These omissions are deliberate boundaries. Unit tests prove authorization decisions against supplied in-memory facts.

## PostgreSQL integration tests

The PostgreSQL integration suite is separate and opt-in. It requires Docker with Compose support and uses only synthetic data. The pinned image is `postgres:16.5-bookworm`, exposed only on local port `54329`.

```bash
python3 -m pip install -e '.[postgres]' --user
pytest -q -m integration tests/integration
```

The integration fixture runs `docker compose up -d --wait`, creates the database, then tears it down with `docker compose down -v --remove-orphans`. It creates two non-superuser login roles, `permish_tenant_a` and `permish_tenant_b`, and maps each role to a synthetic tenant through PostgreSQL `session_user`. Security assertions connect directly as those roles; the privileged setup connection is used only for schema initialization and fixture reset.

The suite verifies PostgreSQL RLS behavior for `SELECT`, `INSERT`, `UPDATE`, and `DELETE`, for both same-tenant and cross-tenant operations. A deliberately vulnerable configuration replaces the safe policies with policies that allow every tenant operation; `PostgreSQLPermissionPolicy` issues SQL under the tenant role, and the Permish engine reports the resulting real row as a finding.

Ordinary unit runs exclude integration tests through pytest configuration:

```bash
pytest -q
```

Prerequisites are Docker and Docker Compose, network access on the first run to pull the pinned image, and the optional `permish[postgres]` Python dependency. Do not reuse production credentials or database hosts. The integration is limited to an isolated PostgreSQL table and synthetic roles; it does not claim to validate application frameworks, identity providers, database migrations, backups, or real production infrastructure.
