"""Command-line interface for Permish authorization regression checks."""

import argparse
import json
import shutil
import subprocess
import sys
from typing import Sequence

from .engine import PermissionEngine, Principal, PrivateResource
from .examples import SafeTenantPolicy, VulnerableTenantPolicy


EXIT_SUCCESS = 0
EXIT_VIOLATION = 1
EXIT_ERROR = 2


def build_check_report(mode: str) -> dict:
    principals = (
        Principal("alice", "tenant-a"),
        Principal("bob", "tenant-b"),
    )
    resources = (
        PrivateResource("private-a", "tenant-a"),
        PrivateResource("private-b", "tenant-b"),
    )
    policy = SafeTenantPolicy() if mode == "safe" else VulnerableTenantPolicy()
    report = PermissionEngine().run(policy, principals, resources)

    checks = []
    findings = []
    for result in report.results:
        expected = "allow" if result.expected_allowed else "deny"
        observed = "allow" if result.actual_allowed else "deny"
        check_id = (
            f"cross-tenant-read:{result.principal.principal_id}:"
            f"{result.resource.resource_id}"
        )
        check = {
            "id": check_id,
            "action": "read",
            "expected": expected,
            "observed": observed,
            "expected_result": expected,
            "observed_result": observed,
            "passed": result.passed,
            "status": "passed" if result.passed else "failed",
        }
        checks.append(check)
        if not result.passed:
            findings.append({
                "check_id": check_id,
                "principal": result.principal.principal_id,
                "tenant": result.principal.tenant_id,
                "resource": result.resource.resource_id,
                "resource_tenant": result.resource.tenant_id,
            })

    return {
        "command": "check",
        "schema_version": 1,
        "mode": mode,
        "scope": "in-memory synthetic cross-tenant reads",
        "status": "passed" if report.passed else "failed",
        "passed": report.passed,
        "check_count": len(checks),
        "checks": checks,
        "finding_count": len(findings),
        "findings": findings,
    }


def run_check(args: argparse.Namespace) -> int:
    report = build_check_report(args.mode)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Permish {args.mode} check: {'PASS' if report['passed'] else 'FAIL'}")
        print(f"Checks: {report['check_count']}; findings: {report['finding_count']}")
        for finding in report["findings"]:
            print(
                f"Violation {finding['check_id']}: {finding['principal']} "
                f"observed access to {finding['resource']}"
            )
    return EXIT_SUCCESS if report["passed"] else EXIT_VIOLATION


def run_postgres(args: argparse.Namespace) -> int:
    if shutil.which("docker") is None:
        print("Error: Docker is required for PostgreSQL integration checks.", file=sys.stderr)
        return EXIT_ERROR

    compose_check = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
    )
    if compose_check.returncode != 0:
        print("Error: Docker Compose v2 is required for PostgreSQL integration checks.", file=sys.stderr)
        return EXIT_ERROR

    pytest_executable = shutil.which("pytest")
    if pytest_executable is None:
        print("Error: pytest is required for PostgreSQL integration checks.", file=sys.stderr)
        return EXIT_ERROR

    command = [pytest_executable, "-q", "-m", "integration", "tests/integration"]
    print("Running disposable PostgreSQL integration suite...")
    completed = subprocess.run(command)
    if completed.returncode == 0:
        return EXIT_SUCCESS
    if completed.returncode == 1:
        print("Error: a PostgreSQL integration test failed.", file=sys.stderr)
        return EXIT_VIOLATION
    return EXIT_ERROR


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permish",
        description="Run deterministic authorization regression checks.",
    )
    parser.epilog = (
        "Exit codes: 0 = all executed checks passed; "
        "1 = confirmed authorization violations; 2 = setup or runtime error."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check",
        help="Run a synthetic in-memory authorization check.",
        description=(
            "Run two synthetic cross-tenant reads. Safe mode must pass; "
            "vulnerable mode is an intentional violation demo and exits 1."
        ),
    )
    check_parser.add_argument(
        "--mode",
        choices=("safe", "vulnerable"),
        default="safe",
        help="Policy to exercise (default: safe).",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Write the complete machine-readable report to stdout.",
    )
    check_parser.set_defaults(handler=run_check)

    postgres_parser = subparsers.add_parser(
        "postgres",
        help="Run the opt-in PostgreSQL integration suite.",
        description="Manage disposable PostgreSQL integration checks.",
    )
    postgres_subparsers = postgres_parser.add_subparsers(dest="postgres_command", required=True)
    postgres_check_parser = postgres_subparsers.add_parser(
        "check",
        help="Start the disposable PostgreSQL database and run integration tests.",
    )
    postgres_check_parser.set_defaults(handler=run_postgres)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
