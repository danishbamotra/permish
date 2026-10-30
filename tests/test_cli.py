import json

from permish.cli import EXIT_ERROR, EXIT_SUCCESS, EXIT_VIOLATION, create_parser, main


def test_safe_check_json_output(capsys):
    exit_code = main(["check", "--mode", "safe", "--json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == EXIT_SUCCESS
    assert report["passed"] is True
    assert report["finding_count"] == 0
    assert report["check_count"] == 2
    assert report["schema_version"] == 1
    assert report["status"] == "passed"
    assert report["checks"][0]["action"] == "read"
    assert report["checks"][0]["expected"] == "deny"
    assert report["checks"][0]["observed"] == "deny"
    assert report["checks"][0]["expected_result"] == "deny"
    assert report["checks"][0]["observed_result"] == "deny"


def test_vulnerable_check_returns_violation_and_json_findings(capsys):
    exit_code = main(["check", "--mode", "vulnerable", "--json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == EXIT_VIOLATION
    assert report["passed"] is False
    assert report["status"] == "failed"
    assert report["finding_count"] == 2
    assert {finding["check_id"] for finding in report["findings"]} == {
        "cross-tenant-read:alice:private-b",
        "cross-tenant-read:bob:private-a",
    }
    assert all(check["observed"] == "allow" for check in report["checks"])


def test_postgres_check_reports_missing_docker(monkeypatch, capsys):
    monkeypatch.setattr("permish.cli.shutil.which", lambda name: None)

    exit_code = main(["postgres", "check"])

    captured = capsys.readouterr()
    assert exit_code == EXIT_ERROR
    assert "Docker is required" in captured.err


def test_help_lists_permission_check_commands(capsys):
    parser = create_parser()

    assert parser.prog == "permish"
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == EXIT_SUCCESS

    help_output = capsys.readouterr().out
    assert "check" in help_output
    assert "postgres" in help_output


def test_check_help_describes_exit_codes(capsys):
    try:
        main(["check", "--help"])
    except SystemExit as exc:
        assert exc.code == EXIT_SUCCESS

    help_output = capsys.readouterr().out
    assert "Safe mode must pass" in help_output
    assert "--mode" in help_output
    assert "--json" in help_output
