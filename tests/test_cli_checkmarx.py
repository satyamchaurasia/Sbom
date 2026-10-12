"""CLI, Checkmarx client parsing and verification (Phases 4, 6, 7)."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from sbom_fixer.checkmarx import CheckmarxAcceptanceClient, CxConfig, UploadResult, count_packages, verify
from sbom_fixer.cli import app

from .conftest import bom

runner = CliRunner()


def test_cli_version_and_commands() -> None:
    assert "sbom-fixer 1.0.0" in runner.invoke(app, ["--version"]).output
    out = runner.invoke(app, ["--help"]).output
    assert all(c in out for c in ("fix", "fill-all", "verify"))
    for gone in ("check", "corrected", "audit", "fill-required", "schema-diff", "bisect", "rules", "cdxgen-fix"):
        assert runner.invoke(app, [gone, "--help"]).exit_code != 0


class FakeCx:
    def __init__(self, state: str = "completed", packages: int | None = 10) -> None:
        self.state, self.packages, self.paths = state, packages, []

    def upload(self, path: Path) -> UploadResult:
        self.paths.append(path)
        return UploadResult(self.state, scan_id="s1", package_count=self.packages, detail="fake")


def test_verify_tolerance() -> None:
    assert verify(FakeCx(packages=10), Path("x"), 10)[0]
    assert verify(FakeCx(packages=10), Path("x"), 10.4 and 10)[0]
    ok, res = verify(FakeCx(packages=8), Path("x"), 10)
    assert not ok and "differs" in res.detail
    assert not verify(FakeCx(state="failed"), Path("x"))[0]


def test_acceptance_adapter_writes_temp_file() -> None:
    cx = FakeCx()
    ok, reason = CheckmarxAcceptanceClient(cx).check(bom(), "cyclonedx", "1.5")
    assert ok and "scan s1" in reason and cx.paths[0].name == "probe-cyclonedx-1.5.json"


def test_cx_config_reports_missing_credentials(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    for k in ("CX_BASE_URI", "CX_APIKEY", "CX_CLIENT_ID", "CX_CLIENT_SECRET", "CX_BIN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    missing = CxConfig.from_env().missing()
    assert any("cx CLI" in m for m in missing) and "CX_BASE_URI" in missing


def test_count_packages_variants() -> None:
    assert count_packages({"scaPackages": [1, 2, 3]}) == 3
    assert count_packages({"summary": {"totalPackages": 7}}) == 7
    assert count_packages({"x": 1}) is None

