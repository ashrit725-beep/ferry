"""Doctor checks and network inventory tests (spec section 10). No test here
touches the network: the opt-in isolation probe is exercised with its TCP
connect replaced, and the default run is shown never to call it.
"""

from __future__ import annotations

import dataclasses
import importlib.metadata
import os
from pathlib import Path

import pytest

from ferry import backends, doctor
from ferry.cli import main as cli_main
from ferry.config import GatewaySettings, ImportSettings, ServerSettings, Settings, load_settings
from ferry.db import Database

from helpers_gateway import ACTOR, write_token


@pytest.fixture
def installed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Settings:
    data = tmp_path / "data"
    assert cli_main(["init", "--data-dir", str(data)]) == 0
    capsys.readouterr()
    return load_settings(data_dir=data)


def _checks(settings: Settings, **kw) -> dict[str, dict[str, str]]:
    with Database(settings.db_path).session() as conn:
        results = doctor.run_checks(settings, conn, environ=kw.pop("environ", {}), **kw)
    for check in results:
        assert set(check) == {"id", "status", "message"} and check["status"] in ("pass", "warn", "fail")
    return {c["id"]: c for c in results}


def test_a_fresh_installation(installed: Settings) -> None:
    checks = _checks(installed)
    assert {k: v["status"] for k, v in checks.items()} == {
        "permissions.data_dir": "pass", "permissions.database": "pass", "permissions.secrets": "pass",
        "trust.store": "warn", "backends.addresses": "pass", "tls": "pass", "proxy.environment": "pass",
        "console.assets": "pass", "telemetry.packages": "pass", "config.policy": "pass", "console.admins": "warn",
        "audit.chain": "pass",
    }
    assert "ferry trust add" in checks["trust.store"]["message"]
    assert "network.isolation" not in checks


def test_permission_problems(installed: Settings) -> None:
    os.chmod(installed.data_dir, 0o750)
    assert _checks(installed)["permissions.data_dir"]["status"] == "warn"
    os.chmod(installed.data_dir, 0o777)
    assert _checks(installed)["permissions.data_dir"]["status"] == "fail"
    os.chmod(installed.data_dir, 0o700)
    os.chmod(installed.db_path, 0o644)
    assert _checks(installed)["permissions.database"]["status"] == "warn"
    os.chmod(installed.db_path, 0o666)
    assert _checks(installed)["permissions.database"]["status"] == "fail"
    os.chmod(installed.db_path, 0o600)
    token = write_token(installed, "leaky", "abc")
    assert _checks(installed)["permissions.secrets"]["status"] == "pass"
    os.chmod(token, 0o644)
    secrets = _checks(installed)["permissions.secrets"]
    assert secrets["status"] == "fail" and "leaky.token" in secrets["message"] and "abc" not in secrets["message"]


def test_trust_store_problems_warn(installed: Settings) -> None:
    (installed.trust_dir / "stray.json").write_text("{}")
    check = _checks(installed)["trust.store"]
    assert check["status"] == "warn" and "stray.json" in check["message"]


def test_backend_addresses(installed: Settings) -> None:
    public = dataclasses.replace(installed, gateway=GatewaySettings(allow_public_backends=True))
    with Database(installed.db_path).session() as conn:
        backends.create_backend(conn, installed, name="private", kind="openai", base_url="http://10.1.2.3:8000",
                                **ACTOR)
        assert _checks(installed)["backends.addresses"]["status"] == "pass"
        backends.create_backend(conn, public, name="public", kind="openai", base_url="http://93.184.216.34:80",
                                **ACTOR)
    allowed = _checks(public)["backends.addresses"]
    assert allowed["status"] == "warn" and "93.184.216.34" in allowed["message"]
    refused = _checks(installed)["backends.addresses"]
    assert refused["status"] == "fail" and "public" in refused["message"] and "private" not in refused["message"]


def test_tls_status(installed: Settings, tmp_path: Path) -> None:
    def with_server(**kw) -> Settings:
        return dataclasses.replace(installed, server=ServerSettings(**kw))

    assert _checks(with_server(host="0.0.0.0"))["tls"]["status"] == "warn"
    assert _checks(with_server(host="::1"))["tls"]["status"] == "pass"
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    missing = _checks(with_server(host="0.0.0.0", tls_cert_file=str(cert), tls_key_file=str(key)))["tls"]
    assert missing["status"] == "fail"
    cert.write_text("cert")
    key.write_text("key")
    os.chmod(key, 0o644)
    assert _checks(with_server(host="0.0.0.0", tls_cert_file=str(cert), tls_key_file=str(key)))["tls"]["status"] == "warn"
    os.chmod(key, 0o600)
    assert _checks(with_server(host="0.0.0.0", tls_cert_file=str(cert), tls_key_file=str(key)))["tls"]["status"] == "pass"


def test_proxy_variables_are_named_but_never_printed(installed: Settings) -> None:
    check = _checks(installed, environ={"HTTPS_PROXY": "http://user:hunter2@proxy.internal:3128",
                                        "no_proxy": "localhost", "PATH": "/bin"})["proxy.environment"]
    assert check["status"] == "warn"
    assert "HTTPS_PROXY" in check["message"] and "no_proxy" in check["message"]
    assert "hunter2" not in check["message"] and "proxy.internal" not in check["message"]


def test_console_assets_are_scanned_for_external_urls(installed: Settings, tmp_path: Path) -> None:
    assert doctor.scan_static(doctor.STATIC_DIR) == []
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    assert _checks(installed, static_dir=static)["console.assets"]["status"] == "warn"
    (static / "index.html").write_text('<script src="/assets/app.js"></script>')
    (static / "assets" / "app.js").write_text("const x = 1;")
    assert _checks(installed, static_dir=static)["console.assets"]["status"] == "pass"
    (static / "assets" / "app.css").write_text("@font-face { src: url(HTTPS://fonts.example/x.woff2) }")
    check = _checks(installed, static_dir=static)["console.assets"]
    assert check["status"] == "fail" and "assets/app.css" in check["message"]


def test_telemetry_capable_packages_are_flagged(installed: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(doctor, "installed_distributions", lambda: {
        "sentry-sdk": "2.0", "opentelemetry-exporter-otlp-proto-http": "1.0", "opentelemetry-api": "1.45",
        "fastapi": "0.162"})
    check = _checks(installed)["telemetry.packages"]
    assert check["status"] == "warn"
    assert "sentry-sdk" in check["message"] and "opentelemetry-exporter-otlp-proto-http" in check["message"]
    assert "opentelemetry-api" not in check["message"]
    monkeypatch.setattr(doctor, "installed_distributions", lambda: {"opentelemetry-api": "1.45"})
    clean = _checks(installed)["telemetry.packages"]
    assert clean["status"] == "pass" and "opentelemetry-api is present" in clean["message"]


def test_weakened_settings_warn(installed: Settings) -> None:
    weak = dataclasses.replace(installed, imports=ImportSettings(allow_pickle=True, allow_executables=True),
                               gateway=GatewaySettings(allow_public_backends=True))
    check = _checks(weak)["config.policy"]
    assert check["status"] == "warn"
    assert "allow_pickle" in check["message"] and "allow_executables" in check["message"]
    assert "allow_public_backends" in check["message"]


def test_admins_and_audit_chain(installed: Settings) -> None:
    from ferry import auth

    with Database(installed.db_path).session() as conn:
        auth.create_admin_user(conn, "root", "a-long-enough-password", "admin", actor_type="cli", actor_id="t")
        assert _checks(installed)["console.admins"]["status"] == "pass"
        conn.execute("UPDATE audit_events SET outcome = 'failure' WHERE seq = 1")
    check = _checks(installed)["audit.chain"]
    assert check["status"] == "fail" and "#1" in check["message"]


def test_the_network_probe_is_opt_in(installed: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("the probe must not run unless asked for")

    monkeypatch.setattr(doctor, "tcp_connect", forbidden)
    assert "network.isolation" not in _checks(installed)

    calls: list[tuple[str, int]] = []

    def unreachable(address: tuple[str, int], timeout: float) -> str:
        calls.append(address)
        assert timeout == doctor.PROBE_TIMEOUT_S == 2.0
        return "timed out"

    monkeypatch.setattr(doctor, "tcp_connect", unreachable)
    isolated = _checks(installed, probe_network=True)["network.isolation"]
    assert isolated["status"] == "pass" and "1.1.1.1:443: timed out" in isolated["message"]
    assert calls == list(doctor.PROBE_TARGETS)

    monkeypatch.setattr(doctor, "tcp_connect", lambda address, timeout: None)
    exposed = _checks(installed, probe_network=True)["network.isolation"]
    assert exposed["status"] == "fail" and "NOT isolated" in exposed["message"]


def test_network_inventory(installed: Settings) -> None:
    with Database(installed.db_path).session() as conn:
        assert [i["direction"] for i in doctor.network_inventory(installed, conn)][0] == "inbound"
        token = write_token(installed, "llama", "inventory-secret-xyz")
        llama = backends.create_backend(conn, installed, name="llama", kind="llamacpp", base_url="http://127.0.0.1:8080",
                                        auth_token_file=str(token), **ACTOR)
        backends.create_route(conn, model="qwen", backend_id=llama["id"], require_verified=False, **ACTOR)
        backends.create_backend(conn, installed, name="local-name", kind="ollama", base_url="http://localhost:11434",
                                **ACTOR)
        inventory = doctor.network_inventory(installed, conn)
    for item in inventory:
        assert set(item) == {"component", "direction", "destination", "purpose", "configurable", "notes"}
        assert isinstance(item["configurable"], bool)
    by_component = {i["component"]: i for i in inventory}
    listener = by_component["gateway listener (ferry serve)"]
    assert listener["destination"] == "127.0.0.1:8750" and "loopback only" in listener["notes"]
    assert "plain HTTP" in listener["notes"]
    backend = by_component["backend llama (llamacpp)"]
    assert backend["direction"] == "outbound" and backend["destination"] == "http://127.0.0.1:8080"
    assert "qwen" in backend["purpose"] and "bearer token configured" in backend["notes"]
    assert "inventory-secret-xyz" not in str(inventory)
    assert by_component["backend name resolution"]["purpose"].startswith("resolve localhost")
    assert by_component["telemetry, crash reporting, update and licence checks"]["direction"] == "none"
    probe = by_component["ferry doctor --probe-network"]
    assert probe["direction"] == "outbound (opt-in)" and "1.1.1.1:443" in probe["destination"]


def test_dependency_closure_reports_installed_versions() -> None:
    deps = {d["name"].lower(): d["version"] for d in doctor.dependencies()}
    for name in ("fastapi", "starlette", "uvicorn", "h11", "httpx", "httpcore", "anyio", "cryptography", "pydantic",
                 "pydantic_core"):
        key = next(k for k in deps if k.replace("-", "_") == name)
        assert deps[key] == importlib.metadata.version(name), name
    assert "pytest" not in deps, "development tools are not runtime dependencies"
