"""End-to-end: the primary workflow as an operator would run it, through the
real CLI (subprocesses) and the real server (uvicorn on 127.0.0.1).

Connected side: keygen for a publisher and a reviewer, pack a tiny GGUF bundle,
countersign. Disconnected side: init, trust both keys with their roles,
require both roles in ferry.toml, verify, import, reject a tampered copy
without importing anything, then serve: register a backend and a pinned route
(the backend is tests/helpers_upstream.FakeUpstream, a TEST DOUBLE whose
/props reports the imported store file), create apps and keys, activate a
policy, and show that the authorized app gets completions while a different
model, an app without permission and a revoked key are refused before
anything reaches the backend. Finally the audit chain verifies and the
evidence report shows the import, the policy version and verified provenance.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import httpx

from ferry.config import load_settings
from ferry.gateway.app import create_app

from helpers_bundle import gguf_bytes, make_workspace
from helpers_gateway import bearer, chat_body, live_server, write_token
from helpers_upstream import FakeUpstream
from test_cli import code, ferry, ok

CREATED_AT = "2026-10-28T02:00:00Z"
CSRF = {"X-Ferry-CSRF": "1"}
OPS_PASSWORD = "ops-console-password-1"


def _key_id(keygen_stdout: str) -> str:
    match = re.search(r"Key id\s+([0-9a-f]{64})", keygen_stdout)
    assert match, keygen_stdout
    return match.group(1)


def _flip_model_byte(bundle: Path, target: Path) -> Path:
    data = bytearray(bundle.read_bytes())
    start = data.find(b"GGUF\x03\x00\x00\x00")
    assert start > 0, "the GGUF member was not found in the tar"
    data[start + len(gguf_bytes()) - 1] ^= 0xFF
    target.write_bytes(bytes(data))
    return target


def _store_files(data: Path) -> list[str]:
    return sorted(p.name for p in (data / "store" / "sha256").iterdir())


def test_primary_workflow(tmp_path: Path) -> None:
    # ---------------------------------------------------------------- connected side
    workspace = make_workspace(tmp_path / "vendor")  # model sources and a pack spec writer
    keys, out = tmp_path / "keys", tmp_path / "out"
    passphrase = tmp_path / "reviewer.pass"
    passphrase.write_text("reviewer key passphrase\n")
    os.chmod(passphrase, 0o600)
    publisher_id = _key_id(ok(ferry("keygen", "publisher", "--out-dir", keys, "--no-passphrase")).stdout)
    reviewer_id = _key_id(ok(ferry("keygen", "reviewer", "--out-dir", keys, "--passphrase-file", passphrase)).stdout)
    packed = json.loads(ok(ferry("pack", workspace.spec(), "--key", keys / "publisher.key", "--out", out,
                                 "--created-at", CREATED_AT, "--json")).stdout)
    bundle = Path(packed["bundle_path"])
    ok(ferry("sign", bundle, "--key", keys / "reviewer.key", "--passphrase-file", passphrase))
    single = json.loads(ok(ferry("pack", workspace.spec(version="1.0.1", spec_name="single.toml"), "--key",
                                 keys / "publisher.key", "--out", out, "--created-at", CREATED_AT, "--json")).stdout)

    # ---------------------------------------------------------------- disconnected side: verify and import
    data = tmp_path / "enclave"
    ok(ferry("init", "--data-dir", data))
    config = data / "ferry.toml"
    text = config.read_text()
    assert 'required_roles = ["publisher"]' in text and "health_interval_s = 30.0" in text
    config.write_text(text.replace('required_roles = ["publisher"]', 'required_roles = ["publisher", "reviewer"]', 1)
                      .replace("health_interval_s = 30.0", "health_interval_s = 0.0", 1))
    D = ["--data-dir", data]
    inbox = data / "inbox"
    arrived = Path(shutil.copy(bundle, inbox / bundle.name))
    ok(ferry(*D, "trust", "add", keys / "publisher.pub.pem", "--name", "Vendor build", "--role", "publisher",
             "--expect-fingerprint", publisher_id[:16]))
    ok(ferry(*D, "trust", "add", keys / "reviewer.pub.pem", "--name", "Vendor review", "--role", "reviewer",
             "--expect-fingerprint", reviewer_id[:16]))

    assert ok(ferry(*D, "verify", arrived)).stdout.startswith("ACCEPTED")
    one_signature = code(ferry(*D, "verify", single["bundle_path"]), 1)
    assert "signatures.roles" in one_signature.stdout and "'reviewer' is not satisfied" in one_signature.stdout

    imported = json.loads(ok(ferry(*D, "import", arrived, "--json")).stdout)
    assert imported["verdict"] == "accepted" and imported["already_imported"] is False
    bundle_id = imported["bundle_id"]
    assert bundle_id == packed["bundle_id"], "countersigning never changes the bundle id"
    digest = next(a["actual_sha256"] for a in imported["report"]["artifacts"] if a["kind"] == "model")
    store_before = _store_files(data)
    assert digest in store_before and len(store_before) == 3

    tampered = _flip_model_byte(arrived, inbox / "tampered.ferry.tar")
    rejected = json.loads(code(ferry(*D, "import", tampered, "--json"), 1).stdout)
    assert rejected["verdict"] == "rejected"
    assert [c["id"] for c in rejected["report"]["checks"] if c["status"] == "fail"] == ["artifact.digest"]
    assert any("artifacts/models/tiny.gguf: SHA-256 is" in e for e in rejected["report"]["errors"])
    assert _store_files(data) == store_before, "nothing from the tampered copy reached the store"
    assert not [p for p in (data / "store" / "tmp").iterdir()], "no staging files are left behind"

    ok(ferry(*D, "admin", "create-user", "ops", "--role", "admin", "--password-stdin", input=OPS_PASSWORD + "\n"))

    # ---------------------------------------------------------------- serve
    settings = load_settings(data_dir=data)
    assert settings.imports.required_roles == ("publisher", "reviewer")
    with FakeUpstream() as upstream:
        upstream.model_path = str(settings.store_dir / "sha256" / digest)
        token_file = write_token(settings, "llama", upstream.token)
        with live_server(create_app(settings)) as base, httpx.Client(base_url=base, trust_env=False) as http:
            assert http.post("/api/auth/login", json={"username": "ops", "password": OPS_PASSWORD},
                             headers=CSRF).status_code == 200
            backend = http.post("/api/backends", json={"name": "llama", "kind": "llamacpp", "base_url": upstream.base_url,
                                                       "auth_token_file": str(token_file)}, headers=CSRF)
            assert backend.status_code == 201, backend.text
            backend_id = backend.json()["id"]
            status = http.post(f"/api/backends/{backend_id}/check", headers=CSRF).json()["status"]
            assert status["state"] == "up" and status["served"][0]["digest"] == digest
            route = http.post("/api/routes", json={"model": "tiny", "backend_id": backend_id,
                                                   "upstream_model": "fake-alias", "artifact_digest": digest},
                              headers=CSRF).json()
            assert route["provenance"]["state"] == "verified" and route["available"] is True
            # A second, unpinned route on the same backend: only the policy stands between apps and it.
            assert http.post("/api/routes", json={"model": "other-model", "backend_id": backend_id,
                                                  "require_verified": False}, headers=CSRF).status_code == 201

            app_id = http.post("/api/apps", json={"name": "report-assistant", "environment": "pilot"},
                               headers=CSRF).json()["id"]
            issued = http.post(f"/api/apps/{app_id}/keys", json={}, headers=CSRF).json()
            key = issued["api_key"]
            other_id = http.post("/api/apps", json={"name": "other-app", "environment": "pilot"},
                                 headers=CSRF).json()["id"]
            other_key = http.post(f"/api/apps/{other_id}/keys", json={}, headers=CSRF).json()["api_key"]
            policy_doc = {"schema": "ferry.dev/access-policy/v1", "description": "pilot: one app, one model",
                          "rules": [{"id": "report-tiny", "effect": "allow", "principals": ["app:report-assistant"],
                                     "actions": ["chat.completions"], "models": ["tiny"],
                                     "limits": {"max_tokens": 64, "allow_stream": True}}]}
            activated = http.post("/api/policy/activate", json={"document": policy_doc, "comment": "pilot"},
                                  headers=CSRF)
            assert activated.status_code == 201 and activated.json()["version"] == 1
            upstream.clear()

            # The authorized app: a plain and a streamed completion.
            answer = http.post("/v1/chat/completions", json=chat_body("tiny", max_tokens=500), headers=bearer(key))
            assert answer.status_code == 200, answer.text
            assert answer.json()["model"] == "tiny"
            assert answer.json()["choices"][0]["message"]["content"] == upstream.completion_text
            assert answer.headers["x-ferry-max-tokens"] == "64"
            with http.stream("POST", "/v1/chat/completions", json=chat_body("tiny", stream=True),
                             headers=bearer(key)) as streamed:
                assert streamed.status_code == 200
                lines = [line for line in streamed.iter_lines() if line.startswith("data: ")]
            assert lines[-1] == "data: [DONE]"
            assert all(json.loads(line[6:])["model"] == "tiny" for line in lines[:-1])
            forwarded = upstream.chat_requests()
            assert len(forwarded) == 2
            first = forwarded[0].json()
            assert first["model"] == "fake-alias" and first["max_tokens"] == 64
            assert forwarded[0].headers["authorization"] == f"Bearer {upstream.token}"
            assert all("fyk_" not in json.dumps(r.headers) for r in forwarded), "app keys are never forwarded"
            assert [m["id"] for m in http.get("/v1/models", headers=bearer(key)).json()["data"]] == ["tiny"]
            assert http.get("/v1/models", headers=bearer(other_key)).json()["data"] == []

            # Refused before the backend: another model, an app without permission, a revoked key.
            other_model = http.post("/v1/chat/completions", json=chat_body("other-model"), headers=bearer(key))
            assert other_model.status_code == 403 and "no rule allows" in other_model.json()["error"]["message"]
            other_app = http.post("/v1/chat/completions", json=chat_body("tiny"), headers=bearer(other_key))
            assert other_app.status_code == 403 and other_app.json()["error"]["type"] == "permission_denied"
            assert http.post(f"/api/keys/{issued['key_id']}/revoke", headers=CSRF).status_code == 200
            revoked = http.post("/v1/chat/completions", json=chat_body("tiny"), headers=bearer(key))
            assert revoked.status_code == 401 and revoked.json()["error"]["type"] == "authentication_error"
            assert len(upstream.chat_requests()) == 2, "no refused request reached the backend"

            # Audit and evidence, as the console shows them.
            assert http.post("/api/audit/verify", headers=CSRF).json()["ok"] is True
            evidence = http.get("/api/evidence").json()
            overview = http.get("/api/overview").json()
    assert overview["traffic_24h"]["success"] == 2 and overview["traffic_24h"]["denied"] == 2
    assert overview["traffic_24h"]["unauthenticated"] == 1 and overview["traffic_by_environment_24h"]["pilot"] == 4

    [imported_bundle] = evidence["bundles"]
    assert imported_bundle["bundle_id"] == bundle_id
    assert sorted(r for s in imported_bundle["signers"] for r in s["roles"]) == ["publisher", "reviewer"]
    assert evidence["verifications"]["by_mode"]["import"] == {"accepted": 1, "rejected": 1}
    assert evidence["active_policy"]["version"] == 1
    assert evidence["active_policy"]["sha256"] == activated.json()["sha256"]
    tiny = next(r for r in evidence["routes"] if r["model"] == "tiny")
    assert tiny["provenance"]["state"] == "verified" and tiny["pin"] == digest
    assert evidence["audit"]["ok"] is True

    # ---------------------------------------------------------------- afterwards, on the host
    assert "Audit chain intact" in ok(ferry(*D, "audit", "verify")).stdout
    markdown = ok(ferry(*D, "evidence", "--format", "md")).stdout
    assert bundle_id in markdown and "| Active version | 1 |" in markdown
    exported = ok(ferry(*D, "audit", "export")).stdout
    events = [json.loads(line) for line in exported.splitlines()]
    chats = [e for e in events if e["action"] == "gateway.chat.completions"]
    assert [e["outcome"] for e in chats] == ["success", "success", "denied", "denied", "unauthenticated"]
    # The body of an unauthenticated request is never parsed, so its event names no model.
    assert [e["details"]["model"] for e in chats] == ["tiny", "tiny", "other-model", "tiny", None]
    assert chats[4]["details"]["auth_failure"] == "revoked"
    assert all(e["policy_version"] == 1 for e in chats[:4])
    assert "Say hello." not in exported and upstream.completion_text not in exported, "no prompt or completion text"
    assert key.split("_", 2)[2] not in exported and upstream.token not in exported
    imports = [e for e in events if e["action"] == "bundle.import"]
    assert [e["outcome"] for e in imports] == ["success", "rejected"]
