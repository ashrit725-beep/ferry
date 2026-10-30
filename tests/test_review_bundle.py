"""Adversarial review tests for area 'bundle' (reviewer-authored; the fixer makes them pass).

Each test encodes the SECURE behaviour and FAILS against the current code, proving a
real defect in bundle acceptance. Nothing here is xfail.
"""

from __future__ import annotations

import pickle

import pytest

from ferry.bundle.importer import import_bundle
from ferry.bundle.verify import verify_bundle
from ferry.config import ImportSettings, Settings
from ferry.db import Database
from ferry.trust import add_key, load_trust_store

from tests.helpers_bundle import crafted_bundle, make_signer, make_workspace

ACTOR = {"actor_type": "cli", "actor_id": "tester"}


# --------------------------------------------------------------------------- Finding 1
# history_problem() detects version reuse with a raw string compare (r["version"] == version)
# while it orders versions with version_key() (which strips build metadata and normalises
# "1.0" == "1.0.0"). So two different-content bundles whose versions are version_key-EQUAL but
# string-DISTINCT are each accepted: neither "version reuse" (strings differ) nor "rollback"
# (keys are equal, not >) fires. This defeats policy.version_reuse (v1-additions A1).


# "1.0.007" is version_key-equal to "1.0.7" (not to "1.0.0", which it follows as an upgrade),
# so the leading-zero case pairs it with 1.0.7.
@pytest.mark.parametrize("first_version, second_version",
                         [("1.0.0", "1.0.0+evil"), ("1.0.0", "1.0"), ("1.0.7", "1.0.007")])
def test_equivalent_version_string_with_different_content_is_rejected(tmp_path, first_version, second_version):
    ws = make_workspace(tmp_path)
    first = ws.pack(version=first_version, out=tmp_path / "out1")
    # Change a source so the second bundle has genuinely different content (new bundle_id)
    # while its version is semantically the same release as 1.0.0.
    ws.add_source("LICENSE", b"attacker-substituted weights\n")
    second = ws.pack(version=second_version, out=tmp_path / "out2")
    assert first.bundle_id != second.bundle_id

    (tmp_path / "data").mkdir()
    settings = Settings(data_dir=tmp_path / "data", imports=ws.policy())
    db = Database(settings.db_path)
    db.init()

    assert import_bundle(settings, db, first.bundle_path, **ACTOR).accepted
    result = import_bundle(settings, db, second.bundle_path, **ACTOR)

    # Same name, same semantic version, different content: must be refused, not silently
    # registered as a second bundle under a confusable version.
    assert not result.accepted, (
        f"bundle {second_version!r} (version_key-equal to the imported {first_version}) with different "
        "content was accepted; policy.version_reuse was bypassed")


# --------------------------------------------------------------------------- Finding 2
# detect_format() only treats a raw pickle as pickle when head[0]==0x80 and head[1] in 2..5
# (protocol 2-5). Pickle protocols 0 and 1 also execute arbitrary code on load (GLOBAL+REDUCE)
# but start with ordinary opcode bytes, so they are classified as "text" (proto 0) or "binary"
# (proto 1). A code-executing pickle can therefore be imported as a benign document/config with
# the DEFAULT policy (allow_pickle=False), defeating threat-model control #4 and the guarantee in
# ferry/formats.py ("a pickle renamed to .bin is still pickle").


class _Evil:
    def __reduce__(self):  # executes os.system("true") when unpickled
        import os

        return (os.system, ("true",))


def _pickle_bundle(tmp_path, protocol, declared_fmt):
    payload = pickle.dumps(_Evil(), protocol=protocol)
    pub = make_signer("pub")
    trust_dir = tmp_path / "trust"
    add_key(trust_dir, pub.pem, name="Acme build", roles=["publisher"])
    path = crafted_bundle(
        tmp_path / f"p{protocol}.tar", [pub],
        [("artifacts/config/tokenizer_config.txt", payload, {"kind": "document", "fmt": declared_fmt})],
        name="legit-model", version="1.0.0")
    report = verify_bundle(path, ImportSettings(trust_dir=str(trust_dir)), load_trust_store(trust_dir))
    return report


def test_protocol0_pickle_is_not_accepted_as_text(tmp_path):
    report = _pickle_bundle(tmp_path, 0, "text")
    assert report.artifacts[0]["detected_format"] == "pickle", (
        "a protocol-0 pickle that runs code on load was classified as "
        f"{report.artifacts[0]['detected_format']!r}, not pickle")
    assert not report.accepted, "code-executing protocol-0 pickle accepted as a text document"


def test_protocol1_pickle_is_not_accepted_as_binary(tmp_path):
    report = _pickle_bundle(tmp_path, 1, "binary")
    assert report.artifacts[0]["detected_format"] == "pickle", (
        "a protocol-1 pickle that runs code on load was classified as "
        f"{report.artifacts[0]['detected_format']!r}, not pickle")
    assert not report.accepted, "code-executing protocol-1 pickle accepted as a binary document"
