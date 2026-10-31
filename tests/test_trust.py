"""Trust store: adding, revoking, status over time, and fail-closed loading."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
from pathlib import Path

import pytest

from ferry import crypto
from ferry.errors import Conflict, CryptoError, NotFound, ValidationFailed
from ferry.trust import TrustEntry, TrustStore, add_key, load_trust_store, revoke_key

from helpers_bundle import make_signer

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def entry_doc(signer, **overrides):
    doc = {"key_id": signer.key_id, "name": "Hand written", "roles": ["publisher"],
           "public_key_pem": signer.pem.decode("ascii"), "not_before": None, "not_after": None,
           "revoked_at": None, "revocation_reason": None, "added_at": "2026-10-28T00:00:00.000Z", "comment": ""}
    doc.update(overrides)
    return doc


def write_entry(directory: Path, filename: str, doc) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc, encoding="utf-8")
    path.chmod(0o644)
    return path


def test_add_and_load(tmp_path):
    trust_dir = tmp_path / "trust"
    signer = make_signer("acme")
    entry = add_key(trust_dir, signer.pem, name="Acme low-side build", roles=["publisher"],
                    not_after="2027-10-28T00:00:00Z", comment="pilot key")
    assert entry.key_id == signer.key_id
    assert stat.S_IMODE(os.stat(trust_dir).st_mode) == 0o755
    path = trust_dir / f"{signer.key_id}.json"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    on_disk = json.loads(path.read_text())
    assert on_disk["not_after"] == "2027-10-28T00:00:00.000Z" and on_disk["revoked_at"] is None
    assert set(on_disk) == {"key_id", "name", "roles", "public_key_pem", "not_before", "not_after", "revoked_at",
                            "revocation_reason", "added_at", "comment"}

    store = load_trust_store(trust_dir)
    assert store.problems == [] and [e.key_id for e in store.entries] == [signer.key_id]
    loaded = store.get(signer.key_id)
    assert loaded is not None and loaded.roles == ("publisher",) and loaded.name == "Acme low-side build"
    assert loaded.status(NOW) == "active"
    assert crypto.key_id(loaded.public_key) == signer.key_id
    assert store.to_dict(NOW)["items"][0]["status"] == "active"


def test_existing_directory_permissions_are_left_alone(tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir(mode=0o700)
    add_key(trust_dir, make_signer("a").pem, name="A", roles=["reviewer"])
    assert stat.S_IMODE(os.stat(trust_dir).st_mode) == 0o700


def test_duplicates_are_refused(tmp_path):
    signer = make_signer("a")
    add_key(tmp_path, signer.pem, name="A", roles=["publisher"])
    with pytest.raises(Conflict):
        add_key(tmp_path, signer.pem, name="A again", roles=["reviewer"])


def test_a_revoked_key_cannot_be_re_added(tmp_path):
    signer = make_signer("a")
    add_key(tmp_path, signer.pem, name="A", roles=["publisher"])
    revoke_key(tmp_path, signer.key_id, "compromised")
    with pytest.raises(Conflict):
        add_key(tmp_path, signer.pem, name="A", roles=["publisher"])


@pytest.mark.parametrize("fingerprint_of", [
    lambda kid: kid[:16], lambda kid: kid, lambda kid: kid[:16].upper(),
    lambda kid: ":".join(kid[i:i + 2] for i in range(0, 32, 2)), lambda kid: "sha256:" + kid[:20],
])
def test_expected_fingerprint_accepted(tmp_path, fingerprint_of):
    signer = make_signer("a")
    add_key(tmp_path, signer.pem, name="A", roles=["publisher"], expect_fingerprint=fingerprint_of(signer.key_id))


def test_expected_fingerprint_mismatch_is_refused(tmp_path):
    signer, other = make_signer("a"), make_signer("b")
    with pytest.raises(CryptoError) as info:
        add_key(tmp_path, signer.pem, name="A", roles=["publisher"], expect_fingerprint=other.key_id[:16])
    assert info.value.code == "fingerprint_mismatch"
    assert not (tmp_path / f"{signer.key_id}.json").exists()


def test_expected_fingerprint_too_short(tmp_path):
    signer = make_signer("a")
    with pytest.raises(ValidationFailed):
        add_key(tmp_path, signer.pem, name="A", roles=["publisher"], expect_fingerprint=signer.key_id[:15])


@pytest.mark.parametrize("kwargs", [
    {"roles": []}, {"roles": ["admin"]}, {"roles": ["publisher", "publisher"]},
    {"name": ""}, {"name": "bad\x1bname"}, {"name": "x" * 129},
    {"not_before": "2027-01-01T00:00:00Z", "not_after": "2026-01-01T00:00:00Z"},
    {"not_after": "next year"}, {"not_after": dt.datetime(2027, 1, 1)},
    {"comment": "x" * 1001},
])
def test_add_key_validation(tmp_path, kwargs):
    args = {"name": "A", "roles": ["publisher"], **kwargs}
    with pytest.raises(ValidationFailed):
        add_key(tmp_path, make_signer("a").pem, **args)


def test_add_key_needs_an_ed25519_public_key(tmp_path):
    with pytest.raises(CryptoError):
        add_key(tmp_path, b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", name="A", roles=["publisher"])


def test_status_precedence():
    signer = make_signer("a")
    base = dict(key_id=signer.key_id, name="A", roles=("publisher",), public_key_pem="")
    window = TrustEntry(**base, not_before="2026-11-01T00:00:00Z", not_after="2026-10-01T00:00:00Z")
    assert window.status(NOW) == "not_yet_valid"  # not_yet_valid outranks expired
    revoked = TrustEntry(**base, not_before="2026-11-01T00:00:00Z", not_after="2026-10-01T00:00:00Z",
                         revoked_at="2026-10-01T00:00:00Z")
    assert revoked.status(NOW) == "revoked"
    assert TrustEntry(**base, not_after="2026-10-28T11:59:59Z").status(NOW) == "expired"
    assert TrustEntry(**base, not_after="2026-10-28T12:00:00Z").status(NOW) == "active"
    assert TrustEntry(**base, not_before="2026-10-28T12:00:01Z").status(NOW) == "not_yet_valid"
    assert TrustEntry(**base, not_before="2026-10-28T12:00:00Z").status(NOW) == "active"


def test_revoke_by_prefix(tmp_path):
    signer = make_signer("a")
    add_key(tmp_path, signer.pem, name="A", roles=["publisher"])
    revoked = revoke_key(tmp_path, signer.key_id[:12].upper(), "  key left the building  ", now=NOW)
    assert revoked.revoked_at == "2026-10-28T12:00:00.000Z" and revoked.revocation_reason == "key left the building"
    loaded = load_trust_store(tmp_path).get(signer.key_id)
    assert loaded is not None and loaded.status() == "revoked"
    with pytest.raises(Conflict):
        revoke_key(tmp_path, signer.key_id, "again")


@pytest.mark.parametrize("reason", ["", "   ", "x" * 501, "bad\x07reason"])
def test_revoke_needs_a_reason(tmp_path, reason):
    signer = make_signer("a")
    add_key(tmp_path, signer.pem, name="A", roles=["publisher"])
    with pytest.raises(ValidationFailed):
        revoke_key(tmp_path, signer.key_id, reason)


def test_find_rules():
    a = TrustEntry(key_id="ab12cd34" + "0" * 56, name="a", roles=("publisher",), public_key_pem="")
    b = TrustEntry(key_id="ab12cd34" + "1" * 56, name="b", roles=("publisher",), public_key_pem="")
    store = TrustStore(None, [a, b], [])
    assert store.find("ab12cd34" + "1" * 8) is b
    assert store.find(a.key_id) is a
    with pytest.raises(Conflict):
        store.find("ab12cd34")
    with pytest.raises(ValidationFailed):
        store.find("ab12cd3")
    with pytest.raises(NotFound):
        store.find("ffffffff")
    with pytest.raises(NotFound):
        store.find("f" * 64)


def test_key_id_that_does_not_match_its_pem_is_ignored_and_reported(tmp_path):
    signer, impostor = make_signer("real"), make_signer("impostor")
    # The file claims the real key's id but carries another key's PEM.
    write_entry(tmp_path, f"{signer.key_id}.json", entry_doc(impostor, key_id=signer.key_id))
    store = load_trust_store(tmp_path)
    assert store.entries == [] and store.get(signer.key_id) is None
    assert any("do not all agree" in p for p in store.problems)
    assert "do not all agree" in store.ignored[signer.key_id]


def test_file_name_that_does_not_match_the_key_is_ignored(tmp_path):
    signer, other = make_signer("a"), make_signer("b")
    write_entry(tmp_path, f"{other.key_id}.json", entry_doc(signer))
    store = load_trust_store(tmp_path)
    assert store.entries == [] and store.problems


@pytest.mark.parametrize("make_doc, expected", [
    (lambda s: "{not json", "not valid JSON"),
    (lambda s: json.dumps({**entry_doc(s), "extra": 1}), "unknown key"),
    (lambda s: json.dumps({k: v for k, v in entry_doc(s).items() if k != "roles"}), "missing roles"),
    (lambda s: json.dumps(entry_doc(s, roles=["root"])), "roles must be"),
    (lambda s: json.dumps(entry_doc(s, roles=[])), "roles must be"),
    (lambda s: json.dumps(entry_doc(s, not_after="tomorrow")), "not_after must be"),
    (lambda s: json.dumps(entry_doc(s, public_key_pem="nope")), "not an Ed25519 public key"),
    (lambda s: json.dumps(entry_doc(s, name="‮evil")), "name must be"),
    (lambda s: '{"key_id": 1, "key_id": 2}', "not valid JSON"),
    (lambda s: "[1]", "not a JSON object"),
])
def test_malformed_entries_are_ignored(tmp_path, make_doc, expected):
    signer = make_signer("a")
    write_entry(tmp_path, f"{signer.key_id}.json", make_doc(signer))
    store = load_trust_store(tmp_path)
    assert store.entries == []
    assert any(expected in p for p in store.problems), store.problems


def test_symlinked_entry_is_ignored(tmp_path):
    signer = make_signer("a")
    real = write_entry(tmp_path / "elsewhere", "entry.json", entry_doc(signer))
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / f"{signer.key_id}.json").symlink_to(real)
    store = load_trust_store(trust_dir)
    assert store.entries == [] and any("symbolic links" in p for p in store.problems)


def test_group_writable_entry_is_ignored(tmp_path):
    signer = make_signer("a")
    path = write_entry(tmp_path, f"{signer.key_id}.json", entry_doc(signer))
    path.chmod(0o664)
    store = load_trust_store(tmp_path)
    assert store.entries == [] and any("writable by group or others" in p for p in store.problems)


def test_world_writable_directory_trusts_nothing(tmp_path):
    trust_dir = tmp_path / "trust"
    add_key(trust_dir, make_signer("a").pem, name="A", roles=["publisher"])
    trust_dir.chmod(0o777)
    try:
        store = load_trust_store(trust_dir)
    finally:
        trust_dir.chmod(0o755)
    assert store.entries == [] and "no keys are trusted" in store.problems[0]


def test_missing_or_symlinked_directory(tmp_path):
    assert "does not exist" in load_trust_store(tmp_path / "nope").problems[0]
    real = tmp_path / "real"
    add_key(real, make_signer("a").pem, name="A", roles=["publisher"])
    link = tmp_path / "link"
    link.symlink_to(real)
    store = load_trust_store(link)
    assert store.entries == [] and "not a directory" in store.problems[0]


def test_other_files_are_reported_and_dotfiles_skipped(tmp_path):
    add_key(tmp_path, make_signer("a").pem, name="A", roles=["publisher"])
    (tmp_path / "README").write_text("hello")
    (tmp_path / ".abc.json.tmp").write_text("partial write")
    (tmp_path / "short.json").write_text("{}")
    store = load_trust_store(tmp_path)
    assert len(store.entries) == 1
    assert any("unexpected file \"README\"" in p for p in store.problems)
    assert any("short.json" in p and "file name" in p for p in store.problems)
    assert not any(".abc" in p for p in store.problems)


def test_hand_written_entry_with_validity_window(tmp_path):
    signer = make_signer("a")
    write_entry(tmp_path, f"{signer.key_id}.json",
                entry_doc(signer, roles=["publisher", "reviewer"], not_before="2026-01-01T00:00:00Z",
                          not_after="2026-06-01T00:00:00Z"))
    entry = load_trust_store(tmp_path).get(signer.key_id)
    assert entry is not None and entry.roles == ("publisher", "reviewer")
    assert entry.status(NOW) == "expired"
    assert entry.status(dt.datetime(2025, 12, 31, tzinfo=UTC)) == "not_yet_valid"
    assert entry.status(dt.datetime(2026, 3, 1, tzinfo=UTC)) == "active"


class _OwnedBy:
    """An os.stat_result with st_uid replaced."""

    def __init__(self, st, uid):
        self._st, self.st_uid = st, uid

    def __getattr__(self, name):
        return getattr(self._st, name)


def _fstat_owned_by(monkeypatch, uid, *, kind):
    real = os.fstat

    def fake(fd):
        st = real(fd)
        return _OwnedBy(st, uid) if kind(st.st_mode) else st

    monkeypatch.setattr(os, "fstat", fake)


OTHER_UID = 4242  # neither root nor the user running the tests


def test_entry_owned_by_another_user_is_ignored(tmp_path, monkeypatch):
    from helpers_bundle import make_workspace

    from ferry.bundle import verify_bundle

    if os.geteuid() == OTHER_UID:
        pytest.skip("tests run as the stand-in uid")
    ws = make_workspace(tmp_path)
    bundle = ws.pack().bundle_path
    with monkeypatch.context() as m:
        _fstat_owned_by(m, OTHER_UID, kind=stat.S_ISREG)
        store = load_trust_store(ws.trust_dir)
    assert store.entries == []
    why = store.ignored[ws.publisher.key_id]
    assert f"owned by uid {OTHER_UID}" in why and "chown" in why
    assert any(ws.publisher.key_id in p and "owned by uid" in p for p in store.problems)

    report = verify_bundle(bundle, ws.policy(), store)
    assert not report.accepted
    sig = {s["key_id"]: s for s in report.signatures}[ws.publisher.key_id]
    assert sig["status"] == "untrusted" and "owned by uid" in sig["detail"]


def test_directory_owned_by_another_user_trusts_nothing(tmp_path, monkeypatch):
    if os.geteuid() == OTHER_UID:
        pytest.skip("tests run as the stand-in uid")
    trust_dir = tmp_path / "trust"
    add_key(trust_dir, make_signer("a").pem, name="A", roles=["publisher"])
    with monkeypatch.context() as m:
        _fstat_owned_by(m, OTHER_UID, kind=stat.S_ISDIR)
        store = load_trust_store(trust_dir)
    assert store.entries == []
    assert len(store.problems) == 1 and f"owned by uid {OTHER_UID}" in store.problems[0]
    assert "no keys are trusted" in store.problems[0] and "chown" in store.problems[0]


def test_root_owned_entries_and_directory_are_trusted(tmp_path, monkeypatch):
    trust_dir = tmp_path / "trust"
    signer = make_signer("a")
    add_key(trust_dir, signer.pem, name="A", roles=["publisher"])
    with monkeypatch.context() as m:
        _fstat_owned_by(m, 0, kind=lambda mode: True)
        store = load_trust_store(trust_dir)
    assert store.problems == [] and [e.key_id for e in store.entries] == [signer.key_id]
