"""Tests for ferry.crypto: Ed25519 keys, key ids, signatures."""

from __future__ import annotations

import hashlib
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ferry import crypto
from ferry.errors import CryptoError


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_write_keypair_creates_private_0600_and_public_0644(tmp_path) -> None:
    priv, pub, kid = crypto.write_keypair(tmp_path, "site-publisher", None)
    assert priv.name == "site-publisher.key" and pub.name == "site-publisher.pub.pem"
    assert _mode(priv) == 0o600 and _mode(pub) == 0o644
    assert crypto.KEY_ID.fullmatch(kid)
    assert b"PRIVATE KEY" in priv.read_bytes() and b"ENCRYPTED" not in priv.read_bytes()
    assert crypto.key_id(crypto.load_public_key_file(pub)) == kid
    assert crypto.key_id(crypto.load_private_key_file(priv).public_key()) == kid


def test_write_keypair_refuses_to_overwrite(tmp_path) -> None:
    priv, _, _ = crypto.write_keypair(tmp_path, "k", None)
    before = priv.read_bytes()
    with pytest.raises(CryptoError, match="refusing to overwrite"):
        crypto.write_keypair(tmp_path, "k", None)
    assert priv.read_bytes() == before


@pytest.mark.parametrize("name", ["", "../escape", "a/b", ".hidden", "x" * 65, "sp ace"])
def test_write_keypair_rejects_bad_names(tmp_path, name: str) -> None:
    with pytest.raises(CryptoError):
        crypto.write_keypair(tmp_path, name, None)
    assert list(tmp_path.iterdir()) == []


def test_passphrase_round_trip_and_failures(tmp_path) -> None:
    priv, pub, kid = crypto.write_keypair(tmp_path, "reviewer", b"correct horse battery staple")
    assert b"ENCRYPTED PRIVATE KEY" in priv.read_bytes()
    key = crypto.load_private_key_file(priv, b"correct horse battery staple")
    assert crypto.key_id(key.public_key()) == kid
    with pytest.raises(CryptoError, match="wrong passphrase"):
        crypto.load_private_key_file(priv, b"wrong passphrase")
    with pytest.raises(CryptoError, match="passphrase is required"):
        crypto.load_private_key_file(priv)
    plain, _, _ = crypto.write_keypair(tmp_path, "plain", None)
    with pytest.raises(CryptoError):
        crypto.load_private_key_file(plain, b"unexpected passphrase")


def test_non_ed25519_keys_are_rejected() -> None:
    for private in (ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(public_exponent=65537, key_size=2048)):
        pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        with pytest.raises(CryptoError, match="not an Ed25519"):
            crypto.load_private_key_pem(pem)
        pub_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(CryptoError, match="not an Ed25519"):
            crypto.load_public_key_pem(pub_pem)


@pytest.mark.parametrize("data", [b"", b"garbage", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"])
def test_garbage_pem_is_rejected(data: bytes) -> None:
    with pytest.raises(CryptoError):
        crypto.load_public_key_pem(data)
    with pytest.raises(CryptoError):
        crypto.load_private_key_pem(data)


def test_missing_key_files_raise_crypto_error(tmp_path) -> None:
    with pytest.raises(CryptoError, match="cannot read"):
        crypto.load_private_key_file(tmp_path / "missing.key")
    with pytest.raises(CryptoError, match="cannot read"):
        crypto.load_public_key_file(tmp_path / "missing.pub.pem")


def test_key_id_is_sha256_of_raw_public_key_and_stable() -> None:
    key = crypto.generate_private_key()
    pub = key.public_key()
    raw = crypto.raw_public_bytes(pub)
    assert len(raw) == 32
    kid = crypto.key_id(pub)
    assert kid == hashlib.sha256(raw).hexdigest()
    reloaded = crypto.load_public_key_pem(crypto.public_key_to_pem(pub))
    assert crypto.key_id(reloaded) == kid
    assert crypto.key_id(crypto.load_private_key_pem(crypto.private_key_to_pem(key, None)).public_key()) == kid
    assert crypto.short_id(kid) == kid[:16]
    assert crypto.key_id(crypto.generate_private_key().public_key()) != kid


def test_sign_and_verify() -> None:
    key = crypto.generate_private_key()
    sig = crypto.sign(key, b"manifest bytes")
    assert len(sig) == crypto.SIGNATURE_BYTES
    assert crypto.verify(key.public_key(), sig, b"manifest bytes") is True
    assert crypto.verify(key.public_key(), sig, b"manifest bytes!") is False
    assert crypto.verify(crypto.generate_private_key().public_key(), sig, b"manifest bytes") is False
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    assert crypto.verify(key.public_key(), flipped, b"manifest bytes") is False


@pytest.mark.parametrize("signature", [b"", b"\x00" * 63, b"\x00" * 65, b"\x00" * 64, os.urandom(64), b"x" * 128])
def test_verify_returns_false_for_garbage_and_wrong_lengths(signature: bytes) -> None:
    key = crypto.generate_private_key()
    assert crypto.verify(key.public_key(), signature, b"data") is False


@pytest.mark.parametrize("signature, data", [(None, b"data"), ("x" * 64, b"data"), (12345, b"data"),
                                             (b"\x00" * 64, "text"), (b"\x00" * 64, None)])
def test_verify_never_raises_for_wrong_types(signature, data) -> None:
    key = crypto.generate_private_key()
    assert crypto.verify(key.public_key(), signature, data) is False


def test_verify_accepts_bytearray_and_memoryview() -> None:
    key = crypto.generate_private_key()
    sig = crypto.sign(key, b"payload")
    assert crypto.verify(key.public_key(), bytearray(sig), b"payload") is True
    assert crypto.verify(key.public_key(), memoryview(sig), bytearray(b"payload")) is True
