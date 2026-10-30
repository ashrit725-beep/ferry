"""Ed25519 signing keys for bundles and audit checkpoints.

Signatures are raw 64-byte Ed25519 signatures over exact bytes, so anyone can
check a bundle with stock OpenSSL (`openssl pkeyutl -verify -rawin`) without
trusting Ferry's own code. A key's id is the hex SHA-256 of its 32 raw public
key bytes.
"""

from __future__ import annotations

import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import CryptoError
from .util import atomic_write, sha256_hex

SIGNATURE_BYTES = 64
KEY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
KEY_ID = re.compile(r"^[0-9a-f]{64}$")


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(key: Ed25519PrivateKey, passphrase: bytes | None) -> bytes:
    encryption: serialization.KeySerializationEncryption
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption)


def public_key_to_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key_pem(data: bytes, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(data, password=passphrase or None)
    except TypeError:
        raise CryptoError("private key is encrypted; a passphrase is required") from None
    except ValueError:
        raise CryptoError("could not load private key: wrong passphrase or not a PEM private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise CryptoError("private key is not an Ed25519 key")
    return key


def load_public_key_pem(data: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        raise CryptoError("not a PEM public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise CryptoError("public key is not an Ed25519 key")
    return key


def raw_public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(key: Ed25519PublicKey) -> str:
    return sha256_hex(raw_public_bytes(key))


def short_id(kid: str) -> str:
    return kid[:16]


def sign(key: Ed25519PrivateKey, data: bytes) -> bytes:
    return key.sign(data)


def verify(key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """True only for a valid signature. Never raises for bad input."""
    buffers = (bytes, bytearray, memoryview)
    if not isinstance(signature, buffers) or not isinstance(data, buffers):
        return False
    signature = bytes(signature)
    if len(signature) != SIGNATURE_BYTES:
        return False
    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


def load_private_key_file(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise CryptoError(f"cannot read private key {path}: {exc.strerror}") from None
    return load_private_key_pem(data, passphrase)


def load_public_key_file(path: Path) -> Ed25519PublicKey:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise CryptoError(f"cannot read public key {path}: {exc.strerror}") from None
    return load_public_key_pem(data)


def write_keypair(out_dir: Path, name: str, passphrase: bytes | None) -> tuple[Path, Path, str]:
    """Create <name>.key (0600) and <name>.pub.pem (0644). Refuses to overwrite."""
    if not KEY_NAME.fullmatch(name):
        raise CryptoError("key name must be 1-64 characters: letters, digits, '.', '_' or '-'")
    out_dir = Path(out_dir)
    priv_path = out_dir / f"{name}.key"
    pub_path = out_dir / f"{name}.pub.pem"
    for p in (priv_path, pub_path):
        if p.exists():
            raise CryptoError(f"{p} already exists; refusing to overwrite a key")
    key = generate_private_key()
    atomic_write(priv_path, private_key_to_pem(key, passphrase), mode=0o600)
    atomic_write(pub_path, public_key_to_pem(key.public_key()), mode=0o644)
    return priv_path, pub_path, key_id(key.public_key())
