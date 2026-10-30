"""Serve an imported model with llama.cpp (`ferry runtime llamacpp`).

The command Ferry builds always serves the read-only store file of an imported
GGUF artifact, never a path the operator types, and always with:

- `--offline`: llama-server never reaches for the network (no `-hf` downloads);
- `--no-webui`: no second, unauthenticated web interface;
- `--host 127.0.0.1`: only this host can connect, so apps must go through the gateway;
- `--api-key-file <secrets/llamacpp-<model>.token>`: the backend's own bearer
  token (0600), which only the gateway holds, so even local users cannot call
  llama-server directly without reading that file.

`ensure_llamacpp_registration` creates what the gateway needs to route to that
server: the token file, a `llamacpp-<model>` backend on 127.0.0.1:<port> and a
route pinned to the artifact's digest with `require_verified`, so the gateway
only forwards requests once llama-server reports serving exactly that file. The
backend and route changes are audited by ferry.backends.
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import backends
from .bundle import store
from .config import Settings
from .errors import ConfigError, Conflict, NotFound, ValidationFailed
from .policy import MODEL_NAME
from .util import ensure_private_dir

DEFAULT_PORT = 8080
DEFAULT_BINARY = "llama-server"
MAX_CTX_SIZE = 1 << 24
_DIGEST = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")


@dataclass(frozen=True)
class ServedModel:
    model: str
    """The public model name: llama-server's --alias, the route's model and upstream model."""
    digest: str
    model_name: str | None
    """The model name declared in the bundle manifest."""
    store_path: Path


def backend_name(model: str) -> str:
    return f"llamacpp-{model}"


def token_path(settings: Settings, model: str) -> Path:
    return settings.secrets_dir / f"llamacpp-{model}.token"


def _check_port(port: object) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValidationFailed("port must be a whole number from 1 to 65535")
    return port


def _artifact(conn: sqlite3.Connection, digest: str) -> sqlite3.Row:
    row = conn.execute("SELECT digest, kind, format, model_name FROM artifacts WHERE digest = ?", (digest,)).fetchone()
    if row is None:
        raise NotFound(f"artifact sha256:{digest} has not been imported")
    return row


def resolve_model(settings: Settings, conn: sqlite3.Connection, model: str) -> ServedModel:
    """Find the imported GGUF artifact for `model`: a digest (64 hex, optionally
    'sha256:'), the public name of an existing pinned route, or the model name
    recorded at import (the newest import wins)."""
    if not isinstance(model, str) or not model.strip():
        raise ValidationFailed("give a model name or an artifact digest")
    text = model.strip()
    m = _DIGEST.fullmatch(text.lower())
    if m:
        row = _artifact(conn, m.group(1))
        public = row["model_name"]
        if not public or not MODEL_NAME.fullmatch(public):
            raise ValidationFailed(f"artifact sha256:{m.group(1)} has no usable model name; serve it by model name instead")
    else:
        if not MODEL_NAME.fullmatch(text):
            raise ValidationFailed("model must be 1-128 characters: letters, digits, '.', '_', ':' or '-'")
        public = text
        route = conn.execute("SELECT artifact_digest FROM routes WHERE model = ?", (text,)).fetchone()
        if route is not None:
            if not route["artifact_digest"]:
                raise ValidationFailed(f"the route for '{text}' is not pinned to an artifact; pin it first, or pass "
                                       "the artifact digest instead of the name")
            row = _artifact(conn, route["artifact_digest"])
        else:
            row = conn.execute("SELECT digest, kind, format, model_name FROM artifacts WHERE kind = 'model' AND"
                               " model_name = ? ORDER BY imported_at DESC, digest LIMIT 1", (text,)).fetchone()
            if row is None:
                raise NotFound(f"no imported model is named '{text}' (and no route has that name); "
                               "import its bundle first, or pass the artifact digest")
    if row["kind"] != "model":
        raise ValidationFailed(f"artifact sha256:{row['digest']} is a {row['kind']}, not a model")
    if row["format"] != "gguf":
        raise ValidationFailed(f"llama.cpp serves GGUF files; sha256:{row['digest']} is {row['format']}")
    path = store.path_for(settings, row["digest"])
    try:
        st = os.lstat(path)
    except OSError:
        raise NotFound(f"the store file for sha256:{row['digest']} is missing ({path}); run: ferry store verify") from None
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"the store entry {path} is not a regular file; run: ferry store verify")
    return ServedModel(model=public, digest=row["digest"], model_name=row["model_name"], store_path=path)


def llamacpp_command(settings: Settings, conn: sqlite3.Connection, model: str, port: int,
                     ctx_size: int | None = None, *, binary: str = DEFAULT_BINARY) -> list[str]:
    """The llama-server command line for an imported model (spec section 10). The token file must hold a
    usable token: llama-server treats an empty --api-key-file as "no API key", i.e. no authentication."""
    served = resolve_model(settings, conn, model)
    _check_port(port)
    key_file = token_path(settings, served.model)
    backends.read_token_file(key_file)
    command = [binary, "-m", str(served.store_path), "--alias", served.model, "--host", "127.0.0.1",
               "--port", str(port), "--api-key-file", str(key_file), "--offline", "--no-webui"]
    if ctx_size is not None:
        if isinstance(ctx_size, bool) or not isinstance(ctx_size, int) or not 1 <= ctx_size <= MAX_CTX_SIZE:
            raise ValidationFailed(f"ctx_size must be a whole number from 1 to {MAX_CTX_SIZE}")
        command += ["-c", str(ctx_size)]
    return command


def ensure_token_file(settings: Settings, model: str) -> tuple[Path, bool]:
    """The backend token file (0600 in a 0700 secrets directory), created with a
    random token if missing. Returns (path, created). An existing file must be a
    private regular file holding a usable token; it is never overwritten."""
    ensure_private_dir(settings.secrets_dir)
    path = token_path(settings, model)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISREG(st.st_mode):
            raise ConfigError(f"{path} exists but is not a regular file (symbolic links are refused)")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise ConfigError(f"{path} is accessible by group or other users; run: chmod 600 {path}")
        try:
            backends.read_token_file(path)
        except ConfigError as exc:
            # An empty key file would start llama-server without authentication.
            raise ConfigError(f"{exc.message}; remove it to have a new token created: rm {path}") from None
        return path, False
    token = (secrets.token_urlsafe(32) + "\n").encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, 0o600)
    written = False
    try:
        os.fchmod(fd, 0o600)
        if os.write(fd, token) != len(token):
            raise ConfigError(f"could not write the whole token to {path}")
        os.fsync(fd)
        written = True
    finally:
        os.close(fd)
        if not written:  # never leave an empty or partial key file behind
            try:
                os.unlink(path)
            except OSError:
                pass
    return path, True


def ensure_llamacpp_registration(settings: Settings, conn: sqlite3.Connection, model: str, port: int, *,
                                 actor_type: str = "cli", actor_id: str) -> dict[str, Any]:
    """Make sure the gateway can route `model` to llama-server on 127.0.0.1:<port>:
    token file, backend `llamacpp-<model>` and a pinned, require_verified route.
    Existing pieces are kept; the backend's URL and token file are corrected when
    they differ. Returns what exists now and what was created or changed."""
    served = resolve_model(settings, conn, model)
    url = f"http://127.0.0.1:{_check_port(port)}"
    token, token_created = ensure_token_file(settings, served.model)
    name = backend_name(served.model)
    created = {"token_file": token_created, "backend": False, "route": False}
    updated_backend = False
    warnings: list[str] = []
    existing = conn.execute("SELECT id, kind, base_url, auth_token_file FROM backends WHERE name = ?", (name,)).fetchone()
    if existing is None:
        backend = backends.create_backend(conn, settings, name=name, kind="llamacpp", base_url=url,
                                          auth_token_file=str(token), actor_type=actor_type, actor_id=actor_id)
        created["backend"] = True
    else:
        if existing["kind"] != "llamacpp":
            raise Conflict(f"a backend named '{name}' already exists with kind {existing['kind']}; rename or delete it")
        changes = {k: v for k, v in (("base_url", url), ("auth_token_file", str(token))) if existing[k] != v}
        if changes:
            backend = backends.update_backend(conn, settings, int(existing["id"]), changes,
                                              actor_type=actor_type, actor_id=actor_id)
            updated_backend = True
        else:
            backend = backends.get_backend(conn, int(existing["id"]))
    row = conn.execute("SELECT id FROM routes WHERE model = ?", (served.model,)).fetchone()
    if row is None:
        route = backends.create_route(conn, model=served.model, backend_id=int(backend["id"]), upstream_model=served.model,
                                      artifact_digest=served.digest, require_verified=True,
                                      actor_type=actor_type, actor_id=actor_id)
        created["route"] = True
    else:
        route = backends.get_route(conn, int(row["id"]))
        if route["artifact_digest"] != served.digest:
            warnings.append(f"the route for '{served.model}' is pinned to sha256:{route['artifact_digest']}, not to the "
                            f"served file sha256:{served.digest}; its provenance will show a mismatch")
        if route["backend_id"] != backend["id"]:
            warnings.append(f"the route for '{served.model}' uses backend '{route['backend_name']}', not '{name}'")
        if not route["require_verified"]:
            warnings.append(f"the route for '{served.model}' does not require verified provenance")
    return {"model": served.model, "digest": served.digest, "store_path": str(served.store_path),
            "token_file": str(token), "backend": backend, "route": route, "created": created,
            "updated": {"backend": updated_backend}, "warnings": warnings}
