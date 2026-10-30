"""Admin API for the web console (spec section 9): JSON under /api.

Conventions: session cookie authentication (ferry.gateway.security), roles
checked on the server for every endpoint, errors as
`{"error": {"code", "message", "details"?}}`, lists as `{"items": [...]}`,
`Cache-Control: no-store` on every response (added by the security headers
middleware). Every state change goes through a ferry.* domain function that
writes its own audit event in the same transaction, or appends one here
(audit.verify, audit.export); bundle verify and import run as background jobs
whose outcome the importer records.

What the API deliberately cannot do: create console users, change the trust
store, or change ferry.toml (import policy, egress rules). Those are host-only
and live in the CLI.

Request bodies are parsed here, not by pydantic models, so that unknown fields
are rejected and validation errors never echo submitted values (a password
must not come back in an error message).
"""

from __future__ import annotations

import datetime as _dt
import json
import math
import os
import platform
import re
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Annotated, Any, Iterator

from fastapi import APIRouter, Depends, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import Response, StreamingResponse

from .. import __version__, audit, auth, backends, doctor, evidence, policy
from ..bundle import store
from ..config import Settings
from ..errors import NotFound, ValidationFailed
from ..formats import strict_json_loads
from ..trust import load_trust_store
from ..util import parse_rfc3339, rfc3339, utc_now
from .jobs import JobRegistry
from .limits import request_id_for
from .security import (ApiError, SessionUser, admin_only, admin_or_auditor, any_role, clear_session_cookie,
                       client_ip, cookie_secure, current_user, is_loopback_host, set_session_cookie)
from .state import GatewayState

router = APIRouter(prefix="/api")

CHAT_ACTION = "gateway.chat.completions"
TRAFFIC_OUTCOMES = ("success", "denied", "error", "unavailable", "rejected", "unauthenticated")
ENVIRONMENTS = ("test", "pilot", "production")
INBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
MAX_INBOX_ITEMS = 1000
MAX_DIR_ENTRIES = 10_000
JOB_ID = re.compile(r"^[0-9a-f]{32}$")
BUNDLE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_QUERY_CHARS = 512
MAX_ATTENTION = 50
KEY_EXPIRY_WARNING = _dt.timedelta(days=7)
# Numeric path ids (row ids, audit seq, policy version) are SQLite INTEGERs, signed
# 64-bit. A value outside that range names nothing and cannot even be bound
# (sqlite3 raises OverflowError, a 500), so it is refused as invalid input (422),
# like a non-numeric id.
RowId = Annotated[int, PathParam(ge=-(2**63), le=2**63 - 1)]


@dataclass
class AdminContext:
    """Per-process admin state, at `app.state.ferry_admin`."""

    jobs: JobRegistry
    throttle: auth.LoginThrottle


# --- plumbing ---------------------------------------------------------------------


def _state(request: Request) -> GatewayState:
    state = getattr(request.app.state, "ferry", None)
    if not isinstance(state, GatewayState):
        raise RuntimeError("app.state.ferry must be a GatewayState (see ferry.gateway.app.create_app)")
    return state


def _admin(request: Request) -> AdminContext:
    ctx = getattr(request.app.state, "ferry_admin", None)
    if not isinstance(ctx, AdminContext):
        raise RuntimeError("app.state.ferry_admin must be an AdminContext (see ferry.gateway.app.create_app)")
    return ctx


@contextmanager
def _db(request: Request) -> Iterator[sqlite3.Connection]:
    with _state(request).db.session() as conn:
        yield conn


def _rid(request: Request) -> str:
    return request_id_for(request.scope)


async def json_body(request: Request) -> dict[str, Any]:
    """Dependency: the request body as a JSON object ({} when empty), or 422.
    Duplicate keys and NaN/Infinity are refused: a policy document must mean one
    thing to the validator, the reviewer and the stored copy alike."""
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        data = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ApiError(422, "invalid_json", "The request body must be a JSON object (UTF-8, no duplicate keys).") from None
    if not isinstance(data, dict):
        raise ApiError(422, "invalid_json", "The request body must be a JSON object.")
    return data


def _fields(body: dict[str, Any], *, required: tuple[str, ...] = (), optional: tuple[str, ...] = ()) -> dict[str, Any]:
    allowed = set(required) | set(optional)
    unknown = sorted(str(k)[:64] for k in body if k not in allowed)
    if unknown:
        raise ApiError(422, "validation_failed", f"unknown field(s): {', '.join(unknown[:20])}",
                       details={"fields": unknown[:20]})
    missing = [k for k in required if k not in body]
    if missing:
        raise ApiError(422, "validation_failed", f"missing field(s): {', '.join(missing)}", details={"fields": missing})
    return body


def _json(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


# --- auth -------------------------------------------------------------------------


def _throttled(wait: int) -> ApiError:
    return ApiError(429, "too_many_attempts", f"Too many failed sign-in attempts. Try again in {wait} seconds.",
                    details={"retry_after_s": wait}, headers={"Retry-After": str(wait)}, extra={"retry_after_s": wait})


def _login(state: GatewayState, throttle: auth.LoginThrottle, username: str, password: str, ip: str | None,
           rid: str) -> tuple[str, dict[str, Any]]:
    with state.db.session() as conn:
        wait = throttle.retry_after(username, ip)
        if wait is not None:
            auth.record_login_failure(conn, username, "throttled", client_ip=ip, correlation_id=rid, throttled=True)
            raise _throttled(wait)
        result = auth.authenticate_admin(conn, username, password)
        if not result.ok or result.user is None:
            throttle.record_failure(username, ip)
            auth.record_login_failure(conn, username, result.reason or "failure", client_ip=ip, correlation_id=rid)
            raise ApiError(401, "invalid_credentials", "Wrong username or password.")
        throttle.record_success(username, ip)
        try:
            return auth.create_session(conn, int(result.user["id"]), state.settings, client_ip=ip, correlation_id=rid)
        except NotFound:  # disabled between the password check and the session
            raise ApiError(401, "invalid_credentials", "Wrong username or password.") from None


@router.post("/auth/login")
def login(request: Request, body: dict[str, Any] = Depends(json_body)) -> Response:
    data = _fields(body, required=("username", "password"))
    username, password = data["username"], data["password"]
    if not isinstance(username, str) or not isinstance(password, str):
        raise ApiError(422, "validation_failed", "username and password must be strings")
    state = _state(request)
    token, session = _login(state, _admin(request).throttle, username, password, client_ip(request), _rid(request))
    response = Response(json.dumps({"user": {"username": session["username"], "role": session["role"]}}),
                        media_type="application/json")
    set_session_cookie(response, token, secure=cookie_secure(state.settings, request.scope))
    return response


@router.post("/auth/logout", status_code=204)
def logout(request: Request, user: SessionUser = Depends(current_user)) -> Response:
    state = _state(request)
    with state.db.session() as conn:
        auth.delete_session(conn, user.token, client_ip=client_ip(request), correlation_id=_rid(request))
    response = Response(status_code=204)
    clear_session_cookie(response, secure=cookie_secure(state.settings, request.scope))
    return response


@router.get("/auth/me")
def me(user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    return {"user": {"username": user.username, "role": user.role}, "session": {"expires_at": user.expires_at}}


# --- inbox ------------------------------------------------------------------------


def valid_inbox_name(name: object) -> bool:
    """A plain entry name: no separators, no '..', not hidden, nothing exotic."""
    return isinstance(name, str) and bool(INBOX_NAME.fullmatch(name)) and ".." not in name


def _inbox_root(settings: Settings) -> Path | None:
    try:
        root = settings.inbox_dir.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return root if root.is_dir() else None


def _resolve_entry(root: Path, name: str) -> tuple[Path, os.stat_result]:
    """The path to verify for inbox entry `name`, and its lstat. A symbolic link
    is allowed only when it resolves to a file or directory inside the inbox; the
    resolved path is returned, so the verifier never follows a link itself."""
    candidate = root / name
    try:
        st = os.lstat(candidate)
    except FileNotFoundError:
        raise ApiError(404, "not_found", f"'{name}' is not in the inbox") from None
    except OSError as exc:
        raise ApiError(422, "unreadable", f"'{name}' cannot be read: {exc.strerror}") from None
    path = candidate
    if stat.S_ISLNK(st.st_mode):
        try:
            target = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            raise ApiError(422, "broken_symlink", f"'{name}' is a symbolic link whose target does not exist") from None
        if root not in target.parents:
            raise ApiError(422, "symlink_outside_inbox", f"'{name}' is a symbolic link to a location outside the inbox; "
                                                         "only files inside the inbox can be verified or imported")
        st = os.lstat(target)
        path = target
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise ApiError(422, "not_a_bundle", f"'{name}' is neither a regular file nor a directory")
    return path, st


def resolve_inbox_entry(settings: Settings, name: object) -> tuple[Path, str]:
    """(path, "tar"|"dir") for a name the console sent, or ApiError (422/404)."""
    if not valid_inbox_name(name):
        raise ApiError(422, "invalid_name", "name must be the plain name of a file or directory in the inbox: letters, "
                                            "digits, '.', '_', '+' or '-', not starting with '.', without '/', '\\' or '..'")
    assert isinstance(name, str)
    root = _inbox_root(settings)
    if root is None:
        raise ApiError(404, "inbox_missing", f"the inbox directory {settings.inbox_dir} does not exist")
    path, st = _resolve_entry(root, name)
    return path, "dir" if stat.S_ISDIR(st.st_mode) else "tar"


def _dir_size(path: Path) -> int | None:
    """Total size of regular files below `path` (symlinks not followed), or None for huge trees."""
    total, seen, stack = 0, 0, [path]
    while stack:
        try:
            entries = list(os.scandir(stack.pop()))
        except OSError:
            return None
        for entry in entries:
            seen += 1
            if seen > MAX_DIR_ENTRIES:
                return None
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def list_inbox(settings: Settings, conn: sqlite3.Connection) -> dict[str, Any]:
    """Bundle candidates in the inbox: `*.tar` files and directories with acceptable names."""
    out: dict[str, Any] = {"inbox_dir": str(settings.inbox_dir), "items": []}
    root = _inbox_root(settings)
    if root is None:
        out["problem"] = "the inbox directory does not exist"
        return out
    latest = {r["source_name"]: r for r in conn.execute(
        "SELECT v.source_name, v.verdict, v.mode, v.created_at, v.bundle_id FROM verifications v JOIN"
        " (SELECT source_name, MAX(id) AS id FROM verifications GROUP BY source_name) m ON m.id = v.id")}
    imported = {r["source_name"]: r["at"] for r in conn.execute(
        "SELECT source_name, MAX(created_at) AS at FROM verifications WHERE mode = 'import' AND verdict = 'accepted'"
        " GROUP BY source_name")}
    try:
        names = sorted(entry.name for entry in os.scandir(root))
    except OSError as exc:
        out["problem"] = f"the inbox cannot be listed: {exc.strerror}"
        return out
    for name in names:
        if len(out["items"]) >= MAX_INBOX_ITEMS:
            out["truncated"] = True
            break
        if not valid_inbox_name(name):
            continue
        try:
            path, st = _resolve_entry(root, name)
        except (ApiError, OSError):
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        if not is_dir and not name.endswith(".tar"):
            continue  # sidecars (.sha256, .review.md) and other files are not bundles
        modified = rfc3339(_dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.timezone.utc))
        source = path.name  # the name the importer records
        last = latest.get(source)
        done = imported.get(source)
        out["items"].append({
            "name": name,
            "type": "dir" if is_dir else "tar",
            "size": _dir_size(path) if is_dir else st.st_size,
            "modified_at": modified,
            "last_verification": None if last is None else {
                "verdict": last["verdict"], "mode": last["mode"], "created_at": last["created_at"],
                "bundle_id": last["bundle_id"]},
            "imported": bool(done and done >= modified),
        })
    return out


@router.get("/inbox")
def get_inbox(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return list_inbox(_state(request).settings, conn)


def _submit(request: Request, user: SessionUser, body: dict[str, Any], kind: str) -> dict[str, Any]:
    data = _fields(body, required=("name",))
    path, _ = resolve_inbox_entry(_state(request).settings, data["name"])
    job = _admin(request).jobs.submit(kind, data["name"], path, actor_type="admin", actor_id=user.username)
    return {"job_id": job.job_id, "state": job.state}


@router.post("/inbox/verify", status_code=202)
def inbox_verify(request: Request, user: SessionUser = Depends(admin_only),
                 body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    return _submit(request, user, body, "verify")


@router.post("/inbox/import", status_code=202)
def inbox_import(request: Request, user: SessionUser = Depends(admin_only),
                 body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    return _submit(request, user, body, "import")


@router.get("/jobs/{job_id}")
def get_job(request: Request, job_id: str, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    job = _admin(request).jobs.get(job_id) if JOB_ID.fullmatch(job_id) else None
    if job is None:
        raise ApiError(404, "not_found", "No such job. Job status is kept in memory and is lost when the server "
                                         "restarts; the verification history keeps every outcome.")
    return job


# --- verifications and bundles ---------------------------------------------------------


_VERIFICATION_COLUMNS = "id, source_name, bundle_id, bundle_name, bundle_version, verdict, mode, created_at, actor"


def _verification_items(conn: sqlite3.Connection, where: str, params: tuple[Any, ...],
                        limit: int) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            f"SELECT {_VERIFICATION_COLUMNS}, json_array_length(report, '$.errors') AS error_count,"
            f" json_array_length(report, '$.warnings') AS warning_count FROM verifications{where}"
            " ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
        items = [dict(r) for r in rows]
    except sqlite3.OperationalError:  # SQLite built without JSON functions
        items = []
        for r in conn.execute(f"SELECT {_VERIFICATION_COLUMNS}, report FROM verifications{where} ORDER BY id DESC"
                              " LIMIT ?", (*params, limit)):
            report = _json(r["report"], {})
            item = {k: r[k] for k in r.keys() if k != "report"}
            item["error_count"] = len(report.get("errors") or []) if isinstance(report, dict) else 0
            item["warning_count"] = len(report.get("warnings") or []) if isinstance(report, dict) else 0
            items.append(item)
    for item in items:
        item["error_count"] = int(item.get("error_count") or 0)
        item["warning_count"] = int(item.get("warning_count") or 0)
    return items


@router.get("/verifications")
def list_verifications(request: Request, limit: int = Query(50, ge=1, le=500),
                       user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return {"items": _verification_items(conn, "", (), limit)}


@router.get("/verifications/{verification_id}")
def get_verification(request: Request, verification_id: RowId, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        items = _verification_items(conn, " WHERE id = ?", (verification_id,), 1)
        if not items:
            raise ApiError(404, "not_found", f"verification {verification_id} does not exist")
        row = conn.execute("SELECT report FROM verifications WHERE id = ?", (verification_id,)).fetchone()
    return {**items[0], "report": _json(row["report"], None)}


def _bundle_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {"bundle_id": row["bundle_id"], "name": row["name"], "version": row["version"],
            "imported_at": row["imported_at"], "imported_by": row["imported_by"], "source_name": row["source_name"],
            "signers": _json(row["signers"], []), "artifact_count": int(row["artifact_count"]),
            "total_bytes": int(row["total_bytes"])}


_BUNDLE_SELECT = (
    "SELECT b.bundle_id, b.name, b.version, b.imported_at, b.imported_by, b.source_name, b.signers,"
    " COUNT(ba.digest) AS artifact_count, COALESCE(SUM(a.size), 0) AS total_bytes FROM bundles b"
    " LEFT JOIN bundle_artifacts ba ON ba.bundle_id = b.bundle_id LEFT JOIN artifacts a ON a.digest = ba.digest"
)


@router.get("/bundles")
def list_bundles(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        rows = conn.execute(_BUNDLE_SELECT + " GROUP BY b.bundle_id ORDER BY b.imported_at DESC, b.bundle_id").fetchall()
    return {"items": [_bundle_summary(r) for r in rows]}


@router.get("/bundles/{bundle_id}")
def get_bundle(request: Request, bundle_id: str, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    wanted = bundle_id.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", wanted):
        wanted = "sha256:" + wanted
    if not BUNDLE_ID.fullmatch(wanted):
        raise ApiError(404, "not_found", "bundle ids look like sha256:<64 hex>")
    with _db(request) as conn:
        row = conn.execute(_BUNDLE_SELECT + " WHERE b.bundle_id = ? GROUP BY b.bundle_id", (wanted,)).fetchone()
        if row is None:
            raise ApiError(404, "not_found", f"bundle {wanted} has not been imported")
        full = conn.execute("SELECT manifest, report FROM bundles WHERE bundle_id = ?", (wanted,)).fetchone()
        artifacts = conn.execute(
            "SELECT ba.path, ba.digest, a.size, a.kind, a.format, a.model_name, a.metadata FROM bundle_artifacts ba"
            " JOIN artifacts a ON a.digest = ba.digest WHERE ba.bundle_id = ? ORDER BY ba.path", (wanted,)).fetchall()
        verifications = [r["id"] for r in conn.execute(
            "SELECT id FROM verifications WHERE bundle_id = ? ORDER BY id DESC LIMIT 50", (wanted,))]
    items = []
    for a in artifacts:
        meta = _json(a["metadata"], {})
        model = meta.get("model") if isinstance(meta, dict) and isinstance(meta.get("model"), dict) else {}
        items.append({"path": a["path"], "digest": a["digest"], "size": a["size"], "kind": a["kind"],
                      "format": a["format"], "model_name": a["model_name"], "license": model.get("license"),
                      "metadata": meta})
    return {**_bundle_summary(row), "manifest": _json(full["manifest"], None), "report": _json(full["report"], None),
            "artifacts": items, "verification_ids": verifications}


@router.get("/trust")
def get_trust(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    settings = _state(request).settings
    trust = load_trust_store(settings.trust_dir)
    now = utc_now()
    keep = ("key_id", "name", "roles", "not_before", "not_after", "revoked_at", "revocation_reason", "status",
            "added_at", "comment")
    return {"trust_dir": str(settings.trust_dir), "required_roles": list(settings.imports.required_roles),
            "distinct_signers": settings.imports.distinct_signers,
            "items": [{k: v for k, v in e.to_dict(now).items() if k in keep} for e in trust.entries],
            "problems": list(trust.problems)}


@router.get("/models")
def list_models(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    settings = _state(request).settings
    with _db(request) as conn:
        routed: dict[str, list[str]] = {}
        for r in conn.execute("SELECT model, artifact_digest FROM routes WHERE artifact_digest IS NOT NULL ORDER BY model"):
            routed.setdefault(r["artifact_digest"], []).append(r["model"])
        rows = conn.execute(
            "SELECT a.digest, a.model_name, a.size, a.format, a.metadata, a.first_bundle_id, a.imported_at,"
            " b.name AS bundle_name, b.version AS bundle_version FROM artifacts a"
            " LEFT JOIN bundles b ON b.bundle_id = a.first_bundle_id WHERE a.kind = 'model'"
            " ORDER BY a.model_name, a.imported_at").fetchall()
    items = []
    for r in rows:
        meta = _json(r["metadata"], {})
        model = meta.get("model") if isinstance(meta, dict) and isinstance(meta.get("model"), dict) else {}
        items.append({"digest": r["digest"], "model_name": r["model_name"], "size": r["size"], "format": r["format"],
                      "metadata": meta, "license": model.get("license"), "first_bundle_id": r["first_bundle_id"],
                      "bundle_name": r["bundle_name"], "bundle_version": r["bundle_version"],
                      "imported_at": r["imported_at"], "routes": routed.get(r["digest"], []),
                      "in_store": store.path_for(settings, r["digest"]).is_file()})
    return {"items": items}


# --- backends and routes ------------------------------------------------------------------

_BACKEND_REQUIRED = ("name", "kind", "base_url")
_BACKEND_OPTIONAL = ("auth_token_file", "timeout_s", "max_concurrency")
_BACKEND_PATCH = ("name", "kind", "base_url", "auth_token_file", "timeout_s", "max_concurrency", "enabled")
_ROUTE_OPTIONAL = ("upstream_model", "artifact_digest", "require_verified")
_ROUTE_PATCH = ("model", "backend_id", "upstream_model", "artifact_digest", "require_verified", "enabled")


@router.get("/backends")
def list_backends(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return {"items": backends.list_backends(conn)}


@router.post("/backends", status_code=201)
def create_backend(request: Request, user: SessionUser = Depends(admin_only),
                   body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=_BACKEND_REQUIRED, optional=_BACKEND_OPTIONAL)
    with _db(request) as conn:
        return backends.create_backend(
            conn, _state(request).settings, name=data["name"], kind=data["kind"], base_url=data["base_url"],
            auth_token_file=data.get("auth_token_file"), timeout_s=data.get("timeout_s"),
            max_concurrency=data.get("max_concurrency"), actor_type="admin", actor_id=user.username)


@router.patch("/backends/{backend_id}")
def update_backend(request: Request, backend_id: RowId, user: SessionUser = Depends(admin_only),
                   body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, optional=_BACKEND_PATCH)
    with _db(request) as conn:
        return backends.update_backend(conn, _state(request).settings, backend_id, data,
                                       actor_type="admin", actor_id=user.username)


@router.delete("/backends/{backend_id}", status_code=204)
def delete_backend(request: Request, backend_id: RowId, user: SessionUser = Depends(admin_only)) -> Response:
    with _db(request) as conn:
        backends.delete_backend(conn, backend_id, actor_type="admin", actor_id=user.username)
    return Response(status_code=204)


@router.post("/backends/{backend_id}/check")
async def check_backend(request: Request, backend_id: RowId, user: SessionUser = Depends(admin_only)) -> dict[str, Any]:
    status = await backends.refresh_backend(_state(request), backend_id, actor_type="admin", actor_id=user.username)
    return {"status": status, "checked_at": status["checked_at"]}


@router.get("/routes")
def list_routes(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return {"items": backends.list_routes(conn)}


@router.post("/routes", status_code=201)
def create_route(request: Request, user: SessionUser = Depends(admin_only),
                 body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=("model", "backend_id"), optional=_ROUTE_OPTIONAL)
    require_verified = data.get("require_verified", True)
    with _db(request) as conn:
        return backends.create_route(conn, model=data["model"], backend_id=data["backend_id"],
                                     upstream_model=data.get("upstream_model"),
                                     artifact_digest=data.get("artifact_digest"),
                                     require_verified=require_verified, actor_type="admin", actor_id=user.username)


@router.patch("/routes/{route_id}")
def update_route(request: Request, route_id: RowId, user: SessionUser = Depends(admin_only),
                 body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, optional=_ROUTE_PATCH)
    with _db(request) as conn:
        return backends.update_route(conn, route_id, data, actor_type="admin", actor_id=user.username)


@router.delete("/routes/{route_id}", status_code=204)
def delete_route(request: Request, route_id: RowId, user: SessionUser = Depends(admin_only)) -> Response:
    with _db(request) as conn:
        backends.delete_route(conn, route_id, actor_type="admin", actor_id=user.username)
    return Response(status_code=204)


# --- apps and keys ----------------------------------------------------------------------------


@router.get("/apps")
def list_applications(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return {"items": auth.list_principals(conn)}


@router.post("/apps", status_code=201)
def create_application(request: Request, user: SessionUser = Depends(admin_only),
               body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=("name", "environment"), optional=("description",))
    description = data.get("description")
    with _db(request) as conn:
        return auth.create_principal(conn, data["name"], environment=data["environment"],
                                     description="" if description is None else description,
                                     actor_type="admin", actor_id=user.username)


@router.patch("/apps/{app_id}")
def update_application(request: Request, app_id: RowId, user: SessionUser = Depends(admin_only),
               body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, optional=("disabled", "description", "environment"))
    with _db(request) as conn:
        return auth.update_principal(conn, app_id, disabled=data.get("disabled"), description=data.get("description"),
                                     environment=data.get("environment"), actor_type="admin", actor_id=user.username)


@router.post("/apps/{app_id}/keys", status_code=201)
def issue_key(request: Request, app_id: RowId, user: SessionUser = Depends(admin_only),
              body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, optional=("expires_in_days",))
    with _db(request) as conn:
        issued = auth.issue_api_key(conn, app_id, expires_in_days=data.get("expires_in_days"),
                                    actor_type="admin", actor_id=user.username)
    # The only response that ever carries the secret; it is not stored anywhere.
    return {"key_id": issued["key_id"], "api_key": issued["api_key"], "expires_at": issued["expires_at"],
            "created_at": issued["created_at"], "app": issued["app"]}


@router.post("/keys/{key_id}/revoke")
def revoke_key(request: Request, key_id: str, user: SessionUser = Depends(admin_only),
               body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    _fields(body)
    with _db(request) as conn:
        return auth.revoke_api_key(conn, key_id, actor_type="admin", actor_id=user.username)


# --- policy -------------------------------------------------------------------------------------


def _known_names(conn: sqlite3.Connection) -> tuple[list[str], list[str]]:
    return ([r["name"] for r in conn.execute("SELECT name FROM principals")],
            [r["model"] for r in conn.execute("SELECT model FROM routes")])


@router.get("/policy")
def get_policy(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return {"active": policy.get_active_policy(conn), "history": policy.policy_history(conn)}


@router.post("/policy/validate")
def validate_policy(request: Request, user: SessionUser = Depends(admin_or_auditor),
                    body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=("document",))
    with _db(request) as conn:
        apps, models = _known_names(conn)
    return policy.validate_policy(data["document"], apps, models)


@router.post("/policy/activate", status_code=201)
def activate_policy(request: Request, user: SessionUser = Depends(admin_only),
                    body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=("document",), optional=("comment",))
    comment = data.get("comment")
    try:
        with _db(request) as conn:
            return policy.activate_policy(conn, data["document"], actor_type="admin", actor_id=user.username,
                                          comment="" if comment is None else comment)
    except ValidationFailed as exc:
        validation = exc.details.get("validation")
        if validation is None:
            raise
        raise ApiError(422, "validation_failed", exc.message, details={"validation": validation},
                       extra={"validation": validation}) from None


@router.post("/policy/explain")
def explain_policy(request: Request, user: SessionUser = Depends(admin_or_auditor),
                   body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    data = _fields(body, required=("app", "model"), optional=("action",))
    action = data.get("action")
    with _db(request) as conn:
        return policy.explain(conn, app=data["app"], model=data["model"],
                              action="chat.completions" if action is None else action)


@router.get("/policy/{version}")
def get_policy_version(request: Request, version: RowId, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return policy.get_policy_version(conn, version)


# --- audit --------------------------------------------------------------------------------------


def _str_param(request: Request, name: str) -> str | None:
    value = request.query_params.get(name)
    if value is None or not value.strip():
        return None
    if len(value) > MAX_QUERY_CHARS:
        raise ApiError(422, "validation_failed", f"'{name}' is longer than {MAX_QUERY_CHARS} characters")
    return value.strip()


def _int_param(request: Request, name: str, default: int | None, lo: int, hi: int) -> int | None:
    value = _str_param(request, name)
    if value is None:
        return default
    if not re.fullmatch(r"[0-9]{1,19}", value) or not lo <= int(value) <= hi:
        raise ApiError(422, "validation_failed", f"'{name}' must be a whole number from {lo} to {hi}")
    return int(value)


def _time_param(request: Request, name: str) -> str | None:
    value = _str_param(request, name)
    if value is None:
        return None
    try:
        return rfc3339(parse_rfc3339(value))
    except (ValueError, IndexError):
        raise ApiError(422, "validation_failed", f"'{name}' must be an RFC 3339 timestamp with a time zone, "
                                                 "e.g. 2026-10-28T00:00:00Z") from None


@router.get("/audit")
def query_audit(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    limit = _int_param(request, "limit", 100, 1, 500) or 100
    before = _int_param(request, "before_seq", None, 1, 2**63 - 1)
    filters = {k: _str_param(request, k) for k in ("action", "outcome", "actor_id", "actor_type", "resource",
                                                    "correlation_id", "q")}
    since, until = _time_param(request, "since"), _time_param(request, "until")
    fetch = limit + 1 if limit < 500 else limit
    with _db(request) as conn:
        events = audit.query_events(conn, **filters, since=since, until=until, before_seq=before, limit=fetch)
    more = len(events) > limit or (fetch == limit and len(events) == limit)
    events = events[:limit]
    return {"items": events, "next_before_seq": events[-1]["seq"] if more and events else None}


@router.get("/audit/facets")
def audit_facets(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return audit.facets(conn)


class _AsciiSink:
    """Text writer that encodes into a binary spool (audit.export_jsonl writes str)."""

    def __init__(self, fh: IO[bytes]) -> None:
        self.fh = fh

    def write(self, text: str) -> int:
        self.fh.write(text.encode("ascii"))
        return len(text)


@router.get("/audit/export")
def export_audit(request: Request, user: SessionUser = Depends(any_role)) -> Response:
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
    try:
        with _db(request) as conn:
            count = audit.export_jsonl(conn, _AsciiSink(spool))  # type: ignore[arg-type]
            head = audit.head(conn)
            audit.append_event(conn, actor_type="admin", actor_id=user.username, action="audit.export",
                               resource="audit", outcome="success", correlation_id=_rid(request),
                               details={"events": count, "head_seq": head["seq"], "head_hash": head["hash"],
                                        "via": "api"})
        spool.seek(0)
    except BaseException:
        spool.close()
        raise

    def chunks() -> Iterator[bytes]:
        try:
            while data := spool.read(64 * 1024):
                yield data
        finally:
            spool.close()

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(chunks(), media_type="application/x-ndjson",
                             headers={"Content-Disposition": f'attachment; filename="ferry-audit-{stamp}.ndjson"'})


@router.post("/audit/verify")
def verify_audit(request: Request, user: SessionUser = Depends(admin_or_auditor),
                 body: dict[str, Any] = Depends(json_body)) -> dict[str, Any]:
    _fields(body)
    with _db(request) as conn:
        result = audit.verify_chain(conn)
        audit.append_event(conn, actor_type="admin", actor_id=user.username, action="audit.verify", resource="audit",
                           outcome="success" if result["ok"] else "failure", correlation_id=_rid(request),
                           details={**{k: result[k] for k in ("ok", "events_checked", "head_seq", "head_hash",
                                                              "first_bad_seq", "problem")}, "via": "api"})
    return result


@router.get("/audit/{seq}")
def audit_event(request: Request, seq: RowId, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        event = audit.get_event(conn, seq)
    if event is None:
        raise ApiError(404, "not_found", f"audit event {seq} does not exist")
    return event


# --- evidence and system -------------------------------------------------------------------------


@router.get("/evidence")
def get_evidence(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return evidence.build_evidence(_state(request).settings, conn)


@router.get("/evidence.md")
def get_evidence_markdown(request: Request, user: SessionUser = Depends(any_role)) -> Response:
    with _db(request) as conn:
        report = evidence.build_evidence(_state(request).settings, conn)
    stamp = report["generated_at"][:10]
    return Response(evidence.render_markdown(report).encode("utf-8"), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="ferry-evidence-{stamp}.md"'})


@router.get("/system")
def get_system(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    state = _state(request)
    with _db(request) as conn:
        inventory = doctor.network_inventory(state.settings, conn)
    return {"version": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "started_at": state.started_at, "config": state.settings.public_dict(), "network_inventory": inventory,
            "dependencies": doctor.dependencies()}


# --- overview ------------------------------------------------------------------------------------


def _percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile of sorted `values`."""
    if not values:
        return None
    return values[max(1, math.ceil(fraction * len(values))) - 1]


def traffic_summary(conn: sqlite3.Connection, since: str) -> tuple[dict[str, Any], dict[str, int]]:
    """Counts by outcome, latency percentiles of successful requests, and counts by
    app environment, all from gateway.chat.completions audit events since `since`."""
    traffic: dict[str, Any] = {"total": 0, **{o: 0 for o in TRAFFIC_OUTCOMES}}
    for row in conn.execute("SELECT outcome, COUNT(*) AS n FROM audit_events WHERE action = ? AND ts >= ?"
                            " GROUP BY outcome", (CHAT_ACTION, since)):
        traffic["total"] += int(row["n"])
        if row["outcome"] in traffic:
            traffic[row["outcome"]] += int(row["n"])
    by_env = {e: 0 for e in ENVIRONMENTS}
    latencies: list[float] = []
    try:
        for row in conn.execute("SELECT json_extract(details, '$.environment') AS env, COUNT(*) AS n FROM audit_events"
                                " WHERE action = ? AND ts >= ? GROUP BY env", (CHAT_ACTION, since)):
            if row["env"] in by_env:
                by_env[row["env"]] += int(row["n"])
        for row in conn.execute("SELECT json_extract(details, '$.latency_ms') AS ms FROM audit_events"
                                " WHERE action = ? AND ts >= ? AND outcome = 'success'", (CHAT_ACTION, since)):
            if isinstance(row["ms"], (int, float)) and not isinstance(row["ms"], bool):
                latencies.append(row["ms"])
    except sqlite3.OperationalError:  # SQLite built without JSON functions
        by_env = {e: 0 for e in ENVIRONMENTS}
        latencies = []
        for row in conn.execute("SELECT outcome, details FROM audit_events WHERE action = ? AND ts >= ?",
                                (CHAT_ACTION, since)):
            details = _json(row["details"], {})
            if not isinstance(details, dict):
                continue
            if details.get("environment") in by_env:
                by_env[details["environment"]] += 1
            ms = details.get("latency_ms")
            if row["outcome"] == "success" and isinstance(ms, (int, float)) and not isinstance(ms, bool):
                latencies.append(ms)
    latencies.sort()
    traffic["p50_ms"] = _percentile(latencies, 0.50)
    traffic["p95_ms"] = _percentile(latencies, 0.95)
    return traffic, by_env


def _key_counts(conn: sqlite3.Connection, now: _dt.datetime) -> tuple[int, int]:
    """(usable keys, usable keys expiring within KEY_EXPIRY_WARNING)."""
    usable = expiring = 0
    for row in conn.execute("SELECT k.expires_at FROM api_keys k JOIN principals p ON p.id = k.principal_id"
                            " WHERE k.revoked_at IS NULL AND p.disabled = 0"):
        if row["expires_at"] is None:
            usable += 1
            continue
        try:
            expires = parse_rfc3339(row["expires_at"])
        except ValueError:
            continue
        if expires > now:
            usable += 1
            if expires - now <= KEY_EXPIRY_WARNING:
                expiring += 1
    return usable, expiring


def _last_verify(conn: sqlite3.Connection) -> dict[str, Any] | None:
    events = audit.query_events(conn, action="audit.verify", limit=1)
    if not events:
        return None
    details = events[0]["details"]
    return {"ok": bool(details.get("ok")), "verified_at": events[0]["ts"], "problem": details.get("problem")}


def build_overview(state: GatewayState, conn: sqlite3.Connection) -> dict[str, Any]:
    """GET /api/overview: real counts only, from database rows and audit events."""
    settings = state.settings
    now = utc_now()
    active = policy.get_active_policy(conn)
    policy_info = None
    if active is not None:
        rules = active["document"].get("rules") if isinstance(active["document"], dict) else None
        policy_info = {"version": active["version"], "sha256": active["sha256"],
                       "activated_at": active["activated_at"], "rule_count": len(rules) if isinstance(rules, list) else 0}
    backend_rows = backends.list_backends(conn)
    route_rows = backends.list_routes(conn)
    trust = load_trust_store(settings.trust_dir)
    active_trust = [e for e in trust.entries if e.status(now) == "active"]
    usable_keys, expiring_keys = _key_counts(conn, now)

    def count(sql: str) -> int:
        return int(conn.execute(sql).fetchone()[0])

    counts = {
        "apps": count("SELECT COUNT(*) FROM principals"),
        "active_keys": usable_keys,
        "backends": len(backend_rows),
        "routes": len(route_rows),
        "bundles": count("SELECT COUNT(*) FROM bundles"),
        "model_artifacts": count("SELECT COUNT(*) FROM artifacts WHERE kind = 'model'"),
        "trusted_keys": len(active_trust),
    }
    since = rfc3339(now - _dt.timedelta(hours=24))
    traffic, by_env = traffic_summary(conn, since)
    inbox = list_inbox(settings, conn)
    pending = sum(1 for item in inbox["items"] if not item["imported"])
    head = audit.head(conn)
    last_verify = _last_verify(conn)
    rejected_24h = int(conn.execute("SELECT COUNT(*) FROM verifications WHERE verdict = 'rejected' AND created_at >= ?",
                                    (since,)).fetchone()[0])
    attention = _attention(settings, policy_info, backend_rows, route_rows, trust, active_trust, last_verify,
                           pending, rejected_24h, expiring_keys)
    return {
        "version": __version__,
        "started_at": state.started_at,
        "policy": policy_info,
        "counts": counts,
        "backends": [{"id": b["id"], "name": b["name"], "kind": b["kind"], "enabled": b["enabled"],
                      "state": (b["last_status"] or {}).get("state") if isinstance(b["last_status"], dict) else None,
                      "checked_at": b["last_checked_at"]} for b in backend_rows],
        "routes": [{"model": r["model"], "backend": r["backend_name"], "provenance": r["provenance"]["state"],
                    "available": r["available"], "reason": r["reason"] or None} for r in route_rows],
        "traffic_24h": traffic,
        "traffic_by_environment_24h": by_env,
        "inbox_pending": pending,
        "audit": {"head_seq": head["seq"], "head_hash": head["hash"], "last_verify": last_verify},
        "attention": attention,
    }


def _attention(settings: Settings, policy_info: dict[str, Any] | None, backend_rows: list[dict[str, Any]],
               route_rows: list[dict[str, Any]], trust: Any, active_trust: list[Any],
               last_verify: dict[str, Any] | None, pending: int, rejected_24h: int,
               expiring_keys: int) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    def add(severity: str, message: str, href: str | None) -> None:
        if len(items) < MAX_ATTENTION:
            items.append({"severity": severity, "message": message, "href": href})

    if last_verify is not None and not last_verify["ok"]:
        add("error", f"The audit chain failed verification: {last_verify['problem']}", "#/audit")
    if policy_info is None:
        add("warning", "No access policy is active, so every gateway request is denied.", "#/access?tab=policy")
    for b in backend_rows:
        status = b["last_status"] if isinstance(b["last_status"], dict) else None
        if not b["enabled"]:
            continue
        if status is None:
            add("info", f"Backend {b['name']} has not been health-checked yet.", "#/models")
        elif status.get("state") == "down":
            add("error", f"Backend {b['name']} is down: {status.get('error') or 'no answer'}", "#/models")
        elif status.get("state") == "loading":
            add("warning", f"Backend {b['name']} is still loading its model.", "#/models")
    for r in route_rows:
        if r["provenance"]["state"] == "mismatch":
            add("error", f"Route {r['model']}: {r['provenance']['detail']}", "#/models")
        elif r["enabled"] and not r["available"]:
            add("warning", f"Route {r['model']} is unavailable: {r['reason']}", "#/models")
    for problem in trust.problems[:5]:
        add("warning", f"Trust store: {problem}", "#/bundles")
    if not active_trust:
        add("warning", "No trusted signing keys: every bundle import is rejected. Add keys on the host with "
                       "ferry trust add.", "#/bundles")
    if rejected_24h:
        add("warning", f"{rejected_24h} bundle verification(s) were rejected in the last 24 hours.", "#/bundles")
    if pending:
        add("info", f"{pending} item(s) in the inbox have not been imported.", "#/bundles")
    if expiring_keys:
        add("info", f"{expiring_keys} API key(s) expire within 7 days.", "#/access")
    if last_verify is None:
        add("info", "The audit chain has not been verified yet.", "#/audit")
    server = settings.server
    if not (server.tls_cert_file and server.tls_key_file) and not is_loopback_host(server.host):
        add("warning", f"The gateway is configured to listen on {server.host} without TLS; keys, sessions and "
                       "prompts would cross the network unencrypted.", "#/evidence")
    if settings.imports.allow_pickle or settings.imports.allow_executables:
        add("warning", "The import policy in ferry.toml allows pickle or executable content.", "#/evidence")
    if settings.gateway.allow_public_backends:
        add("warning", "gateway.allow_public_backends is on: backends may be on public addresses.", "#/evidence")
    return items


@router.get("/overview")
def overview(request: Request, user: SessionUser = Depends(any_role)) -> dict[str, Any]:
    with _db(request) as conn:
        return build_overview(_state(request), conn)


# Registered last: anything else under /api is a JSON 404, never the console page.
@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
def unknown_endpoint(path: str) -> None:
    raise ApiError(404, "not_found", "Unknown API endpoint.")
