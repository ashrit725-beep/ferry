"""The `ferry` command line (spec section 10).

Connected side: keygen, pack, sign, inspect, verify, preflight, rehearse.
Disconnected side (host only): init, verify, import, trust, admin, app,
backend, route, policy, runtime, audit, store, evidence, doctor, serve.

Exit codes: 0 success or accepted, 1 rejected or failed (a bundle, a check, a
policy decision), 2 usage, I/O or configuration error.

Global options: `--config FILE` and `--data-dir DIR` (also accepted after the
command name; FERRY_CONFIG and FERRY_DATA_DIR work too). Passphrases for
private keys come only from `--passphrase-file` or FERRY_KEY_PASSPHRASE, never
from a command-line argument, which other users can read in the process list.
Console passwords come from standard input (`--password-stdin`) or a terminal
prompt for the same reason.

Commands that change state record exactly one audit event as the CLI actor
(the local OS user). Heavy modules are imported only by the commands that use
them, so the CLI starts quickly.
"""

from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import os
import platform
import shlex
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Sequence

from . import __version__
from .errors import ConfigError, CryptoError, FerryError, ValidationFailed

if TYPE_CHECKING:
    from .config import Settings
    from .db import Database

EXIT_OK, EXIT_REJECTED, EXIT_ERROR = 0, 1, 2
PASSPHRASE_ENV = "FERRY_KEY_PASSPHRASE"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_KEY_FILE_BYTES = 64 * 1024


class UsageError(FerryError):
    code = "usage_error"


# --- shared helpers -------------------------------------------------------------


def _err(text: str) -> None:
    print(text, file=sys.stderr)


def _actor() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no user database entry, e.g. in a minimal container
        return "unknown"


def _safe(value: object, limit: int = 256) -> str:
    from .formats import clean_text

    return clean_text(str(value), limit)


def _env_configured() -> bool:
    return bool(os.environ.get("FERRY_CONFIG") or os.environ.get("FERRY_DATA_DIR"))


def _settings(args: argparse.Namespace, *, required: bool = True) -> Settings | None:
    """Settings from --config / --data-dir / the environment. With required=False,
    None when nothing points at an installation (standalone commands)."""
    from .config import load_settings

    config, data_dir = getattr(args, "config", None), getattr(args, "data_dir", None)
    if not required and not (config or data_dir or _env_configured()):
        return None
    return load_settings(config, data_dir)


def _require_settings(args: argparse.Namespace) -> Settings:
    settings = _settings(args)
    assert settings is not None
    return settings


def _database(settings: Settings) -> Database:
    """The installation's database (migrated to the current schema). It must exist:
    a mistyped --data-dir must not quietly start a new, empty installation."""
    from .db import Database

    if not settings.db_path.is_file():
        raise ConfigError(f"no Ferry database at {settings.db_path}; run: ferry init --data-dir {settings.data_dir}")
    database = Database(settings.db_path)
    database.init()
    return database


def _require_exists(path: Path) -> None:
    if not os.path.lexists(path):
        raise UsageError(f"{path} does not exist")


def _read_small(path: str | Path, limit: int) -> bytes:
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        raise UsageError(f"cannot read {p}: {exc.strerror}") from None
    if len(data) > limit:
        raise UsageError(f"{p} is larger than {limit:,} bytes")
    return data


def _read_json_file(path: str | Path) -> Any:
    from .formats import strict_json_loads

    try:
        return strict_json_loads(_read_small(path, MAX_INPUT_BYTES).decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise UsageError(f"{path} is not valid JSON: {exc}") from None


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=False))


def _secret_from_file(path: str) -> bytes:
    data = _read_small(path, 4096)
    first = data.split(b"\n", 1)[0].rstrip(b"\r")
    if not first:
        raise UsageError(f"the passphrase file {path} is empty")
    try:
        mode = os.stat(path).st_mode
    except OSError:
        mode = 0
    if mode & 0o077:
        _err(f"warning: {path} is readable by other users; run: chmod 600 {path}")
    return first


def _passphrase(args: argparse.Namespace) -> bytes | None:
    path = getattr(args, "passphrase_file", None)
    if path:
        return _secret_from_file(path)
    env = os.environ.get(PASSPHRASE_ENV)
    return env.encode("utf-8") if env else None


def _load_key(path: str, args: argparse.Namespace) -> Any:
    """A private signing key, decrypted with the passphrase from --passphrase-file or the environment."""
    from .crypto import load_private_key_file

    passphrase = _passphrase(args)
    try:
        return load_private_key_file(Path(path), passphrase)
    except CryptoError as exc:
        if passphrase is None and "passphrase is required" in exc.message:
            raise CryptoError(f"{path} is encrypted: give --passphrase-file F or set {PASSPHRASE_ENV}") from None
        raise


def _record(settings: Settings | None, *, action: str, resource: str, outcome: str = "success",
            details: dict[str, Any] | None = None) -> bool:
    """Append one CLI audit event when an installation is configured."""
    if settings is None:
        return False
    from . import audit

    database = _database(settings)
    with database.session() as conn:
        audit.append_event(conn, actor_type="cli", actor_id=_actor(), action=action, resource=resource,
                           outcome=outcome, details=details or {})
    return True


def _table(rows: list[list[str]], header: list[str]) -> None:
    widths = [max(len(str(c)) for c in col) for col in zip(header, *rows)] if rows else [len(h) for h in header]
    for row in [header, *rows]:
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip())


# --- connected side: keys, pack, sign, inspect, verify ------------------------------------


def cmd_version(args: argparse.Namespace) -> int:
    if args.json:
        _print_json({"ferry": __version__, "python": platform.python_version()})
    else:
        print(f"ferry {__version__}")
    return EXIT_OK


def cmd_keygen(args: argparse.Namespace) -> int:
    from .crypto import short_id, write_keypair

    if args.no_passphrase and args.passphrase_file:
        raise UsageError("give --passphrase-file or --no-passphrase, not both")
    passphrase: bytes | None = None
    if not args.no_passphrase:
        passphrase = _passphrase(args)
        if passphrase is None:
            raise UsageError("the private key needs a passphrase: give --passphrase-file F, set "
                             f"{PASSPHRASE_ENV}, or pass --no-passphrase")
    out = Path(args.out_dir or ".")
    out.mkdir(parents=True, exist_ok=True)
    private, public, key_id = write_keypair(out, args.name, passphrase)
    print(f"Private key  {private}  (mode 0600{', encrypted' if passphrase else ', NOT encrypted'})")
    print(f"Public key   {public}")
    print(f"Key id       {key_id}")
    print(f"Fingerprint  {short_id(key_id)}")
    print("Give the public key to the receiving site through a separate channel and have them read the key id "
          "back to you before they trust it (ferry trust add --expect-fingerprint).")
    return EXIT_OK


def cmd_pack(args: argparse.Namespace) -> int:
    from .bundle.pack import pack_bundle

    key = _load_key(args.key, args)
    result = pack_bundle(args.spec, key, Path(args.out or "."), created_at=args.created_at,
                         allow_unsafe=args.allow_unsafe)
    for warning in result.warnings:
        _err(f"warning: {warning}")
    if any(w.startswith("UNSAFE") or "UNSAFE:" in w for w in result.warnings):
        _err("WARNING: this bundle contains content the default import policy rejects (--allow-unsafe was given).")
    _record(_settings(args, required=False), action="bundle.pack", resource=f"bundle:{result.bundle_id}",
            details={"bundle_id": result.bundle_id, "bundle_path": str(result.bundle_path), "key_id": result.key_id,
                     "tar_sha256": result.tar_sha256, "allow_unsafe": args.allow_unsafe})
    if args.json:
        _print_json(result.to_dict())
        return EXIT_OK
    print(f"Packed       {result.bundle_path}  ({result.tar_size:,} bytes)")
    print(f"Bundle id    {result.bundle_id}")
    print(f"File SHA-256 {result.tar_sha256}")
    print(f"Signed by    {result.key_id}")
    print(f"Sidecars     {result.sha256_path.name}, {result.review_path.name}")
    return EXIT_OK


def cmd_sign(args: argparse.Namespace) -> int:
    from .bundle.pack import sign_bundle

    _require_exists(Path(args.bundle))
    key = _load_key(args.key, args)
    try:
        result = sign_bundle(args.bundle, key)
    except ValidationFailed as exc:
        if "report" not in exc.details:
            raise
        _err(f"ferry: {exc.message}")
        return EXIT_REJECTED
    _record(_settings(args, required=False), action="bundle.sign", resource=f"bundle:{result.bundle_id}",
            details={"bundle_id": result.bundle_id, "bundle_path": str(result.bundle_path), "key_id": result.key_id,
                     "tar_sha256": result.tar_sha256})
    if args.json:
        _print_json(result.to_dict())
        return EXIT_OK
    print(f"Countersigned {result.bundle_path}")
    print(f"Bundle id     {result.bundle_id}  (unchanged)")
    print(f"Signature     {result.signature_member}")
    if result.tar_sha256:
        print(f"File SHA-256  {result.tar_sha256}" + ("  (.sha256 sidecar updated)" if result.sidecar_updated else ""))
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace) -> int:
    from .bundle.reader import open_bundle
    from .bundle.verify import EXTRA_MEMBERS, SIGNATURE_MEMBER
    from .config import ImportSettings
    from .manifest import ManifestError, bundle_id_for, parse_manifest

    path = Path(args.bundle)
    _require_exists(path)
    limits = ImportSettings()
    with open_bundle(path, max_members=limits.max_artifacts + EXTRA_MEMBERS) as reader:
        members = list(reader.members)
        signatures = sorted(m.group(1) for member in members if member.is_file
                            and (m := SIGNATURE_MEMBER.fullmatch(member.name)))
        manifest_member = next((m for m in members if m.name == "manifest.json" and m.is_file), None)
        raw = None
        if manifest_member is not None and manifest_member.size <= limits.max_manifest_bytes:
            with reader.open(manifest_member) as fh:
                raw = fh.read(limits.max_manifest_bytes + 1)
        info: dict[str, Any] = {"bundle": str(path), "type": reader.source_type, "size": reader.size,
                                "members": len(members), "signatures": signatures, "verified": False}
    if raw is None:
        info["problem"] = "no readable manifest.json (or it is larger than the limit)"
        if args.json:
            _print_json(info)
        else:
            _err(f"ferry: {path}: {info['problem']}")
        return EXIT_REJECTED
    info["bundle_id"] = bundle_id_for(raw)
    try:
        manifest = parse_manifest(raw)
    except ManifestError as exc:
        info["manifest_errors"] = exc.errors
        if args.json:
            _print_json(info)
        else:
            _err(f"ferry: {path}: manifest.json is not a valid v1 manifest:")
            for problem in exc.errors:
                _err(f"  - {_safe(problem)}")
        return EXIT_REJECTED
    info["manifest"] = manifest.to_dict()
    if args.json:
        _print_json(info)
        return EXIT_OK
    print(f"Bundle      {manifest.name} {manifest.version}  (created {manifest.created_at})")
    print(f"Bundle id   {info['bundle_id']}")
    print(f"File        {path}  ({reader.source_type}, {info['size']:,} bytes, {len(members)} members)")
    print(f"Signatures  {len(signatures)}: " + (", ".join(k[:16] + "..." for k in signatures) or "none"))
    requires = [f"Ferry >= {manifest.ferry_min_version}"]
    if manifest.runtime:
        requires.append(f"runtime {manifest.runtime}")
    if manifest.min_memory_bytes is not None:
        requires.append(f"memory >= {manifest.min_memory_bytes:,} bytes")
    print(f"Requires    {', '.join(_safe(r) for r in requires)}")
    if manifest.description:
        print(f"Description {_safe(manifest.description, 300)}")
    print("Artifacts:")
    for a in manifest.artifacts:
        extra = f"  licence {a.model.license}" if a.model else ""
        print(f"  {a.path}  {a.kind}  {a.format}  {a.size:,} bytes  sha256 {a.sha256}{_safe(extra)}")
    print("Nothing was verified. Run `ferry verify` to check the signatures against a trust store, every digest, "
          "the file formats and the import policy.")
    return EXIT_OK


def _print_report(report: Any, *, recorded: bool | None = None) -> None:
    bundle = report.bundle or {}
    title = f"{bundle.get('name')} {bundle.get('version')}" if bundle else _safe(report.source.get("name") or "")
    print(f"{report.verdict.upper()}  {title}  {report.bundle_id or '(no bundle id)'}")
    for s in report.signatures:
        detail = f": {s['detail']}" if s.get("detail") else ""
        print(f"  signature {s['key_id'][:16]}...  {s.get('name') or '(not in the trust store)'}  "
              f"{','.join(s.get('roles') or []) or '-'}  {s['status']}{detail}")
    failed = [c for c in report.checks if c["status"] == "fail"]
    if failed:
        print("Failed checks:")
        for c in failed:
            print(f"  {c['id']}: {c['message']}")
    if report.errors:
        print("Reasons:")
        for e in report.errors:
            print(f"  - {e}")
    if report.warnings:
        print("Warnings:")
        for w in report.warnings:
            print(f"  - {w}")
    if report.accepted:
        passed = sum(1 for c in report.checks if c["status"] == "pass")
        print(f"  {len(report.artifacts)} artifact(s) verified, {passed} checks passed")
    if recorded is not None:
        print("Recorded in the verification history and the audit log." if recorded
              else "Not recorded (no data directory given).")


def cmd_verify(args: argparse.Namespace) -> int:
    from .bundle.importer import verify_only
    from .bundle.verify import verify_bundle
    from .config import SIGNER_ROLES, ImportSettings
    from .trust import load_trust_store

    path = Path(args.bundle)
    _require_exists(path)
    settings = _settings(args, required=False)
    imports = settings.imports if settings is not None else ImportSettings()
    if args.require_role:
        bad = [r for r in args.require_role if r not in SIGNER_ROLES]
        if bad:
            raise UsageError(f"unknown role(s) {', '.join(bad)}; roles are: {', '.join(SIGNER_ROLES)}")
        imports = dataclasses.replace(imports, required_roles=tuple(dict.fromkeys(args.require_role)))
    if args.trust_dir:
        imports = dataclasses.replace(imports, trust_dir=str(Path(args.trust_dir).resolve()))
    if settings is not None:
        settings = dataclasses.replace(settings, imports=imports)
        result = verify_only(settings, _database(settings), path, actor_type="cli", actor_id=_actor(), full=args.full)
        report, recorded = result.report, True
    else:
        if not args.trust_dir:
            _err("warning: no trust store given (--trust-dir): no signature can be trusted, so the bundle will be "
                 "rejected")
        trust = load_trust_store(Path(args.trust_dir)) if args.trust_dir else None
        report, recorded = verify_bundle(path, imports, trust, full=args.full), False
    if args.json:
        _print_json(report.to_dict())
    else:
        _print_report(report, recorded=recorded)
    return EXIT_OK if report.accepted else EXIT_REJECTED


# --- disconnected side: installation, import, trust ------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    from .bundle.store import ensure_store
    from .config import CONFIG_FILENAME, default_config_toml, load_settings
    from .db import Database
    from .util import atomic_write, ensure_private_dir

    if getattr(args, "config", None):
        raise UsageError("ferry init writes <data dir>/ferry.toml; pass --data-dir DIR only")
    target = getattr(args, "data_dir", None) or os.environ.get("FERRY_DATA_DIR")
    if not target:
        raise UsageError("ferry init needs --data-dir DIR")
    data = Path(target).expanduser().resolve()
    ensure_private_dir(data)
    config = data / CONFIG_FILENAME
    created = not config.exists()
    if created:
        atomic_write(config, default_config_toml(data).encode("utf-8"), mode=0o600)
    settings = load_settings(config_path=config)
    version = Database(settings.db_path).init()
    ensure_store(settings)
    ensure_private_dir(settings.secrets_dir)
    if not settings.inbox_dir.exists():
        ensure_private_dir(settings.inbox_dir)
    if not settings.trust_dir.exists():
        settings.trust_dir.mkdir(parents=True)
        os.chmod(settings.trust_dir, 0o755)
    print(f"Data directory  {data}")
    print(f"Configuration   {config}" + ("  (created)" if created else "  (kept)"))
    print(f"Database        {settings.db_path}  (schema v{version})")
    print(f"Inbox           {settings.inbox_dir}")
    print(f"Trust store     {settings.trust_dir}")
    print("Next: ferry trust add PUB.pem --name NAME --role publisher; "
          "ferry admin create-user NAME --role admin --password-stdin; ferry serve")
    return EXIT_OK


def cmd_import(args: argparse.Namespace) -> int:
    from .bundle.importer import import_bundle

    settings = _require_settings(args)
    database = _database(settings)
    path = Path(args.bundle)
    _require_exists(path)
    result = import_bundle(settings, database, path, actor_type="cli", actor_id=_actor(),
                           allow_downgrade=args.allow_downgrade)
    if args.json:
        _print_json(result.to_dict())
    else:
        _print_report(result.report)
        if result.accepted:
            if result.already_imported:
                print("Already imported: nothing new was stored (the attempt is recorded).")
            else:
                print(f"Imported into {settings.store_dir}: {len(result.stored)} new file(s) stored.")
        else:
            print("Nothing was imported.")
    return EXIT_OK if result.accepted else EXIT_REJECTED


def _trust_target(args: argparse.Namespace) -> tuple[Path, Settings | None]:
    settings = _settings(args, required=False)
    if getattr(args, "trust_dir", None):
        return Path(args.trust_dir).resolve(), settings
    if settings is None:
        raise UsageError("give --data-dir (or --config) for the host's trust store, or --trust-dir DIR")
    return settings.trust_dir, settings


def cmd_trust_add(args: argparse.Namespace) -> int:
    from .crypto import short_id
    from .trust import add_key

    trust_dir, settings = _trust_target(args)
    if settings is not None:
        _database(settings)  # fail before changing anything if the change could not be recorded
    pem = _read_small(args.pem, MAX_KEY_FILE_BYTES)
    entry = add_key(trust_dir, pem, name=args.name, roles=args.role, not_before=args.not_before,
                    not_after=args.expires, comment=args.comment or "", expect_fingerprint=args.expect_fingerprint)
    _record(settings, action="trust.add", resource=f"key:{entry.key_id}",
            details={"key_id": entry.key_id, "name": entry.name, "roles": list(entry.roles),
                     "not_before": entry.not_before, "not_after": entry.not_after, "trust_dir": str(trust_dir),
                     "fingerprint_checked": bool(args.expect_fingerprint)})
    print(f"Trusted key {entry.key_id}")
    print(f"  name {entry.name}; roles {', '.join(entry.roles)}; valid "
          f"{entry.not_before or 'now'} to {entry.not_after or 'no expiry'}")
    if not args.expect_fingerprint:
        _err(f"note: confirm the fingerprint {short_id(entry.key_id)} with the key's owner through a separate channel "
             "(or pass --expect-fingerprint next time)")
    return EXIT_OK


def cmd_trust_list(args: argparse.Namespace) -> int:
    from .trust import load_trust_store

    trust_dir, _ = _trust_target(args)
    store = load_trust_store(trust_dir)
    if args.json:
        _print_json(store.to_dict())
        return EXIT_OK
    print(f"Trust store {trust_dir}")
    rows = [[e.key_id[:16], e.name, ",".join(e.roles), e.status(), e.not_after or "-",
             e.revoked_at or "-"] for e in store.entries]
    if rows:
        _table(rows, ["KEY ID", "NAME", "ROLES", "STATUS", "NOT AFTER", "REVOKED"])
    else:
        print("  no trusted keys")
    for problem in store.problems:
        print(f"problem: {problem}")
    return EXIT_OK


def cmd_trust_revoke(args: argparse.Namespace) -> int:
    from .trust import revoke_key

    trust_dir, settings = _trust_target(args)
    if settings is not None:
        _database(settings)
    entry = revoke_key(trust_dir, args.key_id, args.reason)
    _record(settings, action="trust.revoke", resource=f"key:{entry.key_id}",
            details={"key_id": entry.key_id, "name": entry.name, "reason": entry.revocation_reason,
                     "revoked_at": entry.revoked_at, "trust_dir": str(trust_dir)})
    print(f"Revoked key {entry.key_id} ({entry.name}) at {entry.revoked_at}; its signatures no longer count.")
    return EXIT_OK


# --- accounts ----------------------------------------------------------------------------------


def cmd_admin_create_user(args: argparse.Namespace) -> int:
    from . import auth

    settings = _require_settings(args)
    database = _database(settings)
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    elif sys.stdin.isatty():
        password = getpass.getpass(f"Password for {args.username}: ")
        if password != getpass.getpass("Repeat the password: "):
            raise UsageError("the passwords do not match")
    else:
        raise UsageError("give the password on standard input with --password-stdin")
    with database.session() as conn:
        user = auth.create_admin_user(conn, args.username, password, args.role, actor_type="cli", actor_id=_actor())
    print(f"Created console user {user['username']} with role {user['role']}.")
    return EXIT_OK


def cmd_app_create(args: argparse.Namespace) -> int:
    from . import auth

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        app = auth.create_principal(conn, args.name, environment=args.environment, description=args.description or "",
                                    actor_type="cli", actor_id=_actor())
    if args.json:
        _print_json(app)
    else:
        print(f"Created app {app['name']} (id {app['id']}, environment {app['environment']}). "
              f"Issue a key with: ferry app key {app['name']}")
    return EXIT_OK


def cmd_app_list(args: argparse.Namespace) -> int:
    from . import auth

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        apps = auth.list_principals(conn)
    if args.json:
        _print_json({"items": apps})
        return EXIT_OK
    rows = [[str(a["id"]), a["name"], a["environment"], "disabled" if a["disabled"] else "enabled",
             f"{sum(1 for k in a['keys'] if k['status'] == 'active')}/{len(a['keys'])}"] for a in apps]
    _table(rows, ["ID", "NAME", "ENVIRONMENT", "STATE", "ACTIVE KEYS"])
    return EXIT_OK


def cmd_app_key(args: argparse.Namespace) -> int:
    from . import auth

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        app = auth.get_principal_by_name(conn, args.name)
        issued = auth.issue_api_key(conn, app["id"], expires_in_days=args.expires_in_days, actor_type="cli",
                                    actor_id=_actor())
    if args.json:
        _print_json({"key_id": issued["key_id"], "api_key": issued["api_key"], "expires_at": issued["expires_at"],
                     "app": issued["app"]})
    else:
        print(issued["api_key"])
        _err(f"API key {issued['key_id']} for app {issued['app']}"
             + (f", expires {issued['expires_at']}" if issued["expires_at"] else ", no expiry")
             + ". This is the only time the key is shown; Ferry keeps only its hash.")
    return EXIT_OK


def cmd_app_revoke_key(args: argparse.Namespace) -> int:
    from . import auth

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        key = auth.revoke_api_key(conn, args.key_id, actor_type="cli", actor_id=_actor())
    print(f"Revoked API key {key['key_id']} of app {key['app']} at {key['revoked_at']}.")
    return EXIT_OK


# --- backends, routes, policy ----------------------------------------------------------------------


def _print_status(name: str, status: dict[str, Any]) -> None:
    print(f"Backend {name}: {status['state']}  ({status.get('latency_ms')} ms"
          + (f", HTTP {status['http_status']}" if status.get("http_status") else "") + ")")
    if status.get("version"):
        print(f"  version  {status['version']}")
    if status.get("models"):
        print(f"  models   {', '.join(status['models'])}")
    for served in status.get("served") or []:
        digest = served.get("digest")
        print(f"  serves   {served.get('path')}  " + (f"(store file sha256:{digest})" if digest
                                                       else "(not a file in the Ferry store)"))
    if status.get("error"):
        print(f"  error    {status['error']}")


def cmd_backend_add(args: argparse.Namespace) -> int:
    from . import backends

    settings = _require_settings(args)
    token = str(Path(args.token_file).expanduser().resolve()) if args.token_file else None
    with _database(settings).session() as conn:
        backend = backends.create_backend(conn, settings, name=args.name, kind=args.kind, base_url=args.url,
                                          auth_token_file=token, timeout_s=args.timeout_s,
                                          max_concurrency=args.max_concurrency, actor_type="cli", actor_id=_actor())
    if args.json:
        _print_json(backend)
    else:
        print(f"Added backend {backend['name']} ({backend['kind']}) at {backend['base_url']}, id {backend['id']}"
              + (", with a bearer token" if backend["has_token"] else "") + ". Check it with: "
              f"ferry backend check {backend['name']}")
    return EXIT_OK


def cmd_backend_list(args: argparse.Namespace) -> int:
    from . import backends

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        items = backends.list_backends(conn)
    if args.json:
        _print_json({"items": items})
        return EXIT_OK
    rows = [[str(b["id"]), b["name"], b["kind"], b["base_url"], "yes" if b["enabled"] else "no",
             (b["last_status"] or {}).get("state", "unchecked") if isinstance(b["last_status"], dict) else "unchecked",
             b["last_checked_at"] or "-"] for b in items]
    _table(rows, ["ID", "NAME", "KIND", "URL", "ENABLED", "STATE", "CHECKED"])
    return EXIT_OK


def cmd_backend_check(args: argparse.Namespace) -> int:
    import asyncio

    from . import backends
    from .gateway.state import build_state, close_state

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        backend = backends.get_backend_by_name(conn, args.name)

    async def check() -> dict[str, Any]:
        state = build_state(settings)
        try:
            return await backends.refresh_backend(state, int(backend["id"]), actor_type="cli", actor_id=_actor())
        finally:
            await close_state(state)

    status = asyncio.run(check())
    if args.json:
        _print_json(status)
    else:
        _print_status(backend["name"], status)
    return EXIT_OK if status["state"] == "up" else EXIT_REJECTED


def cmd_route_add(args: argparse.Namespace) -> int:
    from . import backends

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        backend = backends.get_backend_by_name(conn, args.backend)
        route = backends.create_route(conn, model=args.model, backend_id=int(backend["id"]),
                                      upstream_model=args.upstream_model, artifact_digest=args.artifact,
                                      require_verified=not args.no_require_verified, actor_type="cli",
                                      actor_id=_actor())
    if args.json:
        _print_json(route)
    else:
        pin = f"pinned to sha256:{route['artifact_digest']}" if route["artifact_digest"] else "not pinned"
        print(f"Added route {route['model']} -> {route['backend_name']} ({route['upstream_model']}), {pin}, "
              f"require_verified {'on' if route['require_verified'] else 'off'}; provenance "
              f"{route['provenance']['state']}.")
    return EXIT_OK


def cmd_route_list(args: argparse.Namespace) -> int:
    from . import backends

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        items = backends.list_routes(conn)
    if args.json:
        _print_json({"items": items})
        return EXIT_OK
    rows = [[r["model"], r["backend_name"], r["upstream_model"], (r["artifact_digest"] or "-")[:16],
             r["provenance"]["state"], "yes" if r["available"] else f"no: {r['reason']}"] for r in items]
    _table(rows, ["MODEL", "BACKEND", "UPSTREAM", "PIN", "PROVENANCE", "AVAILABLE"])
    return EXIT_OK


def _print_validation(result: dict[str, Any]) -> None:
    for e in result["errors"]:
        print(f"error   {e['path'] or 'document'}: {e['message']}")
    for w in result["warnings"]:
        print(f"warning {w['rule_id'] or 'policy'}: {w['message']}")


def _known_names(settings: Settings | None) -> tuple[list[str] | None, list[str] | None]:
    if settings is None:
        return None, None
    with _database(settings).session() as conn:
        return ([r["name"] for r in conn.execute("SELECT name FROM principals")],
                [r["model"] for r in conn.execute("SELECT model FROM routes")])


def cmd_policy_validate(args: argparse.Namespace) -> int:
    from . import policy

    document = _read_json_file(args.file)
    apps, models = _known_names(_settings(args, required=False))
    result = policy.validate_policy(document, apps, models)
    if args.json:
        _print_json(result)
    else:
        _print_validation(result)
        print("valid" if result["valid"] else f"invalid: {len(result['errors'])} error(s)")
    return EXIT_OK if result["valid"] else EXIT_REJECTED


def cmd_policy_activate(args: argparse.Namespace) -> int:
    from . import policy

    document = _read_json_file(args.file)
    settings = _require_settings(args)
    try:
        with _database(settings).session() as conn:
            result = policy.activate_policy(conn, document, actor_type="cli", actor_id=_actor(),
                                            comment=args.comment or "")
    except ValidationFailed as exc:
        validation = exc.details.get("validation")
        if validation is None:
            raise
        _print_validation(validation)
        _err(f"ferry: {exc.message}")
        return EXIT_REJECTED
    if args.json:
        _print_json(result)
    else:
        for w in result["warnings"]:
            print(f"warning {w['rule_id'] or 'policy'}: {w['message']}")
        print(f"Activated policy version {result['version']} (sha256 {result['sha256']}).")
    return EXIT_OK


def cmd_policy_show(args: argparse.Namespace) -> int:
    from . import policy

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        active, history = policy.get_active_policy(conn), policy.policy_history(conn)
    if args.json:
        _print_json({"active": active, "history": history})
        return EXIT_OK
    if active is None:
        print("No active policy: every gateway request is denied.")
    else:
        print(f"Active policy version {active['version']} (sha256 {active['sha256']}), activated "
              f"{active['activated_at']} by {active['activated_by']}")
        print(json.dumps(active["document"], indent=2))
    if history:
        print("History:")
        _table([[str(h["version"]), h["created_at"], h["created_by"], "active" if h["active"] else "", h["comment"]]
                for h in history], ["VERSION", "CREATED", "BY", "", "COMMENT"])
    return EXIT_OK


def cmd_policy_explain(args: argparse.Namespace) -> int:
    from . import policy

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        result = policy.explain(conn, app=args.app, model=args.model, action=args.action)
    if args.json:
        _print_json(result)
    else:
        print(f"{'ALLOW' if result['allowed'] else 'DENY'}  {result['principal']} -> {args.model} ({args.action}): "
              f"{result['reason']}")
        print(f"  policy version {result['policy_version']}, decisive rule {result['decisive_rule'] or '-'}")
        if result["allowed"]:
            limits = result["limits"]
            print(f"  limits: max_tokens {limits['max_tokens'] or 'no policy cap'}, stream "
                  f"{'allowed' if limits['allow_stream'] else 'not allowed'}")
    return EXIT_OK if result["allowed"] else EXIT_REJECTED


def cmd_runtime_llamacpp(args: argparse.Namespace) -> int:
    from . import runtime

    settings = _require_settings(args)
    database = _database(settings)
    binary = args.binary or runtime.DEFAULT_BINARY
    executable = None if args.print_only else shutil.which(binary)
    if not args.print_only and executable is None:
        raise UsageError(f"{binary} was not found on PATH; install llama.cpp, pass --binary, or use --print-only")
    with database.session() as conn:
        registration = runtime.ensure_llamacpp_registration(settings, conn, args.model, args.port, actor_type="cli",
                                                            actor_id=_actor())
        command = runtime.llamacpp_command(settings, conn, args.model, args.port, args.ctx_size,
                                           binary=executable or binary)
    created = [k.replace("_", " ") for k, v in registration["created"].items() if v]
    _err(f"model {registration['model']}: store file sha256:{registration['digest']}")
    _err(f"backend {registration['backend']['name']} -> {registration['backend']['base_url']}; route "
         f"{registration['route']['model']} pinned, require_verified"
         + (f" (created: {', '.join(created)})" if created else " (already registered)"))
    for warning in registration["warnings"]:
        _err(f"warning: {warning}")
    if args.print_only:
        print(shlex.join(command))
        return EXIT_OK
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(command[0], command)  # replaces this process; does not return
    return EXIT_ERROR  # pragma: no cover


# --- audit, store, evidence, doctor, serve ---------------------------------------------------------


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from . import audit, crypto

    settings = _require_settings(args)
    checkpoint = _read_json_file(args.checkpoint) if args.checkpoint else None
    if checkpoint is not None and (not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("seq"), int)
                                   or not isinstance(checkpoint.get("hash"), str)):
        raise UsageError(f"{args.checkpoint} is not an audit checkpoint (needs integer seq and hash)")
    signature = None
    with _database(settings).session() as conn:
        result = audit.verify_chain(conn, checkpoint)
        if checkpoint is not None and checkpoint.get("signature") is not None:
            if args.checkpoint_key:
                key = crypto.load_public_key_file(Path(args.checkpoint_key))
                signature = "valid" if audit.verify_checkpoint_signature(checkpoint, key) else "invalid"
                if signature == "invalid":
                    result["ok"] = False
                    result["problem"] = result["problem"] or "the checkpoint's signature does not verify with that key"
            else:
                signature = "not checked (pass --checkpoint-key PUB.pem)"
        audit.append_event(conn, actor_type="cli", actor_id=_actor(), action="audit.verify", resource="audit",
                           outcome="success" if result["ok"] else "failure",
                           details={**{k: result[k] for k in ("ok", "events_checked", "head_seq", "head_hash",
                                                              "first_bad_seq", "problem", "checkpoint_verified")},
                                    "via": "cli", "checkpoint_signature": signature})
    if args.json:
        _print_json({**result, "checkpoint_signature": signature})
    elif result["ok"]:
        print(f"Audit chain intact: {result['events_checked']} event(s), head #{result['head_seq']} "
              f"{result['head_hash']}" + (" (checkpoint confirmed)" if result["checkpoint_verified"] else ""))
        if signature:
            print(f"Checkpoint signature: {signature}")
    else:
        print(f"Audit chain BROKEN at event #{result['first_bad_seq']}: {result['problem']}")
    return EXIT_OK if result["ok"] else EXIT_REJECTED


def cmd_audit_export(args: argparse.Namespace) -> int:
    import tempfile

    from . import audit

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        if args.out:
            out = Path(args.out).resolve()
            fd, tmp = tempfile.mkstemp(prefix=f".{out.name}.", dir=out.parent)
            try:
                with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
                    count = audit.export_jsonl(conn, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.chmod(tmp, 0o600)
                os.replace(tmp, out)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        else:
            count = audit.export_jsonl(conn, sys.stdout)
            sys.stdout.flush()
        head = audit.head(conn)
        audit.append_event(conn, actor_type="cli", actor_id=_actor(), action="audit.export", resource="audit",
                           outcome="success", details={"events": count, "head_seq": head["seq"],
                                                       "head_hash": head["hash"], "via": "cli",
                                                       "out": str(args.out) if args.out else "stdout"})
    _err(f"exported {count} audit event(s)" + (f" to {args.out}" if args.out else ""))
    return EXIT_OK


def cmd_audit_checkpoint(args: argparse.Namespace) -> int:
    from . import audit
    from .util import atomic_write

    settings = _require_settings(args)
    key = _load_key(args.sign_key, args) if args.sign_key else None
    with _database(settings).session() as conn:
        checkpoint = audit.make_checkpoint(conn, key)
        signature = checkpoint.get("signature") or {}
        audit.append_event(conn, actor_type="cli", actor_id=_actor(), action="audit.checkpoint", resource="audit",
                           outcome="success", details={"seq": checkpoint["seq"], "hash": checkpoint["hash"],
                                                       "signed": key is not None, "key_id": signature.get("key_id"),
                                                       "out": str(args.out) if args.out else "stdout"})
    text = json.dumps(checkpoint, indent=2) + "\n"
    if args.out:
        atomic_write(Path(args.out), text.encode("ascii"), mode=0o644)
        _err(f"checkpoint of event #{checkpoint['seq']} written to {args.out}; keep a copy outside this host")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_store_verify(args: argparse.Namespace) -> int:
    from .bundle.store import verify_store

    settings = _require_settings(args)
    result = verify_store(settings, database=_database(settings), actor_type="cli", actor_id=_actor())
    if args.json:
        _print_json(result)
    else:
        print(f"Store {result['store_dir']}: {result['checked']} file(s), {result['bytes_checked']:,} bytes re-hashed: "
              + ("OK" if result["ok"] else "PROBLEMS"))
        for m in result["mismatches"]:
            print(f"  mismatch  {m['digest']} now hashes to {m['actual_sha256']}")
        for d in result["missing"]:
            print(f"  missing   {d} (imported, but the file is gone)")
        for p in result["problems"]:
            print(f"  problem   {p}")
        for w in result["warnings"]:
            print(f"  warning   {w}")
    return EXIT_OK if result["ok"] else EXIT_REJECTED


def cmd_evidence(args: argparse.Namespace) -> int:
    from .evidence import build_evidence, render_markdown
    from .util import atomic_write

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        report = build_evidence(settings, conn)
    text = render_markdown(report) if args.format == "md" else json.dumps(report, indent=2) + "\n"
    if args.out:
        atomic_write(Path(args.out), text.encode("utf-8"), mode=0o644)
        _err(f"evidence report written to {args.out}")
    else:
        sys.stdout.write(text)
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from .doctor import network_inventory, run_checks

    settings = _require_settings(args)
    with _database(settings).session() as conn:
        checks = run_checks(settings, conn, probe_network=args.probe_network)
        inventory = network_inventory(settings, conn)
    if args.json:
        _print_json({"checks": checks, "network_inventory": inventory})
    else:
        for check in checks:
            print(f"[{check['status'].upper():4}] {check['id']}: {check['message']}")
        print("\nNetwork inventory:")
        for item in inventory:
            print(f"  {item['direction']:<10} {item['component']}: {item['destination']} ({item['purpose']})")
    return EXIT_REJECTED if any(c["status"] == "fail" for c in checks) else EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .config import validate
    from .doctor import is_loopback_host
    from .gateway.app import create_app

    settings = _require_settings(args)
    _database(settings)
    server = dataclasses.replace(settings.server, host=args.host or settings.server.host,
                                 port=args.port if args.port is not None else settings.server.port)
    settings = dataclasses.replace(settings, server=server)
    validate(settings)
    tls = bool(server.tls_cert_file and server.tls_key_file)
    if not tls and not is_loopback_host(server.host):
        _err(f"warning: listening on {server.host} without TLS; API keys, console sessions, prompts and completions "
             "cross the network unencrypted. Set [server] tls_cert_file and tls_key_file.")
    config = uvicorn.Config(create_app(settings), host=server.host, port=server.port,
                            ssl_certfile=server.tls_cert_file or None, ssl_keyfile=server.tls_key_file or None,
                            log_level="info", server_header=False, lifespan="on")
    instance = uvicorn.Server(config)
    instance.run()
    return EXIT_OK if instance.started else EXIT_ERROR


# --- parser ---------------------------------------------------------------------------------------


def _common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS,
                        help="ferry.toml to use (default: FERRY_CONFIG, or <data dir>/ferry.toml)")
    common.add_argument("--data-dir", metavar="DIR", default=argparse.SUPPRESS,
                        help="installation data directory (default: FERRY_DATA_DIR, or data_dir in ferry.toml)")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog="ferry", parents=[common],
        description="Move open-weight models into disconnected networks as signed, reviewable bundles, and serve "
                    "them under a default-deny policy.",
        epilog="Exit codes: 0 success/accepted, 1 rejected/failed, 2 usage, I/O or configuration error.")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    def command(name: str, func: Callable[[argparse.Namespace], int], help_text: str,
                parent: Any = sub) -> argparse.ArgumentParser:
        p = parent.add_parser(name, parents=[common], help=help_text, description=help_text)
        p.set_defaults(func=func)
        return p

    def group(name: str, help_text: str) -> Any:
        p = sub.add_parser(name, parents=[common], help=help_text, description=help_text)
        return p.add_subparsers(dest=f"{name}_command", metavar="SUBCOMMAND", required=True)

    p = command("version", cmd_version, "print the Ferry version")
    p.add_argument("--json", action="store_true")

    command("init", cmd_init, "create a data directory: ferry.toml, database, inbox, store, trust and secrets dirs")

    p = command("keygen", cmd_keygen, "create an Ed25519 signing key pair (NAME.key, NAME.pub.pem)")
    p.add_argument("name", metavar="NAME")
    p.add_argument("--out-dir", metavar="DIR", help="where to write the keys (default: current directory)")
    p.add_argument("--passphrase-file", metavar="F", help="file whose first line encrypts the private key")
    p.add_argument("--no-passphrase", action="store_true", help="write the private key unencrypted")

    p = command("pack", cmd_pack, "build and sign a bundle from a pack spec (TOML)")
    p.add_argument("spec", metavar="SPEC")
    p.add_argument("--key", metavar="K", required=True, help="publisher private key")
    p.add_argument("--passphrase-file", metavar="F", help=f"passphrase for --key (or {PASSPHRASE_ENV})")
    p.add_argument("--out", metavar="DIR", help="output directory (default: current directory)")
    p.add_argument("--created-at", metavar="TS", help="RFC 3339 creation time, for reproducible bundles")
    p.add_argument("--allow-unsafe", action="store_true",
                   help="pack pickle, executable or archive content anyway (the default import policy rejects it)")
    p.add_argument("--json", action="store_true")

    p = command("sign", cmd_sign, "countersign a bundle after checking its integrity")
    p.add_argument("bundle", metavar="BUNDLE")
    p.add_argument("--key", metavar="K", required=True, help="reviewer private key")
    p.add_argument("--passphrase-file", metavar="F", help=f"passphrase for --key (or {PASSPHRASE_ENV})")
    p.add_argument("--json", action="store_true")

    p = command("inspect", cmd_inspect, "show a bundle's manifest and signatures without verifying anything")
    p.add_argument("bundle", metavar="BUNDLE")
    p.add_argument("--json", action="store_true")

    p = command("verify", cmd_verify, "verify a bundle (recorded when a data directory is given)")
    p.add_argument("bundle", metavar="BUNDLE")
    p.add_argument("--trust-dir", metavar="D", help="trust store to use (default: the installation's)")
    p.add_argument("--require-role", metavar="R", action="append", help="required signer role (repeatable)")
    p.add_argument("--full", action="store_true", help="keep checking after the first structural failure")
    p.add_argument("--json", action="store_true", help="print the verification report as JSON")

    p = command("import", cmd_import, "verify a bundle and import it into the store (data directory required)")
    p.add_argument("bundle", metavar="BUNDLE")
    p.add_argument("--allow-downgrade", action="store_true",
                   help="host-only override: accept a version older than one already imported (audited)")
    p.add_argument("--json", action="store_true")

    trust = group("trust", "manage the trust store (host only)")
    p = command("add", cmd_trust_add, "trust a signer's public key in one or more roles", trust)
    p.add_argument("pem", metavar="PEM")
    p.add_argument("--name", required=True)
    p.add_argument("--role", action="append", required=True, choices=("publisher", "reviewer"))
    p.add_argument("--expires", metavar="TS", help="RFC 3339 time after which the key is no longer trusted")
    p.add_argument("--not-before", metavar="TS", help="RFC 3339 time before which the key is not trusted")
    p.add_argument("--expect-fingerprint", metavar="FP", help="key id prefix (>= 16 hex) read out of band")
    p.add_argument("--comment", default="")
    p.add_argument("--trust-dir", metavar="D", help="a trust directory other than the installation's")
    p = command("list", cmd_trust_list, "list trusted keys and trust store problems", trust)
    p.add_argument("--trust-dir", metavar="D")
    p.add_argument("--json", action="store_true")
    p = command("revoke", cmd_trust_revoke, "revoke a trusted key", trust)
    p.add_argument("key_id", metavar="ID", help="key id or a unique prefix (>= 8 hex)")
    p.add_argument("--reason", required=True)
    p.add_argument("--trust-dir", metavar="D")

    admin = group("admin", "console users (host only)")
    p = command("create-user", cmd_admin_create_user, "create a console user", admin)
    p.add_argument("username", metavar="USERNAME")
    p.add_argument("--role", required=True, choices=("admin", "auditor"))
    p.add_argument("--password-stdin", action="store_true", help="read the password from the first line of stdin")

    app = group("app", "apps (API principals) and their keys")
    p = command("create", cmd_app_create, "create an app", app)
    p.add_argument("name", metavar="NAME")
    p.add_argument("--environment", default="test", choices=("test", "pilot", "production"))
    p.add_argument("--description", default="")
    p.add_argument("--json", action="store_true")
    p = command("list", cmd_app_list, "list apps and their keys", app)
    p.add_argument("--json", action="store_true")
    p = command("key", cmd_app_key, "issue an API key (printed once)", app)
    p.add_argument("name", metavar="NAME")
    p.add_argument("--expires-in-days", metavar="N", type=int)
    p.add_argument("--json", action="store_true")
    p = command("revoke-key", cmd_app_revoke_key, "revoke an API key", app)
    p.add_argument("key_id", metavar="KEY_ID", help="the 12 hex characters after fyk_")

    backend = group("backend", "inference backends")
    p = command("add", cmd_backend_add, "register a backend on a loopback or private address", backend)
    p.add_argument("name", metavar="NAME")
    p.add_argument("--kind", required=True, choices=("llamacpp", "ollama", "openai"))
    p.add_argument("--url", required=True, metavar="U", help="base URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--token-file", metavar="F", help="file whose first line is the backend's bearer token (0600)")
    p.add_argument("--timeout-s", type=float)
    p.add_argument("--max-concurrency", type=int)
    p.add_argument("--json", action="store_true")
    p = command("list", cmd_backend_list, "list backends", backend)
    p.add_argument("--json", action="store_true")
    p = command("check", cmd_backend_check, "health-check a backend now and record the result", backend)
    p.add_argument("name", metavar="NAME")
    p.add_argument("--json", action="store_true")

    route = group("route", "model routes")
    p = command("add", cmd_route_add, "route a public model name to a backend", route)
    p.add_argument("model", metavar="MODEL")
    p.add_argument("--backend", required=True, metavar="NAME")
    p.add_argument("--upstream-model", metavar="ID", help="model id at the backend (default: MODEL)")
    p.add_argument("--artifact", metavar="DIGEST", help="pin to an imported model artifact (sha256)")
    p.add_argument("--no-require-verified", action="store_true",
                   help="allow serving without verified provenance (needed for Ollama and OpenAI-type backends)")
    p.add_argument("--json", action="store_true")
    p = command("list", cmd_route_list, "list routes with provenance", route)
    p.add_argument("--json", action="store_true")

    pol = group("policy", "access policy")
    p = command("validate", cmd_policy_validate, "check a policy document", pol)
    p.add_argument("file", metavar="FILE")
    p.add_argument("--json", action="store_true")
    p = command("activate", cmd_policy_activate, "validate and activate a policy document as a new version", pol)
    p.add_argument("file", metavar="FILE")
    p.add_argument("--comment", default="")
    p.add_argument("--json", action="store_true")
    p = command("show", cmd_policy_show, "show the active policy and its history", pol)
    p.add_argument("--json", action="store_true")
    p = command("explain", cmd_policy_explain, "explain the decision for an app and model (exit 1 when denied)", pol)
    p.add_argument("--app", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--action", default="chat.completions")
    p.add_argument("--json", action="store_true")

    rt = group("runtime", "serve imported models")
    p = command("llamacpp", cmd_runtime_llamacpp,
                "register and start llama-server on an imported GGUF model (offline, loopback, API key file)", rt)
    p.add_argument("model", metavar="MODEL", help="model name, route name or artifact digest")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--ctx-size", type=int)
    p.add_argument("--binary", help="llama-server binary (default: llama-server on PATH)")
    p.add_argument("--print-only", action="store_true",
                   help="register, then print the command instead of starting llama-server")

    aud = group("audit", "the hash-chained audit log")
    p = command("verify", cmd_audit_verify, "verify the audit chain (and a checkpoint)", aud)
    p.add_argument("--checkpoint", metavar="F", help="checkpoint file from ferry audit checkpoint")
    p.add_argument("--checkpoint-key", metavar="PEM", help="public key that signed the checkpoint")
    p.add_argument("--json", action="store_true")
    p = command("export", cmd_audit_export, "export every event as JSON lines", aud)
    p.add_argument("--out", metavar="F")
    p = command("checkpoint", cmd_audit_checkpoint, "write a checkpoint of the head (keep it outside this host)", aud)
    p.add_argument("--sign-key", metavar="K", help="private key to sign the checkpoint with")
    p.add_argument("--passphrase-file", metavar="F", help=f"passphrase for --sign-key (or {PASSPHRASE_ENV})")
    p.add_argument("--out", metavar="F")

    st = group("store", "the content-addressed artifact store")
    p = command("verify", cmd_store_verify, "re-hash every store file", st)
    p.add_argument("--json", action="store_true")

    p = command("evidence", cmd_evidence, "write the evidence report")
    p.add_argument("--format", choices=("md", "json"), default="md")
    p.add_argument("--out", metavar="F")

    p = command("doctor", cmd_doctor, "check this host and list its network interactions")
    p.add_argument("--probe-network", action="store_true",
                   help="also try one TCP connection to two public addresses to see whether the host is isolated")
    p.add_argument("--json", action="store_true")

    p = command("serve", cmd_serve, "run the gateway, admin API and console")
    p.add_argument("--host", help="bind address (default: [server].host)")
    p.add_argument("--port", type=int, help="port (default: [server].port)")

    from . import cli_offline

    cli_offline.register(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except FerryError as exc:
        _err(f"ferry: error: {exc.message}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _err("ferry: interrupted")
        return EXIT_ERROR
    except OSError as exc:
        where = f": {exc.filename}" if exc.filename else ""
        _err(f"ferry: error: {exc.strerror or type(exc).__name__}{where}")
        return EXIT_ERROR
    except Exception as exc:
        if os.environ.get("FERRY_DEBUG"):
            raise
        _err(f"ferry: internal error ({type(exc).__name__}); run with FERRY_DEBUG=1 for a traceback")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
