"""Evidence report (`ferry evidence`, GET /api/evidence, GET /api/evidence.md).

The report gathers what this installation recorded and can check: trust
anchors, imported bundles with their signers and artifact digests,
verification history, routes with model provenance, access policy versions,
the audit chain's verification result, the network inventory, dependencies and
the effective configuration. It is configuration and event evidence for a
reviewer or assessor to examine. It is not a compliance certification, and it
can only show what Ferry itself recorded.

Building the report reads the database and the trust store; it changes nothing.
"""

from __future__ import annotations

import json
import platform
import re
import sqlite3
from typing import Any

from . import __version__, audit, backends, doctor, policy
from .bundle.verify import policy_dict
from .config import Settings
from .trust import load_trust_store
from .util import rfc3339, utc_now

REPORT_SCHEMA = "ferry.dev/evidence/v1"
MAX_RECENT_REJECTIONS = 20
STATEMENT = (
    "This report is configuration and event evidence recorded by one Ferry installation: its trust anchors, "
    "imported bundles and their signers, verification history, routes and model provenance, access policy "
    "versions, audit-chain status, network inventory and dependencies. It is not a compliance certification or "
    "an accreditation decision. It shows only what this installation recorded and can check, as of the time "
    "it was generated."
)


def _json(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def _bundles(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    artifacts: dict[str, list[dict[str, Any]]] = {}
    for row in conn.execute(
        "SELECT ba.bundle_id, ba.path, a.digest, a.size, a.kind, a.format, a.model_name, a.metadata"
        " FROM bundle_artifacts ba JOIN artifacts a ON a.digest = ba.digest ORDER BY ba.bundle_id, ba.path"
    ):
        meta = _json(row["metadata"], {})
        model = meta.get("model") if isinstance(meta, dict) and isinstance(meta.get("model"), dict) else {}
        artifacts.setdefault(row["bundle_id"], []).append({
            "path": row["path"], "sha256": row["digest"], "size": row["size"], "kind": row["kind"],
            "format": row["format"], "model_name": row["model_name"], "license": model.get("license"),
            "source_uri": model.get("source_uri"), "source_revision": model.get("source_revision"),
        })
    return [
        {"bundle_id": row["bundle_id"], "name": row["name"], "version": row["version"],
         "imported_at": row["imported_at"], "imported_by": row["imported_by"], "source_name": row["source_name"],
         "signers": _json(row["signers"], []), "artifacts": artifacts.get(row["bundle_id"], [])}
        for row in conn.execute("SELECT bundle_id, name, version, imported_at, imported_by, source_name, signers"
                                " FROM bundles ORDER BY imported_at, bundle_id")
    ]


def _verifications(conn: sqlite3.Connection) -> dict[str, Any]:
    summary: dict[str, Any] = {"total": 0, "accepted": 0, "rejected": 0,
                               "by_mode": {"verify": {"accepted": 0, "rejected": 0},
                                           "import": {"accepted": 0, "rejected": 0}},
                               "recent_rejections": []}
    for row in conn.execute("SELECT mode, verdict, COUNT(*) AS n FROM verifications GROUP BY mode, verdict"):
        n = int(row["n"])
        summary["total"] += n
        summary[row["verdict"]] = summary.get(row["verdict"], 0) + n
        summary["by_mode"].setdefault(row["mode"], {"accepted": 0, "rejected": 0})[row["verdict"]] = n
    for row in conn.execute(
        "SELECT id, source_name, bundle_id, bundle_name, bundle_version, mode, created_at, actor, report"
        " FROM verifications WHERE verdict = 'rejected' ORDER BY id DESC LIMIT ?", (MAX_RECENT_REJECTIONS,)
    ):
        report = _json(row["report"], {})
        checks = report.get("checks") if isinstance(report, dict) else None
        errors = report.get("errors") if isinstance(report, dict) else None
        summary["recent_rejections"].append({
            "id": row["id"], "source_name": row["source_name"], "bundle_id": row["bundle_id"],
            "bundle_name": row["bundle_name"], "bundle_version": row["bundle_version"], "mode": row["mode"],
            "created_at": row["created_at"], "actor": row["actor"],
            "failed_checks": [c.get("id") for c in checks or [] if isinstance(c, dict) and c.get("status") == "fail"],
            "errors": [e for e in errors or [] if isinstance(e, str)][:3],
        })
    return summary


def _routes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    kinds = {b["id"]: b for b in backends.list_backends(conn)}
    out = []
    for route in backends.list_routes(conn):
        backend = kinds.get(route["backend_id"], {})
        out.append({
            "model": route["model"], "backend": route["backend_name"], "backend_kind": backend.get("kind"),
            "base_url": backend.get("base_url"), "upstream_model": route["upstream_model"],
            "pin": route["artifact_digest"], "require_verified": route["require_verified"],
            "enabled": route["enabled"], "provenance": route["provenance"], "available": route["available"],
            "reason": route["reason"],
        })
    return out


def _active_policy(conn: sqlite3.Connection) -> dict[str, Any] | None:
    active = policy.get_active_policy(conn)
    if active is None:
        return None
    rules = active["document"].get("rules") if isinstance(active["document"], dict) else None
    return {"version": active["version"], "sha256": active["sha256"], "activated_at": active["activated_at"],
            "activated_by": active["activated_by"], "created_by": active["created_by"], "comment": active["comment"],
            "rule_count": len(rules) if isinstance(rules, list) else 0, "document": active["document"]}


def _last_checkpoint(conn: sqlite3.Connection) -> dict[str, Any] | None:
    events = audit.query_events(conn, action="audit.checkpoint", limit=1)
    if not events:
        return None
    event = events[0]
    return {"recorded_at": event["ts"], "seq": event["details"].get("seq"), "hash": event["details"].get("hash"),
            "signed": event["details"].get("signed"), "key_id": event["details"].get("key_id")}


def build_evidence(settings: Settings, conn: sqlite3.Connection, *, now: Any = None) -> dict[str, Any]:
    """The evidence report as JSON-serializable data (spec section 10)."""
    stamp = now or utc_now()
    trust = load_trust_store(settings.trust_dir)
    chain = audit.verify_chain(conn)
    chain["last_checkpoint"] = _last_checkpoint(conn)
    return {
        "report": REPORT_SCHEMA,
        "statement": STATEMENT,
        "generated_at": rfc3339(stamp),
        "ferry_version": __version__,
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "config": settings.public_dict(),
        "import_policy": {**policy_dict(settings.imports), "trust_dir": str(settings.trust_dir)},
        "trust_anchors": [entry.to_dict(stamp) for entry in trust.entries],
        "trust_problems": list(trust.problems),
        "bundles": _bundles(conn),
        "verifications": _verifications(conn),
        "routes": _routes(conn),
        "active_policy": _active_policy(conn),
        "policy_history": policy.policy_history(conn),
        "audit": chain,
        "network_inventory": doctor.network_inventory(settings, conn),
        "dependencies": doctor.dependencies(),
    }


# --- Markdown -------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#!])")


def _text(value: Any) -> str:
    """Plain table-cell text: control characters flattened, Markdown and HTML syntax escaped."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return _MD_SPECIAL.sub(r"\\\1", _CONTROL.sub(" ", str(value)))


def _code(value: Any) -> str:
    """A code span that survives backticks and table pipes in `value`."""
    if value is None or value == "":
        return ""
    text = _CONTROL.sub(" ", str(value))
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    escaped = text.replace("|", "\\|")
    return f"{fence}{pad}{escaped}{pad}{fence}"


def _fenced(text: str, info: str = "") -> list[str]:
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + info, *text.splitlines(), fence]


def _table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(cell if cell else " " for cell in row) + " |" for row in rows]
    return out


def _size(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else _text(value)


def _audit_section(chain: dict[str, Any]) -> list[str]:
    if chain.get("ok"):
        status = "**Intact.** Every event's hash matches its content and its predecessor."
    else:
        status = (f"**BROKEN at event #{_text(chain.get('first_bad_seq'))}:** {_text(chain.get('problem'))}. Events "
                  "from that point on cannot be relied on.")
    lines = ["## Audit chain", "", status, ""]
    lines += _table(["Field", "Value"], [
        ["Events checked", _size(chain.get("events_checked"))],
        ["Head sequence number", _size(chain.get("head_seq"))],
        ["Head hash", _code(chain.get("head_hash"))],
        ["Verified at", _text(chain.get("verified_at"))],
    ])
    cp = chain.get("last_checkpoint")
    lines += [""]
    if cp:
        lines.append(f"Last recorded checkpoint: event #{_text(cp.get('seq'))}, hash {_code(cp.get('hash'))}, "
                     f"{'signed' if cp.get('signed') else 'unsigned'}, recorded {_text(cp.get('recorded_at'))}. "
                     "Compare it with the copy kept outside this host to detect truncation.")
    else:
        lines.append("No checkpoint has been recorded. A hash chain alone cannot reveal deleted newest events or a "
                     "rebuilt chain; keep checkpoints (`ferry audit checkpoint`) outside this host.")
    return lines + [""]


def _trust_section(e: dict[str, Any]) -> list[str]:
    lines = ["## Trust anchors", "", f"Trust directory: {_code(e['import_policy'].get('trust_dir'))}", ""]
    anchors = e.get("trust_anchors") or []
    if anchors:
        lines += _table(["Key id", "Name", "Roles", "Status", "Not before", "Not after", "Revoked"], [
            [_code(a.get("key_id")), _text(a.get("name")), _text(", ".join(a.get("roles") or [])), _text(a.get("status")),
             _text(a.get("not_before") or "any time"), _text(a.get("not_after") or "no expiry"),
             _text(f"{a.get('revoked_at')}: {a.get('revocation_reason') or ''}" if a.get("revoked_at") else "no")]
            for a in anchors])
    else:
        lines.append("No trusted keys: every bundle is rejected.")
    problems = e.get("trust_problems") or []
    if problems:
        lines += ["", "Problems found while loading the trust store (these entries are not trusted):", ""]
        lines += [f"- {_text(p)}" for p in problems]
    return lines + [""]


def _policy_rows(p: dict[str, Any]) -> list[list[str]]:
    return [[_text(k), _code(json.dumps(v)) if isinstance(v, (list, dict)) else _text(v)] for k, v in p.items()]


def _bundles_section(e: dict[str, Any]) -> list[str]:
    lines = ["## Imported bundles", ""]
    bundles = e.get("bundles") or []
    if not bundles:
        return lines + ["No bundles have been imported.", ""]
    for b in bundles:
        lines += [f"### {_text(b.get('name'))} {_text(b.get('version'))}", ""]
        signers = "; ".join(f"{_code(s.get('key_id'))} {_text(s.get('name'))} ({_text(', '.join(s.get('roles') or []))})"
                            for s in b.get("signers") or [] if isinstance(s, dict))
        lines += _table(["Field", "Value"], [
            ["Bundle id", _code(b.get("bundle_id"))],
            ["Imported", f"{_text(b.get('imported_at'))} by {_text(b.get('imported_by'))}"],
            ["Source", _code(b.get("source_name"))],
            ["Signers", signers or "none recorded"],
        ])
        lines += [""]
        lines += _table(["Path", "Kind", "Format", "Size (bytes)", "SHA-256", "Licence"], [
            [_code(a.get("path")), _text(a.get("kind")), _text(a.get("format")), _size(a.get("size")),
             _code(a.get("sha256")), _text(a.get("license") or "-")] for a in b.get("artifacts") or []])
        lines += [""]
    return lines


def _verifications_section(v: dict[str, Any]) -> list[str]:
    by_mode = v.get("by_mode") or {}
    lines = ["## Verification history", ""]
    lines += _table(["Mode", "Accepted", "Rejected"], [
        [_text(mode), _size(counts.get("accepted", 0)), _size(counts.get("rejected", 0))]
        for mode, counts in sorted(by_mode.items())])
    recent = v.get("recent_rejections") or []
    if recent:
        lines += ["", "Most recent rejections:", ""]
        lines += _table(["When", "Mode", "Source", "Failed checks", "First reason"], [
            [_text(r.get("created_at")), _text(r.get("mode")), _code(r.get("source_name")),
             _text(", ".join(c for c in r.get("failed_checks") or [] if c)), _text((r.get("errors") or [""])[0])]
            for r in recent])
    return lines + [""]


def _routes_section(e: dict[str, Any]) -> list[str]:
    lines = ["## Routes and model provenance", "",
             "Provenance `verified` means the backend reported serving a file from Ferry's content-addressed store "
             "whose digest equals the route's pin. It catches misconfiguration; a compromised backend can report "
             "anything.", ""]
    routes = e.get("routes") or []
    if not routes:
        return lines + ["No routes are configured.", ""]

    def row(r: dict[str, Any]) -> list[str]:
        prov = r.get("provenance") if isinstance(r.get("provenance"), dict) else {}
        state = _text(prov.get("state"))
        if prov.get("detail"):
            state += ": " + _text(prov.get("detail"))
        available = _text(r.get("available"))
        if r.get("reason"):
            available += " (" + _text(r.get("reason")) + ")"
        backend = _text(r.get("backend")) + " (" + _text(r.get("backend_kind")) + ")"
        return [_code(r.get("model")), backend, _code(r.get("pin")) or "not pinned", _text(r.get("require_verified")),
                state, available]

    lines += _table(["Model", "Backend", "Pinned artifact", "Require verified", "Provenance", "Available"],
                    [row(r) for r in routes])
    return lines + [""]


def _policy_section(e: dict[str, Any]) -> list[str]:
    lines = ["## Access policy", ""]
    active = e.get("active_policy")
    if active:
        lines += _table(["Field", "Value"], [
            ["Active version", _text(active.get("version"))],
            ["SHA-256", _code(active.get("sha256"))],
            ["Activated", f"{_text(active.get('activated_at'))} by {_text(active.get('activated_by'))}"],
            ["Rules", _size(active.get("rule_count"))],
            ["Comment", _text(active.get("comment")) or "none"],
        ])
        lines += ["", "Active document (default deny: a request is allowed only by an allow rule that no deny rule "
                      "overrides):", ""]
        lines += _fenced(json.dumps(active.get("document"), indent=2, sort_keys=True), "json")
    else:
        lines.append("**No active policy: every gateway request is denied.**")
    history = e.get("policy_history") or []
    if history:
        lines += ["", "Version history (newest first):", ""]
        lines += _table(["Version", "Created", "By", "Comment", "SHA-256", "Active"], [
            [_text(h.get("version")), _text(h.get("created_at")), _text(h.get("created_by")), _text(h.get("comment")),
             _code(h.get("sha256")), _text(h.get("active"))] for h in history])
    return lines + [""]


def render_markdown(evidence: dict[str, Any]) -> str:
    """The evidence report as a Markdown document."""
    e = evidence
    host = e.get("host") or {}
    config = e.get("config") or {}
    lines = ["# Ferry evidence report", "", f"**What this is:** {_text(e.get('statement'))}", ""]
    lines += _table(["Field", "Value"], [
        ["Generated", _text(e.get("generated_at"))],
        ["Ferry version", _text(e.get("ferry_version"))],
        ["Platform", _text(host.get("platform"))],
        ["Python", _text(host.get("python"))],
        ["Configuration file", _code(config.get("config_path")) or "none (built-in defaults)"],
        ["Data directory", _code(config.get("data_dir"))],
    ])
    lines += [""]
    lines += _audit_section(e.get("audit") or {})
    lines += _trust_section(e)
    lines += ["## Import policy", ""] + _table(["Setting", "Value"], _policy_rows(e.get("import_policy") or {})) + [""]
    lines += _bundles_section(e)
    lines += _verifications_section(e.get("verifications") or {})
    lines += _routes_section(e)
    lines += _policy_section(e)
    lines += ["## Network inventory", ""]
    lines += _table(["Component", "Direction", "Destination", "Purpose", "Configurable", "Notes"], [
        [_text(n.get("component")), _text(n.get("direction")), _code(n.get("destination")), _text(n.get("purpose")),
         _text(n.get("configurable")), _text(n.get("notes"))] for n in e.get("network_inventory") or []])
    lines += ["", "## Dependencies", ""]
    lines += _table(["Package", "Version"], [[_text(d.get("name")), _code(d.get("version"))]
                                             for d in e.get("dependencies") or []])
    lines += ["", "## Effective configuration", ""]
    lines += _fenced(json.dumps(config, indent=2, sort_keys=True), "json")
    lines += ["", "---", "", "Generated by `ferry evidence`. Configuration and event evidence, not a compliance "
                             "certification.", ""]
    return "\n".join(lines)
