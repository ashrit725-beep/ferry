"""Access policy v1: which app may use which model, decided deterministically.

The default is deny and cannot be changed: a request is allowed only when an
allow rule matches it and no deny rule does. Policies are stored as numbered,
immutable versions. Rolling back means activating an older document as a new
version, so the history always shows what was in force, since when, and who
put it there.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from . import audit
from .db import write_tx
from .errors import FerryError, NotFound, ValidationFailed
from .util import canonical_json, rfc3339, sha256_hex

SCHEMA = "ferry.dev/access-policy/v1"
ACTIONS = ("chat.completions",)
EFFECTS = ("allow", "deny")
MAX_RULES = 1000
MAX_LIST_ITEMS = 256
MAX_DESCRIPTION_CHARS = 2000
MAX_COMMENT_CHARS = 1000
MAX_TOKENS_LIMIT = 1_000_000
# Warnings are advisory; beyond this many the document is wrong in bulk and the
# response would only amplify a large request.
MAX_WARNINGS = 200

RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
# The naming grammar shared with auth.py (principals) and backends.py (routes).
APP_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL_PREFIX = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._:-]{0,126})\*$")
_PREFIX_SEPARATORS = ("-", ".", "_", ":")

_DOC_KEYS = frozenset({"schema", "description", "rules"})
_RULE_KEYS = frozenset({"id", "effect", "principals", "actions", "models", "limits"})
_LIMIT_KEYS = frozenset({"max_tokens", "allow_stream"})


class PolicyIntegrityError(FerryError):
    code = "policy_integrity"


class _Invalid(Exception):
    pass


@dataclass(frozen=True)
class _Pattern:
    """A principal or model pattern. `prefix` is None for an exact match; "*"
    compiles to a prefix ("" for models, "app:" for principals)."""

    raw: str
    prefix: str | None

    def matches(self, value: str) -> bool:
        if self.prefix is None:
            return value == self.raw
        return value.startswith(self.prefix)

    def covers(self, other: _Pattern) -> bool:
        """True when every value `other` matches is also matched by this pattern."""
        if self.prefix is None:
            return other.prefix is None and other.raw == self.raw
        if other.prefix is None:
            return other.raw.startswith(self.prefix)
        return other.prefix.startswith(self.prefix)


@dataclass(frozen=True)
class CompiledRule:
    index: int
    id: str
    effect: str
    principals: tuple[_Pattern, ...]
    actions: frozenset[str]
    models: tuple[_Pattern, ...]
    max_tokens: int | None
    allow_stream: bool

    def match_parts(self, principal: str, action: str, model: str) -> tuple[bool, bool, bool]:
        return (
            any(p.matches(principal) for p in self.principals),
            action in self.actions,
            any(m.matches(model) for m in self.models),
        )

    def matches(self, principal: str, action: str, model: str) -> bool:
        return all(self.match_parts(principal, action, model))

    def covers(self, other: CompiledRule) -> bool:
        return (
            all(any(mine.covers(theirs) for mine in self.principals) for theirs in other.principals)
            and other.actions <= self.actions
            and all(any(mine.covers(theirs) for mine in self.models) for theirs in other.models)
        )


@dataclass(frozen=True)
class CompiledPolicy:
    rules: tuple[CompiledRule, ...]
    sha256: str
    version: int | None = None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    decisive_rule: str | None
    matched_rules: tuple[tuple[str, str], ...]
    max_tokens: int | None
    allow_stream: bool
    policy_version: int | None
    policy_sha256: str | None

    @property
    def limits(self) -> dict[str, Any]:
        return {"max_tokens": self.max_tokens, "allow_stream": self.allow_stream}

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decisive_rule": self.decisive_rule,
            "matched_rules": [{"id": rid, "effect": effect} for rid, effect in self.matched_rules],
            "reason": self.reason,
            "limits": self.limits,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
        }


def default_policy_document() -> dict[str, Any]:
    """The starting document: no rules, so nothing is allowed until an admin says so."""
    return {
        "schema": SCHEMA,
        "description": "Default policy: no rule allows anything, so every request is denied. "
                       "Add allow rules for specific apps and models.",
        "rules": [],
    }


# --- parsing -----------------------------------------------------------------


def _principal_pattern(item: Any) -> _Pattern:
    if not isinstance(item, str):
        raise _Invalid("must be a string")
    if item in ("*", "app:*"):
        # Every principal is an app in v1, so both spellings mean "any app".
        return _Pattern(item, "app:")
    if item.startswith("app:") and APP_NAME.fullmatch(item[4:]):
        return _Pattern(item, None)
    raise _Invalid("must be '*', 'app:*' or 'app:<name>' (name: lowercase letters, digits, '-' and '_')")


def _action_set(item: Any) -> frozenset[str]:
    if item == "*":
        return frozenset(ACTIONS)
    if isinstance(item, str) and item in ACTIONS:
        return frozenset({item})
    raise _Invalid(f"unknown action; use one of: {', '.join(ACTIONS)}, *")


def _model_pattern(item: Any) -> _Pattern:
    if not isinstance(item, str):
        raise _Invalid("must be a string")
    if item == "*":
        return _Pattern(item, "")
    if item.endswith("*"):
        m = _MODEL_PREFIX.fullmatch(item)
        if not m:
            raise _Invalid("a wildcard is only allowed as the last character, after a model-name prefix "
                           "(for example 'qwen2.5-*')")
        return _Pattern(item, m.group(1))
    if MODEL_NAME.fullmatch(item):
        return _Pattern(item, None)
    raise _Invalid("not a valid model name (letters, digits, '.', '_', ':' and '-'; at most 128 characters)")


def _parse_list(value: Any, path: str, parse: Callable[[Any], Any], err: Callable[[str, str], None]) -> list[Any]:
    if not isinstance(value, list) or not value:
        err(path, "required: a non-empty list")
        return []
    if len(value) > MAX_LIST_ITEMS:
        err(path, f"at most {MAX_LIST_ITEMS} entries")
        return []
    out = []
    for j, item in enumerate(value):
        try:
            out.append(parse(item))
        except _Invalid as exc:
            err(f"{path}[{j}]", str(exc))
    return out


def _parse_rule(i: int, raw: Any, err: Callable[[str, str], None], seen: dict[str, int],
                errors: list[dict[str, str]]) -> CompiledRule | None:
    path = f"rules[{i}]"
    if not isinstance(raw, dict):
        err(path, "each rule must be an object")
        return None
    before = len(errors)
    for key in sorted(set(raw) - _RULE_KEYS):
        err(f"{path}.{key}", "unknown key")
    rid = raw.get("id")
    if not isinstance(rid, str) or not RULE_ID.fullmatch(rid):
        err(f"{path}.id", "required: 1-64 characters, lowercase letters, digits, '-' or '_', "
                          "starting with a letter or digit")
    elif rid in seen:
        err(f"{path}.id", f"duplicate rule id '{rid}' (also used by rules[{seen[rid]}])")
    else:
        seen[rid] = i
    effect = raw.get("effect")
    if effect not in EFFECTS:
        err(f"{path}.effect", 'required: "allow" or "deny"')
    principals = _parse_list(raw.get("principals"), f"{path}.principals", _principal_pattern, err)
    action_sets = _parse_list(raw.get("actions"), f"{path}.actions", _action_set, err)
    models = _parse_list(raw.get("models"), f"{path}.models", _model_pattern, err)
    max_tokens: int | None = None
    allow_stream = True
    if "limits" in raw:
        limits = raw["limits"]
        if effect == "deny":
            err(f"{path}.limits", "limits are only allowed on allow rules")
        elif not isinstance(limits, dict):
            err(f"{path}.limits", "must be an object")
        else:
            for key in sorted(set(limits) - _LIMIT_KEYS):
                err(f"{path}.limits.{key}", "unknown key")
            if "max_tokens" in limits:
                value = limits["max_tokens"]
                if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TOKENS_LIMIT:
                    err(f"{path}.limits.max_tokens", f"must be a whole number from 1 to {MAX_TOKENS_LIMIT}")
                else:
                    max_tokens = value
            if "allow_stream" in limits:
                if not isinstance(limits["allow_stream"], bool):
                    err(f"{path}.limits.allow_stream", "must be true or false")
                else:
                    allow_stream = limits["allow_stream"]
    if len(errors) != before:
        return None
    return CompiledRule(
        index=i,
        id=rid,
        effect=effect,
        principals=tuple(principals),
        actions=frozenset().union(*action_sets),
        models=tuple(models),
        max_tokens=max_tokens,
        allow_stream=allow_stream,
    )


def _parse(doc: Any) -> tuple[list[CompiledRule], list[dict[str, str]]]:
    errors: list[dict[str, str]] = []

    def err(path: str, message: str) -> None:
        errors.append({"path": path, "message": message})

    if not isinstance(doc, dict):
        err("", "the policy must be a JSON object")
        return [], errors
    for key in sorted(set(doc) - _DOC_KEYS, key=str):
        err(str(key), "unknown key")
    if doc.get("schema") != SCHEMA:
        err("schema", f'required: "{SCHEMA}"')
    description = doc.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS:
        err("description", f"must be a string of at most {MAX_DESCRIPTION_CHARS} characters")
    raw_rules = doc.get("rules")
    if not isinstance(raw_rules, list):
        err("rules", "required: a list of rules (it may be empty)")
        return [], errors
    if len(raw_rules) > MAX_RULES:
        err("rules", f"at most {MAX_RULES} rules")
        return [], errors
    seen: dict[str, int] = {}
    rules = []
    for i, raw in enumerate(raw_rules):
        rule = _parse_rule(i, raw, err, seen, errors)
        if rule is not None:
            rules.append(rule)
    return rules, errors


def _warnings(rules: list[CompiledRule], known_apps: Iterable[str] | None,
              known_models: Iterable[str] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def warn(rule_id: str | None, message: str) -> None:
        out.append({"rule_id": rule_id, "message": message})

    if not rules:
        warn(None, "the policy has no rules, so every request is denied")
    apps = set(known_apps) if known_apps is not None else None
    models = set(known_models) if known_models is not None else None
    for rule in rules:
        if apps is not None:
            for p in rule.principals:
                if p.prefix is None and p.raw[4:] not in apps:
                    warn(rule.id, f"app '{p.raw[4:]}' does not exist")
        for m in rule.models:
            if models is not None:
                if m.prefix is None and m.raw not in models:
                    warn(rule.id, f"model '{m.raw}' has no route")
                elif m.prefix and rule.effect == "allow" and not any(x.startswith(m.prefix) for x in models):
                    warn(rule.id, f"no routed model matches '{m.raw}'")
            if m.prefix and not m.prefix.endswith(_PREFIX_SEPARATORS):
                warn(rule.id, f"'{m.raw}' matches every model name starting with '{m.prefix}' (including "
                              f"'{m.prefix}' itself); if you meant only the '{m.prefix}-' family, write '{m.prefix}-*'")
        if (rule.effect == "allow" and any(p.prefix == "app:" for p in rule.principals)
                and any(m.prefix == "" for m in rule.models)):
            warn(rule.id, "this rule allows every app to use every model")
        # A deny decides whatever it matches, so an allow covered by any deny never
        # applies; a deny only becomes decisive if no earlier deny covers it.
        shadow = next((d for d in rules if d is not rule and d.effect == "deny"
                       and (rule.effect == "allow" or d.index < rule.index) and d.covers(rule)), None)
        if shadow is not None:
            if rule.effect == "allow":
                warn(rule.id, f"never takes effect: deny rule '{shadow.id}' matches every request this rule allows")
            else:
                warn(rule.id, f"never decisive: the earlier deny rule '{shadow.id}' already matches "
                              "every request this rule matches")
    if len(out) > MAX_WARNINGS:
        dropped = len(out) - MAX_WARNINGS
        out = out[:MAX_WARNINGS]
        out.append({"rule_id": None, "message": f"{dropped} more warning(s) not shown"})
    return out


def validate_policy(doc: Any, known_apps: Iterable[str] | None = None,
                    known_models: Iterable[str] | None = None) -> dict[str, Any]:
    """Errors make a document unusable; warnings point at likely mistakes and are
    only computed for a document without errors."""
    rules, errors = _parse(doc)
    warnings = _warnings(rules, known_apps, known_models) if not errors else []
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def compile_policy(doc: Any, *, version: int | None = None, sha256: str | None = None) -> CompiledPolicy:
    rules, errors = _parse(doc)
    if errors:
        first = errors[0]
        raise ValidationFailed(
            f"policy is invalid ({len(errors)} error(s)); first: {first['path'] or 'document'}: {first['message']}",
            details={"errors": errors},
        )
    return CompiledPolicy(rules=tuple(rules), sha256=sha256 or sha256_hex(canonical_json(doc)), version=version)


# --- evaluation --------------------------------------------------------------


def _deny(reason: str, compiled: CompiledPolicy | None, decisive: str | None = None,
          matched: tuple[tuple[str, str], ...] = ()) -> Decision:
    return Decision(
        allowed=False, reason=reason, decisive_rule=decisive, matched_rules=matched, max_tokens=None,
        allow_stream=False, policy_version=compiled.version if compiled else None,
        policy_sha256=compiled.sha256 if compiled else None,
    )


def valid_principal(principal: str) -> bool:
    return isinstance(principal, str) and principal.startswith("app:") and bool(APP_NAME.fullmatch(principal[4:]))


def evaluate(compiled: CompiledPolicy | None, *, principal: str, action: str, model: str) -> Decision:
    """Decide (principal, action, model). Malformed input is denied, never guessed at."""
    if compiled is None:
        return _deny("no active policy: every request is denied until a policy is activated", None)
    if not valid_principal(principal):
        return _deny("invalid principal", compiled)
    if not isinstance(action, str) or action not in ACTIONS:
        return _deny("unknown action", compiled)
    if not isinstance(model, str) or not MODEL_NAME.fullmatch(model):
        return _deny("invalid model name", compiled)
    matched = [r for r in compiled.rules if r.matches(principal, action, model)]
    summary = tuple((r.id, r.effect) for r in matched)
    denies = [r for r in matched if r.effect == "deny"]
    if denies:
        return _deny(f"denied by rule '{denies[0].id}'", compiled, denies[0].id, summary)
    allows = [r for r in matched if r.effect == "allow"]
    if not allows:
        return _deny("no rule allows", compiled, None, summary)
    # Limits are a union: the most permissive matching allow wins.
    max_tokens = None if any(r.max_tokens is None for r in allows) else max(r.max_tokens or 0 for r in allows)
    reason = f"allowed by rule '{allows[0].id}'"
    if len(allows) > 1:
        reason += f" (and {len(allows) - 1} more)"
    return Decision(
        allowed=True, reason=reason, decisive_rule=allows[0].id, matched_rules=summary, max_tokens=max_tokens,
        allow_stream=any(r.allow_stream for r in allows), policy_version=compiled.version,
        policy_sha256=compiled.sha256,
    )


def trace(compiled: CompiledPolicy | None, *, principal: str, action: str, model: str) -> list[dict[str, Any]]:
    """Per-rule match detail, for explaining a decision to an operator."""
    if compiled is None:
        return []
    out = []
    for rule in compiled.rules:
        p, a, m = rule.match_parts(principal, action, model)
        out.append({"id": rule.id, "effect": rule.effect, "matched": p and a and m,
                    "principal_matched": p, "action_matched": a, "model_matched": m})
    return out


# --- storage -----------------------------------------------------------------


def _known_names(conn: sqlite3.Connection) -> tuple[list[str], list[str]]:
    apps = [r["name"] for r in conn.execute("SELECT name FROM principals")]
    models = [r["model"] for r in conn.execute("SELECT model FROM routes")]
    return apps, models


def activate_policy(conn: sqlite3.Connection, doc: Any, *, actor_type: str, actor_id: str,
                    comment: str = "") -> dict[str, Any]:
    """Validate and store `doc` as the next version and make it active.

    Returns {version, sha256, warnings}. Raises ValidationFailed (details carry
    the full validation result) when the document has errors."""
    if not isinstance(comment, str) or len(comment) > MAX_COMMENT_CHARS:
        raise ValidationFailed(f"comment must be a string of at most {MAX_COMMENT_CHARS} characters")
    apps, models = _known_names(conn)
    result = validate_policy(doc, apps, models)
    if not result["valid"]:
        raise ValidationFailed(f"policy is invalid ({len(result['errors'])} error(s)); nothing was activated",
                               details={"validation": result})
    text = canonical_json(doc).decode("ascii")
    digest = sha256_hex(text.encode("ascii"))
    now = rfc3339()
    by = f"{actor_type}:{actor_id}"
    with write_tx(conn):
        previous = conn.execute("SELECT version FROM active_policy WHERE id = 1").fetchone()
        version = int(conn.execute("SELECT COALESCE(MAX(version), 0) AS v FROM policies").fetchone()["v"]) + 1
        conn.execute(
            "INSERT INTO policies (version, document, sha256, created_at, created_by, comment) VALUES (?,?,?,?,?,?)",
            (version, text, digest, now, by, comment),
        )
        conn.execute(
            "INSERT INTO active_policy (id, version, activated_at, activated_by) VALUES (1, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET version = excluded.version, activated_at = excluded.activated_at,"
            " activated_by = excluded.activated_by",
            (version, now, by),
        )
        audit.append_event(
            conn, actor_type=actor_type, actor_id=actor_id, action="policy.activate", resource=f"policy:{version}",
            outcome="success", policy_version=version,
            details={"version": version, "sha256": digest, "previous_version": previous["version"] if previous else None,
                     "rule_count": len(doc["rules"]), "warning_count": len(result["warnings"]), "comment": comment},
        )
    return {"version": version, "sha256": digest, "warnings": result["warnings"]}


def get_active_policy(conn: sqlite3.Connection) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT p.version, p.document, p.sha256, p.created_at, p.created_by, p.comment, a.activated_at, a.activated_by"
        " FROM active_policy a JOIN policies p ON p.version = a.version WHERE a.id = 1"
    ).fetchone()
    if row is None:
        return None
    return {
        "version": row["version"], "sha256": row["sha256"], "document": json.loads(row["document"]),
        "created_at": row["created_at"], "created_by": row["created_by"], "activated_at": row["activated_at"],
        "activated_by": row["activated_by"], "comment": row["comment"],
    }


def _active_version(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT version FROM active_policy WHERE id = 1").fetchone()
    return row["version"] if row else None


def policy_history(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Every stored version, newest first."""
    active = _active_version(conn)
    return [
        {"version": r["version"], "sha256": r["sha256"], "created_at": r["created_at"],
         "created_by": r["created_by"], "comment": r["comment"], "active": r["version"] == active}
        for r in conn.execute("SELECT version, sha256, created_at, created_by, comment FROM policies"
                              " ORDER BY version DESC")
    ]


def get_policy_version(conn: sqlite3.Connection, version: int) -> dict[str, Any]:
    if isinstance(version, bool) or not isinstance(version, int):
        raise NotFound("policy versions are whole numbers")
    row = conn.execute("SELECT * FROM policies WHERE version = ?", (version,)).fetchone()
    if row is None:
        raise NotFound(f"policy version {version} does not exist")
    return {
        "version": row["version"], "sha256": row["sha256"], "document": json.loads(row["document"]),
        "created_at": row["created_at"], "created_by": row["created_by"], "comment": row["comment"],
        "active": row["version"] == _active_version(conn),
    }


def load_compiled(conn: sqlite3.Connection, version: int) -> CompiledPolicy:
    """Compile a stored version after checking it still matches its recorded digest."""
    row = conn.execute("SELECT version, document, sha256 FROM policies WHERE version = ?", (version,)).fetchone()
    if row is None:
        raise NotFound(f"policy version {version} does not exist")
    if sha256_hex(row["document"].encode("utf-8")) != row["sha256"]:
        raise PolicyIntegrityError(f"stored policy version {version} does not match its recorded sha256")
    try:
        doc = json.loads(row["document"])
    except ValueError:
        raise PolicyIntegrityError(f"stored policy version {version} is not valid JSON") from None
    return compile_policy(doc, version=row["version"], sha256=row["sha256"])


def load_active_compiled(conn: sqlite3.Connection) -> CompiledPolicy | None:
    version = _active_version(conn)
    return load_compiled(conn, version) if version is not None else None


def explain(conn: sqlite3.Connection, *, app: str, model: str, action: str = "chat.completions") -> dict[str, Any]:
    """What would happen if `app` asked for `model` now: the policy decision, plus
    the app's own status (a disabled or unknown app is rejected before policy)."""
    if not isinstance(app, str) or not APP_NAME.fullmatch(app):
        raise ValidationFailed("app must be an app name (lowercase letters, digits, '-' and '_')",
                               details={"field": "app"})
    if not isinstance(action, str) or action not in ACTIONS:
        raise ValidationFailed(f"action must be one of: {', '.join(ACTIONS)}", details={"field": "action"})
    if not isinstance(model, str) or not MODEL_NAME.fullmatch(model):
        raise ValidationFailed("model must be a model name, not a pattern", details={"field": "model"})
    principal = f"app:{app}"
    compiled = load_active_compiled(conn)
    decision = evaluate(compiled, principal=principal, action=action, model=model)
    out = decision.to_dict()
    row = conn.execute("SELECT disabled FROM principals WHERE name = ?", (app,)).fetchone()
    status = "unknown" if row is None else ("disabled" if row["disabled"] else "active")
    out.update(principal=principal, principal_status=status, policy_allowed=decision.allowed,
               trace=trace(compiled, principal=principal, action=action, model=model))
    if status != "active":
        out["allowed"] = False
        out["reason"] = (f"app '{app}' does not exist" if status == "unknown"
                         else f"app '{app}' is disabled, so its keys are rejected before policy is evaluated")
    return out
