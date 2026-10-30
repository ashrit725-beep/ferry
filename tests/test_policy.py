"""Tests for ferry.policy: validation, deterministic default-deny evaluation, versions."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from ferry import audit, auth, policy
from ferry.db import write_tx
from ferry.errors import NotFound, ValidationFailed

ACTOR = {"actor_type": "cli", "actor_id": "pytest"}


def doc(*rules: dict[str, Any], description: str = "test") -> dict[str, Any]:
    return {"schema": policy.SCHEMA, "description": description, "rules": list(rules)}


def rule(rule_id: str, effect: str = "allow", principals=("app:report",), actions=("chat.completions",),
         models=("qwen-test",), **extra: Any) -> dict[str, Any]:
    r = {"id": rule_id, "effect": effect, "principals": list(principals), "actions": list(actions),
         "models": list(models)}
    r.update(extra)
    return r


def decide(d: dict[str, Any], principal: str = "app:report", model: str = "qwen-test",
           action: str = "chat.completions") -> policy.Decision:
    return policy.evaluate(policy.compile_policy(d, version=7), principal=principal, action=action, model=model)


# --- evaluation -----------------------------------------------------------------


def test_default_document_denies_everything() -> None:
    d = policy.default_policy_document()
    result = policy.validate_policy(d)
    assert result["valid"] is True and d["rules"] == []
    assert any("every request is denied" in w["message"] for w in result["warnings"])
    decision = decide(d)
    assert decision.allowed is False and decision.reason == "no rule allows" and decision.decisive_rule is None


def test_no_active_policy_denies() -> None:
    decision = policy.evaluate(None, principal="app:report", action="chat.completions", model="qwen-test")
    assert decision.allowed is False and "no active policy" in decision.reason
    assert decision.policy_version is None and decision.policy_sha256 is None


def test_allow_returns_limits_version_and_digest() -> None:
    d = doc(rule("chat", limits={"max_tokens": 256, "allow_stream": False}))
    decision = decide(d)
    assert decision.allowed is True and decision.decisive_rule == "chat"
    assert decision.limits == {"max_tokens": 256, "allow_stream": False}
    assert decision.policy_version == 7
    assert decision.policy_sha256 == policy.compile_policy(d).sha256
    assert decision.to_dict() == {
        "allowed": True, "decisive_rule": "chat", "matched_rules": [{"id": "chat", "effect": "allow"}],
        "reason": "allowed by rule 'chat'", "limits": {"max_tokens": 256, "allow_stream": False},
        "policy_version": 7, "policy_sha256": decision.policy_sha256,
    }


def test_deny_overrides_allow_regardless_of_order() -> None:
    allow_first = doc(rule("chat"), rule("block", "deny", principals=["*"], actions=["*"], models=["qwen-*"]))
    deny_first = doc(rule("block", "deny", principals=["*"], actions=["*"], models=["qwen-*"]), rule("chat"))
    for d in (allow_first, deny_first):
        decision = decide(d)
        assert decision.allowed is False and decision.decisive_rule == "block"
        assert decision.reason == "denied by rule 'block'"
        assert {r for r, _ in decision.matched_rules} == {"chat", "block"}
        assert decision.limits == {"max_tokens": None, "allow_stream": False}


def test_decisive_rule_is_the_first_matching_deny() -> None:
    d = doc(rule("chat"), rule("deny-a", "deny", models=["*"]), rule("deny-b", "deny", models=["qwen-test"]))
    assert decide(d).decisive_rule == "deny-a"


@pytest.mark.parametrize("pattern, model, matches", [
    ("foo-*", "foo-1", True),
    ("foo-*", "foo-bar-baz", True),
    ("foo-*", "foo", False),
    ("foo-*", "foobar", False),
    ("foo-*", "xfoo-1", False),
    ("foo*", "foo", True),
    ("foo*", "foobar", True),
    ("foo", "foo", True),
    ("foo", "foo-1", False),
    ("*", "anything.at:all", True),
    ("qwen2.5-*", "qwen2.5-0.5b-instruct", True),
    ("qwen2.5-*", "qwen2-5-0.5b", False),
])
def test_model_patterns(pattern: str, model: str, matches: bool) -> None:
    assert decide(doc(rule("r", models=[pattern])), model=model).allowed is matches


def test_trailing_wildcard_without_separator_warns() -> None:
    warnings = policy.validate_policy(doc(rule("r", models=["foo*"])))["warnings"]
    assert any("'foo*' matches every model name starting with 'foo'" in w["message"] for w in warnings)
    assert not any("starting with" in w["message"] for w in policy.validate_policy(doc(rule("r", models=["foo-*"])))["warnings"])


@pytest.mark.parametrize("principal_pattern, principal, matches", [
    ("app:report", "app:report", True),
    ("app:report", "app:report2", False),
    ("app:report", "app:other", False),
    ("app:*", "app:anything", True),
    ("*", "app:anything", True),
])
def test_principal_patterns(principal_pattern: str, principal: str, matches: bool) -> None:
    assert decide(doc(rule("r", principals=[principal_pattern])), principal=principal).allowed is matches


@pytest.mark.parametrize("principal, model, action", [
    ("report", "qwen-test", "chat.completions"),
    ("app:Report", "qwen-test", "chat.completions"),
    ("app:", "qwen-test", "chat.completions"),
    ("user:report", "qwen-test", "chat.completions"),
    ("app:report", "qwen-*", "chat.completions"),
    ("app:report", "", "chat.completions"),
    ("app:report", "qwen-test", "embeddings"),
    ("app:report", "qwen-test", "*"),
])
def test_malformed_requests_are_denied_not_guessed(principal: str, model: str, action: str) -> None:
    d = doc(rule("open", principals=["*"], actions=["*"], models=["*"]))
    assert decide(d, principal=principal, model=model, action=action).allowed is False


def test_action_wildcard_covers_chat_completions() -> None:
    assert decide(doc(rule("r", actions=["*"]))).allowed is True


def test_limits_are_the_most_permissive_across_matching_allows() -> None:
    capped = doc(rule("small", limits={"max_tokens": 100, "allow_stream": False}),
                 rule("large", models=["qwen-*"], limits={"max_tokens": 500}))
    decision = decide(capped)
    assert decision.max_tokens == 500 and decision.allow_stream is True
    assert decision.reason == "allowed by rule 'small' (and 1 more)"
    uncapped = doc(rule("small", limits={"max_tokens": 100}), rule("open", models=["*"]))
    assert decide(uncapped).max_tokens is None
    no_stream = doc(rule("a", limits={"allow_stream": False}), rule("b", models=["*"], limits={"allow_stream": False}))
    assert decide(no_stream).allow_stream is False
    # A non-matching allow never contributes limits.
    other = doc(rule("small", limits={"max_tokens": 10}), rule("big", principals=["app:other"], models=["*"]))
    assert decide(other).max_tokens == 10


def test_app_cannot_use_a_model_allowed_only_to_another_app() -> None:
    d = doc(rule("a-chat", principals=["app:app-a"], models=["model-a"]),
            rule("b-chat", principals=["app:app-b"], models=["model-b"]))
    assert decide(d, principal="app:app-a", model="model-a").allowed is True
    assert decide(d, principal="app:app-a", model="model-b").allowed is False
    assert decide(d, principal="app:app-b", model="model-a").allowed is False
    assert decide(d, principal="app:app-c", model="model-a").allowed is False
    # Name prefixes give no access to similarly named apps or models.
    assert decide(d, principal="app:app-a2", model="model-a").allowed is False
    assert decide(d, principal="app:app-a", model="model-a2").allowed is False


def test_evaluation_is_deterministic() -> None:
    d = doc(rule("chat"), rule("block", "deny", models=["other"]))
    compiled = policy.compile_policy(d)
    first = policy.evaluate(compiled, principal="app:report", action="chat.completions", model="qwen-test")
    for _ in range(50):
        assert policy.evaluate(compiled, principal="app:report", action="chat.completions", model="qwen-test") == first


def test_trace_explains_each_rule() -> None:
    compiled = policy.compile_policy(doc(rule("chat"), rule("other", principals=["app:x"])))
    trace = policy.trace(compiled, principal="app:report", action="chat.completions", model="qwen-test")
    assert trace[0] == {"id": "chat", "effect": "allow", "matched": True, "principal_matched": True,
                        "action_matched": True, "model_matched": True}
    assert trace[1]["matched"] is False and trace[1]["principal_matched"] is False
    assert policy.trace(None, principal="app:report", action="chat.completions", model="m") == []


# --- validation -----------------------------------------------------------------


def _errors(d: Any) -> list[dict[str, str]]:
    result = policy.validate_policy(d)
    assert result["valid"] is False and result["warnings"] == []
    return result["errors"]


@pytest.mark.parametrize("mutate, path", [
    (lambda d: d.update(schema="ferry.dev/access-policy/v2"), "schema"),
    (lambda d: d.pop("schema"), "schema"),
    (lambda d: d.update(extra=1), "extra"),
    (lambda d: d.update(default_effect="allow"), "default_effect"),
    (lambda d: d.update(description=5), "description"),
    (lambda d: d.update(description="x" * 2001), "description"),
    (lambda d: d.update(rules={}), "rules"),
    (lambda d: d["rules"].append("not a rule"), "rules[1]"),
    (lambda d: d["rules"][0].update(id="Bad Id"), "rules[0].id"),
    (lambda d: d["rules"][0].update(id="-leading"), "rules[0].id"),
    (lambda d: d["rules"][0].update(id="x" * 65), "rules[0].id"),
    (lambda d: d["rules"][0].pop("id"), "rules[0].id"),
    (lambda d: d["rules"].append(copy.deepcopy(d["rules"][0])), "rules[1].id"),
    (lambda d: d["rules"][0].update(effect="maybe"), "rules[0].effect"),
    (lambda d: d["rules"][0].update(principals=[]), "rules[0].principals"),
    (lambda d: d["rules"][0].update(principals="app:report"), "rules[0].principals"),
    (lambda d: d["rules"][0].update(principals=["report"]), "rules[0].principals[0]"),
    (lambda d: d["rules"][0].update(principals=["app:Upper"]), "rules[0].principals[0]"),
    (lambda d: d["rules"][0].update(principals=["user:*"]), "rules[0].principals[0]"),
    (lambda d: d["rules"][0].update(actions=[]), "rules[0].actions"),
    (lambda d: d["rules"][0].update(actions=["embeddings"]), "rules[0].actions[0]"),
    (lambda d: d["rules"][0].update(models=[]), "rules[0].models"),
    (lambda d: d["rules"][0].update(models=["*-suffix"]), "rules[0].models[0]"),
    (lambda d: d["rules"][0].update(models=["a*b"]), "rules[0].models[0]"),
    (lambda d: d["rules"][0].update(models=["**"]), "rules[0].models[0]"),
    (lambda d: d["rules"][0].update(models=[5]), "rules[0].models[0]"),
    (lambda d: d["rules"][0].update(models=["bad model"]), "rules[0].models[0]"),
    (lambda d: d["rules"][0].update(colour="red"), "rules[0].colour"),
    (lambda d: d["rules"][0].update(limits=[]), "rules[0].limits"),
    (lambda d: d["rules"][0].update(limits={"max_tokens": 0}), "rules[0].limits.max_tokens"),
    (lambda d: d["rules"][0].update(limits={"max_tokens": 1_000_001}), "rules[0].limits.max_tokens"),
    (lambda d: d["rules"][0].update(limits={"max_tokens": 12.5}), "rules[0].limits.max_tokens"),
    (lambda d: d["rules"][0].update(limits={"max_tokens": True}), "rules[0].limits.max_tokens"),
    (lambda d: d["rules"][0].update(limits={"max_tokens": None}), "rules[0].limits.max_tokens"),
    (lambda d: d["rules"][0].update(limits={"allow_stream": "yes"}), "rules[0].limits.allow_stream"),
    (lambda d: d["rules"][0].update(limits={"rpm": 5}), "rules[0].limits.rpm"),
    (lambda d: d["rules"][0].update(effect="deny", limits={"max_tokens": 5}), "rules[0].limits"),
])
def test_validation_errors_name_the_path(mutate, path: str) -> None:
    d = doc(rule("chat"))
    mutate(d)
    assert path in [e["path"] for e in _errors(d)]


@pytest.mark.parametrize("bad", [None, [], "policy", 42])
def test_non_object_documents_are_invalid(bad: Any) -> None:
    assert _errors(bad)[0]["path"] == ""


def test_too_many_rules_is_an_error() -> None:
    d = doc(*[rule(f"r{i}") for i in range(policy.MAX_RULES + 1)])
    assert _errors(d)[0]["path"] == "rules"


def test_compile_policy_rejects_invalid_documents() -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        policy.compile_policy(doc(rule("chat", effect="permit")))
    assert excinfo.value.details["errors"][0]["path"] == "rules[0].effect"


def test_warnings_for_likely_mistakes() -> None:
    d = doc(
        rule("ghost-app", principals=["app:ghost"]),
        rule("no-route", models=["unrouted"]),
        rule("everything", principals=["*"], actions=["*"], models=["*"]),
        rule("block-all", "deny", principals=["*"], actions=["*"], models=["*"]),
        rule("narrow-deny", "deny", models=["qwen-test"]),
        rule("family", models=["llama-*"]),
    )
    result = policy.validate_policy(d, known_apps=["report"], known_models=["qwen-test"])
    assert result["valid"] is True
    by_rule: dict[str, list[str]] = {}
    for w in result["warnings"]:
        by_rule.setdefault(w["rule_id"], []).append(w["message"])
    assert any("app 'ghost' does not exist" in m for m in by_rule["ghost-app"])
    assert any("model 'unrouted' has no route" in m for m in by_rule["no-route"])
    assert any("allows every app to use every model" in m for m in by_rule["everything"])
    assert any("never takes effect: deny rule 'block-all'" in m for m in by_rule["everything"])
    assert any("earlier deny rule 'block-all'" in m for m in by_rule["narrow-deny"])
    assert any("no routed model matches 'llama-*'" in m for m in by_rule["family"])
    # Without inventory information, only structural warnings remain.
    plain = policy.validate_policy(d)["warnings"]
    assert not any("does not exist" in w["message"] or "no route" in w["message"] for w in plain)


def test_an_allow_shadowed_by_a_later_deny_still_warns() -> None:
    d = doc(rule("chat"), rule("lockdown", "deny", principals=["*"], actions=["*"], models=["*"]))
    messages = [w["message"] for w in policy.validate_policy(d)["warnings"] if w["rule_id"] == "chat"]
    assert any("deny rule 'lockdown'" in m for m in messages)


def test_partial_deny_does_not_shadow() -> None:
    d = doc(rule("chat", models=["qwen-*"]), rule("one", "deny", models=["qwen-test"]))
    assert not [w for w in policy.validate_policy(d)["warnings"] if w["rule_id"] == "chat"]


# --- storage, versions, explain -------------------------------------------------------


def test_activation_creates_versions_and_rollback_is_a_new_version(conn) -> None:
    assert policy.get_active_policy(conn) is None and policy.policy_history(conn) == []
    first = doc(rule("chat"), description="v1")
    second = doc(rule("chat", models=["qwen-*"]), description="v2")
    v1 = policy.activate_policy(conn, first, comment="initial", **ACTOR)
    v2 = policy.activate_policy(conn, second, comment="widen", **ACTOR)
    assert (v1["version"], v2["version"]) == (1, 2) and v1["sha256"] != v2["sha256"]
    active = policy.get_active_policy(conn)
    assert active["version"] == 2 and active["document"] == second and active["comment"] == "widen"  # type: ignore[index]
    assert active["activated_by"] == "cli:pytest"  # type: ignore[index]

    rollback = policy.activate_policy(conn, policy.get_policy_version(conn, 1)["document"], comment="roll back", **ACTOR)
    assert rollback["version"] == 3 and rollback["sha256"] == v1["sha256"]
    history = policy.policy_history(conn)
    assert [h["version"] for h in history] == [3, 2, 1]
    assert [h["active"] for h in history] == [True, False, False]
    assert policy.get_policy_version(conn, 2)["active"] is False
    assert policy.load_active_compiled(conn).version == 3  # type: ignore[union-attr]

    events = list(reversed(audit.query_events(conn, action="policy.activate")))
    assert [e["details"]["previous_version"] for e in events] == [None, 1, 2]
    assert [e["policy_version"] for e in events] == [1, 2, 3]
    assert events[0]["details"]["sha256"] == v1["sha256"] and events[0]["details"]["comment"] == "initial"


def test_stored_document_is_canonical_json_with_matching_digest(conn) -> None:
    result = policy.activate_policy(conn, doc(rule("chat")), **ACTOR)
    row = conn.execute("SELECT document, sha256 FROM policies WHERE version = 1").fetchone()
    from ferry.util import canonical_json, sha256_hex
    assert row["document"] == canonical_json(doc(rule("chat"))).decode()
    assert row["sha256"] == sha256_hex(row["document"].encode()) == result["sha256"]


def test_invalid_document_is_not_activated(conn) -> None:
    with pytest.raises(ValidationFailed) as excinfo:
        policy.activate_policy(conn, doc(rule("Bad Id")), **ACTOR)
    assert excinfo.value.details["validation"]["valid"] is False
    assert policy.policy_history(conn) == [] and audit.head(conn)["seq"] == 0
    with pytest.raises(ValidationFailed):
        policy.activate_policy(conn, doc(rule("chat")), comment="x" * 1001, **ACTOR)
    assert policy.policy_history(conn) == []


def test_activation_warnings_use_the_database_inventory(conn) -> None:
    auth.create_principal(conn, "report", **ACTOR)
    result = policy.activate_policy(conn, doc(rule("chat"), rule("ghost", principals=["app:ghost"])), **ACTOR)
    messages = [w["message"] for w in result["warnings"]]
    assert "app 'ghost' does not exist" in messages
    assert "model 'qwen-test' has no route" in messages
    assert not any("app 'report'" in m for m in messages)


def test_get_policy_version_errors(conn) -> None:
    with pytest.raises(NotFound):
        policy.get_policy_version(conn, 1)
    with pytest.raises(NotFound):
        policy.get_policy_version(conn, "1")  # type: ignore[arg-type]


def test_tampered_stored_policy_refuses_to_compile(conn) -> None:
    policy.activate_policy(conn, doc(rule("chat")), **ACTOR)
    with write_tx(conn):
        conn.execute("UPDATE policies SET document = replace(document, 'app:report', 'app:mallory') WHERE version = 1")
    with pytest.raises(policy.PolicyIntegrityError):
        policy.load_active_compiled(conn)


def test_explain_reports_decision_principal_and_trace(conn) -> None:
    auth.create_principal(conn, "report", **ACTOR)
    policy.activate_policy(conn, doc(rule("chat", limits={"max_tokens": 64}),
                                     rule("block", "deny", principals=["*"], actions=["*"], models=["secret-*"])),
                           **ACTOR)
    out = policy.explain(conn, app="report", model="qwen-test")
    assert out["allowed"] is True and out["principal"] == "app:report" and out["principal_status"] == "active"
    assert out["decisive_rule"] == "chat" and out["limits"]["max_tokens"] == 64 and out["policy_version"] == 1
    assert [t["id"] for t in out["trace"]] == ["chat", "block"]
    denied = policy.explain(conn, app="report", model="secret-plans")
    assert denied["allowed"] is False and denied["decisive_rule"] == "block"


def test_explain_denies_disabled_and_unknown_apps(conn) -> None:
    principal = auth.create_principal(conn, "report", **ACTOR)
    policy.activate_policy(conn, doc(rule("open", principals=["*"], actions=["*"], models=["*"])), **ACTOR)
    auth.update_principal(conn, principal["id"], disabled=True, **ACTOR)
    disabled = policy.explain(conn, app="report", model="qwen-test")
    assert disabled["allowed"] is False and disabled["policy_allowed"] is True
    assert disabled["principal_status"] == "disabled" and "disabled" in disabled["reason"]
    unknown = policy.explain(conn, app="nobody", model="qwen-test")
    assert unknown["allowed"] is False and unknown["principal_status"] == "unknown"


@pytest.mark.parametrize("kwargs", [{"app": "Bad App", "model": "m"}, {"app": "a", "model": "m-*"},
                                    {"app": "a", "model": "m", "action": "embeddings"}])
def test_explain_validates_its_input(conn, kwargs) -> None:
    with pytest.raises(ValidationFailed):
        policy.explain(conn, **kwargs)
