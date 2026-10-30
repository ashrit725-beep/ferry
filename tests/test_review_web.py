"""Adversarial review tests for the 'web' area (auth, policy, security, admin API).

Each test asserts the CORRECT behaviour, so it FAILS against the current code and
passes once the defect is fixed. See the review report for the write-up. The tests
added with the fix also pin its exact bounds and that it leaves auth ordering alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ferry import audit

from helpers_app import CSRF, app_env

# One past SQLite's signed 64-bit maximum (9223372036854775807). FastAPI parses a
# path parameter typed `int` as an unbounded Python int, so this reaches the data
# layer unchecked.
OVERSIZE = str(2**64)

# Admin-API endpoints whose id/seq/version path parameter is declared `int`.
GET_INT_ENDPOINTS = [
    "/api/audit/{}",
    "/api/policy/{}",
    "/api/verifications/{}",
]
MUTATING_INT_ENDPOINTS = [
    ("PATCH", "/api/apps/{}", {"description": "x"}),
    ("POST", "/api/apps/{}/keys", {}),
    ("PATCH", "/api/backends/{}", {"enabled": False}),
    ("DELETE", "/api/backends/{}", None),
    ("POST", "/api/backends/{}/check", None),
    ("PATCH", "/api/routes/{}", {"enabled": False}),
    ("DELETE", "/api/routes/{}", None),
]


@pytest.mark.parametrize("template", GET_INT_ENDPOINTS)
def test_oversized_integer_id_on_reads_is_a_clean_4xx_not_500(tmp_path: Path, template: str) -> None:
    """A huge id is just a non-existent resource: it must be a clean 404/422, not an
    unhandled OverflowError surfaced as a generic 500. Reachable by any console user
    (these reads are `any_role`, so an auditor can trigger it)."""
    with app_env(tmp_path / "data", login_as="auditor") as env:
        response = env.get(template.format(OVERSIZE))
        assert response.status_code in (404, 422), (template, response.status_code, response.text)
        assert response.json()["error"]["code"] != "internal_error", template


@pytest.mark.parametrize("method, template, body", MUTATING_INT_ENDPOINTS,
                         ids=[f"{m} {p}" for m, p, _ in MUTATING_INT_ENDPOINTS])
def test_oversized_integer_id_on_mutations_is_a_clean_4xx_not_500(tmp_path: Path, method: str, template: str,
                                                                  body: dict | None) -> None:
    """Same bug on the admin-only mutating endpoints: an out-of-range id must resolve
    to 404 (no such resource), not a 500 from a bind-time OverflowError."""
    with app_env(tmp_path / "data") as env:  # logged in as admin
        kwargs: dict = {"headers": CSRF}
        if body is not None:
            kwargs["json"] = body
        response = env.client.request(method, template.format(OVERSIZE), **kwargs)
        assert response.status_code in (404, 422), (method, template, response.status_code, response.text)
        assert response.json()["error"]["code"] != "internal_error", (method, template)


# The bound is exactly SQLite's INTEGER range: both extremes are still looked up (404
# when absent, as before the fix); one past either end is refused as invalid input.
BOUNDARY = [(2**63 - 1, 404), (2**63, 422), (-(2**63), 404), (-(2**63) - 1, 422)]


@pytest.mark.parametrize("value, status", BOUNDARY, ids=[str(v) for v, _ in BOUNDARY])
def test_integer_path_ids_are_bounded_exactly_to_the_sqlite_integer_range(tmp_path: Path, value: int,
                                                                          status: int) -> None:
    with app_env(tmp_path / "data", login_as="auditor") as env:
        for template in GET_INT_ENDPOINTS:
            response = env.get(template.format(value))
            assert response.status_code == status, (template, response.text)
            assert response.json()["error"]["code"] == ("not_found" if status == 404 else "validation_failed")


def test_oversized_ids_do_not_reorder_authentication_or_role_checks(tmp_path: Path) -> None:
    """The range check runs after the session and role checks, so a bad id never turns
    a 401 or 403 into a 422."""
    with app_env(tmp_path / "data", login_as="auditor") as env:
        assert env.patch(f"/api/routes/{OVERSIZE}", {"enabled": False}).status_code == 403
        env.logout_locally()
        assert env.get(f"/api/audit/{OVERSIZE}").status_code == 401
        assert env.delete(f"/api/backends/{OVERSIZE}").status_code == 401


@pytest.mark.parametrize("value", [2**64, 2**63, -(2**63) - 1], ids=["2^64", "2^63", "-2^63-1"])
def test_oversized_backend_id_in_a_route_body_is_a_clean_422_not_500(tmp_path: Path, value: int) -> None:
    """The same unbounded int reaches the backend lookup from the JSON body of
    POST /api/routes and PATCH /api/routes/{id}: it is invalid input and changes nothing."""
    with app_env(tmp_path / "data") as env:
        backend = env.post("/api/backends", {"name": "b1", "kind": "llamacpp", "base_url": "http://127.0.0.1:9"})
        assert backend.status_code == 201, backend.text
        route = env.post("/api/routes", {"model": "m1", "backend_id": backend.json()["id"], "require_verified": False})
        assert route.status_code == 201, route.text
        with env.conn() as conn:
            before = audit.head(conn)
        for response in (env.post("/api/routes", {"model": "m2", "backend_id": value, "require_verified": False}),
                         env.patch(f"/api/routes/{route.json()['id']}", {"backend_id": value})):
            assert response.status_code == 422, response.text
            assert response.json()["error"]["code"] == "validation_failed"
        with env.conn() as conn:
            assert audit.head(conn) == before
