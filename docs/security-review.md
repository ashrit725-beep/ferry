# Internal security review, 2026-10-28/29

**What this is:** an AI-assisted adversarial review of Ferry v0.1.0 run by the
founding engineer before any customer use. Four reviewers, one per area, were
told to attack the code and to prove every finding with a failing test (or an
exact reproduction they ran). Separate fixers then confirmed each finding,
fixed the code with the smallest change that did not weaken a check, and kept
the suite green. Nothing here is an independent third-party assessment, a
penetration test, or an accreditation artifact.

**Method limits:** the reviewers read the code and wrote tests on one macOS
machine. No Linux host, no fuzzing campaign beyond targeted cases, no review of
the React console source, no review of llama.cpp itself.

## Findings

Severity is the reviewer's. "Fixed" means the reviewer's failing test now
passes and the fix is covered by the regular suite.

| Id | Severity | Finding | Status | Test |
|---|---|---|---|---|
| bundle-1 | high | Version-reuse check compared raw version strings while rollback ordering used `version_key`, so `1.0.0+evil` or `1.0` after `1.0.0` slipped past `policy.version_reuse` | Fixed: reuse is now detected with `version_key` equality; one parameter of the reviewer's test (`1.0.007` vs `1.0.0`) was refuted as a legitimate upgrade and re-pointed at `1.0.7` | `tests/test_review_bundle.py` |
| bundle-2 | high | Pickle streams of protocol 0/1 (no `\x80` header) were classified as text or binary and passed the pickle policy | Fixed: a bounded `pickletools.genops` scan in `detect_format` classifies a stream that reaches `GLOBAL`/`INST`/`STACK_GLOBAL` as pickle, without building objects; three regression cases added | `tests/test_review_bundle.py`, `tests/test_formats.py` |
| web-1 | low | Integer path ids outside the 64-bit range raised an unhandled `OverflowError` (HTTP 500) on ten admin endpoints | Fixed: ids are bounded with a shared `RowId` path type (422 on overflow); the same root cause in body `backend_id` on route create/update was found by fuzzing and fixed | `tests/test_review_web.py` |
| GW-1 | medium | Egress guard accepted 6to4 (`2002::/16`) and Teredo (`2001::/32`) addresses that relay to public IPv4 hosts | Fixed: both ranges count as public and need `allow_public_backends` | `tests/test_review_gateway.py` |
| GW-2 | medium | A streamed request's audit write ran on the event loop and could block it while waiting for the database lock | Fixed: the write runs in the thread pool inside the shielded cancel scope | `tests/test_review_gateway.py` |
| GW-3 | low | `verify_chain` raised on some tampered rows instead of reporting them | Fixed: parse/hash errors are reported as a modified row with its seq | `tests/test_review_gateway.py` |
| GW-4 | low | A `details` rewrite that parsed to the same JSON value passed chain verification | Fixed: stored details must equal their canonical JSON form | `tests/test_review_gateway.py` |
| GW-5 | low | A stream chunk containing an escaped lone surrogate crashed the relay and was audited as a client disconnect | Fixed: relayed as-is with escaping; unexpected relay errors are audited as `internal_error` | `tests/test_review_gateway.py` |
| GW-6 | low | A request containing a lone surrogate returned 500 instead of a client error | Fixed: 400 at the validate stage, before authorization and routing; a deeply nested `tools` object (100 KB) that also produced a 500 was found and fixed the same way | `tests/test_review_gateway.py`, `tests/test_gateway_openai.py` |
| GW-7 | low | `ConcurrencyLimiter.acquire` leaked the backend slot when cancelled while queued for the global slot | Fixed: the backend slot is released before re-raising | `tests/test_review_gateway.py` |
| OFF-1 | high | On macOS a command could reach the internet through a loopback proxy taken from the environment (`HTTPS_PROXY` etc.) and still pass the preflight | Fixed: sandboxed commands get an environment without proxy variables and `NO_PROXY=*` | `tests/test_review_offline.py` |
| OFF-2 | medium | `--strict` could be fooled: numeric `127.0.0.1` lookups "explained away" native DNS lookups | Fixed: local-name budget no longer covers resolver-socket denials from native lookups | `tests/test_review_offline.py` |
| OFF-3 | medium | `ferry rehearse` ignored the global `--config` and `FERRY_CONFIG` | Fixed: the import policy is loaded from the same places as every other command | `tests/test_review_offline.py` |
| OFF-4 | medium | A rehearsal passed although the runtime attempted outbound connections | Fixed: the runner collects blocked attempts (macOS sandbox log, strace on Linux) and any attempt fails the rehearsal | `tests/test_review_offline.py` |
| OFF-5 | medium | Reports claimed "egress blocked" when no isolation was used (`--allow-no-isolation`) | Fixed: `egress_blocked` is `null` and the report says no isolation was used | `tests/test_review_offline.py` |
| OFF-6 | low | The Python hook treated any host name starting with `127.` (e.g. `127.0.0.1.nip.io`) as loopback | Fixed: only `localhost` and loopback/unspecified IP literals are local | `tests/test_review_offline.py` |
| OFF-7 | low | Linux strace evidence dropped DNS queries sent to a loopback stub resolver (`127.0.0.53`) | Fixed: queries to a loopback resolver are kept as DNS attempts | `tests/test_review_offline.py` |
| OFF-8 | low | An empty backend token file was accepted, so llama-server would run without authentication | Fixed: `read_token_file` and the runtime helper refuse an empty token | `tests/test_review_offline.py` |
| OFF-9 | low | Evidence files next to `--log` were written through symlinks planted there | Fixed: report files are opened with `O_NOFOLLOW` | `tests/test_review_offline.py` |
| OFF-10 | low | The runner left SIGTERM-ignoring members of the process group running | Fixed: SIGTERM to the group, then SIGKILL to what remains after the grace period | `tests/test_review_offline.py` |
| OFF-11 | low | `--request-url` without `--ready-url` was silently ignored and the preflight exited 0 | Fixed: usage error (exit 2) | `tests/test_review_offline.py` |

The offline-area fixer's own report was lost to an API usage limit after it
had made its changes; the integrator (the founding engineer) confirmed each
fix by reading the code and running the reviewer's tests, which pass.

## Checked and found sound

The reviewers listed 57 behaviours they attacked without finding a defect,
among them: signature verification before manifest parsing; archive member
hygiene (symlinks, hardlinks, devices, `..`, absolute and case-colliding
names); trust entries whose key id does not match their PEM; revoked, expired
and not-yet-valid keys; the two-signer rule with `distinct_signers`; staging
cleanup on every failure path; API-key comparison with `hmac.compare_digest`;
session expiry and cookie flags; CSRF and `Origin` checks; auditor role
enforcement on every admin-only endpoint; inbox name validation; CSP and
security headers on all responses; authorization before routing in the gateway;
body-size limit with and without `Content-Length`; `max_tokens` clamping;
model-name rewriting in streams; no prompt or completion text in the audit log.

## Open items

| Item | Why it is open |
|---|---|
| Linux isolation (`unshare --net`, `bwrap`) and strace evidence paths | Never executed on a Linux host |
| React console source | Not reviewed |

Resolved on 2026-10-29, after the review (tests in `tests/test_hardening.py`):

- The header-less pickle scan now also runs on files that parse as safetensors,
  so a stream laid out to skip into the JSON header is classified as pickle;
  well-formed files with header lengths whose bytes form pickle opcodes stay
  safetensors.
- `audit.query_events`, `get_event` and `export_jsonl` return a row whose
  `details` were tampered into invalid JSON with an `integrity:
  details_unparseable` marker instead of raising; `verify_chain` still reports
  the row.
- Policy validation returns at most 200 warnings plus a count of the rest;
  `/api/bundles`, `/api/apps` and `/api/models` take `limit` (default 1000,
  at most 5000).

## Final state

- Full suite on 2026-10-29: `1310 passed, 5 skipped, 1 warning` (the skips are
  the opt-in real-runtime tests; the warning is Starlette's own `httpx` notice).
- Opt-in real-runtime tests with llama.cpp 0.7.0 (b11669) and the Qwen2.5-0.5B
  GGUF: 4 passed.
- `demo/run-demo.sh` after all fixes: completed all 16 steps (hidden-call
  preflight FAIL as expected, llama-server preflight PASS, OpenSSL and
  `shasum` checks OK, tampered copy REJECTED, rehearsal PASS, import ACCEPTED,
  allowed request HTTP 200 with a real completion, two denials HTTP 403 before
  inference, audit chain intact).

## Quality pass, 2026-10-30

**What this is:** a second AI-assisted pass over the Python package and CLI,
run the same way as the review above. Five finders (verify/import, gateway
security, CLI usability, silent failures, performance) reported 44 findings;
two refuters per P0/P1 finding (one per P2) tried to disprove each by
reproducing it at f737b96. None was refuted, though most were downgraded.
Fixers then changed the code, one module group each, with a test for every
fix. As before, this is not an independent assessment.

The security-relevant defects (found as P0 or P1 in the verify/import and
gateway-security areas) are listed here. Severity is the refuters' rating;
the finder's rating is in brackets. The full list of 44, with each refuter's
reproduction, the fixes and the tests that cover them, is in
[reviews/quality-pass-2026-10-30.md](reviews/quality-pass-2026-10-30.md).

| Id | Severity | Finding | Status | Test |
|---|---|---|---|---|
| VI-1 | medium [P0] | A valid GGUF whose bytes also run, from byte 0, as a header-less protocol-0 pickle reaching `GLOBAL`/`INST`/`STACK_GLOBAL` was accepted as GGUF, because the header-less pickle scan never ran on files that parsed as GGUF | Fixed: `detect_format` runs the scan on a valid GGUF and classifies such a polyglot as pickle (`polyglot: gguf`), so the pickle policy rejects it | `tests/test_formats.py` |
| VI-2 | medium [P0] | `version_key` compared non-numeric parts as text, so a signed `v9.0.0` replayed after `v10.0.0` passed rollback protection, and `1.0.0` after `1.0.0rc1` was refused as older | Fixed: versions are parsed (optional `v`, numeric core, pre-release, build); a version whose core is not numeric (`latest`, `1.x`) fails `policy.rollback`, even with `--allow-downgrade` | `tests/test_bundle_rollback.py` |
| VI-3 (also SF-1) | medium [P1, P0] | Rollback and version-reuse checks ran outside the transaction that registers the bundle, so two concurrent imports of the same name could both register (two copies of one version, or an older one after a newer one) | Fixed: the history check runs again inside the `BEGIN IMMEDIATE` registration transaction; a conflict is recorded as a rejection, and files that call placed are removed unless another bundle uses them | `tests/test_bundle_rollback.py`, `tests/test_bundle_import.py` |
| VI-4 (also SF-3, integrity-1) | low [P1] | Re-import kept an existing store file of the right size without hashing it, so a corrupted or tampered store file stayed in place while the import reported success | Fixed: an existing file is kept only if it is a regular file, mode 0444 and hashes to its digest; otherwise it is replaced from the verified staged copy and listed as `repaired` in the result and the audit event | `tests/test_bundle_import.py` |
| VI-5 | medium [P1] | Listing the tar kept every PAX/GNU long header in memory (up to 8 MiB each across about 1,000 members) before any size limit applied; chained extended headers could raise an uncaught `RecursionError` | Fixed: 64 KiB per header and 16 MiB in total while listing, PAX records are dropped after use, and `RecursionError` becomes `archive.readable` | `tests/test_bundle_verify.py` |
| VI-6 | medium [P1] | `artifacts` rows were first-writer-wins by digest, so a later bundle shipping the same bytes had its signed kind, model name and licence replaced by the first bundle's in the store and the evidence report | Fixed: the newest import that declares the bytes as a model names them, and the evidence report reads each bundle's declaration from its own signed manifest. The console bundle detail page still reads the shared row (see limitations) | `tests/test_bundle_import.py` |
| GWS-1 | medium [P0] | The login throttle checked and counted in separate steps around a 65 to 75 ms scrypt check, so 20 concurrent guesses against one account all got a password check where the limit is 5 | Fixed: `LoginThrottle.begin`/`finish` count in-flight checks under the throttle lock; at most four scrypt checks run at once in the process | `tests/test_app_admin_api.py` |
| GWS-2 | low [P1] | `ferry serve` left uvicorn trusting `X-Forwarded-For`/`-Proto` from loopback, so any local client could set the `client_ip` used as the throttle key and in the audit log | Fixed: forwarded headers are ignored unless the peer is in the new `[server] trusted_proxies` (empty by default); `docs/deployment.md` explains the setting | `tests/test_cli.py` |
| GWS-3 | medium [P1] | Policy warning (shadowed-rule) analysis was quadratic and unbounded, so an auditor could hold a worker for minutes with one `POST /api/policy/validate` of under 1 MiB | Fixed: set-based coverage plus a budget of 5,000,000 comparisons; when it runs out, shadow analysis is skipped with one warning, and errors and other warnings are still computed | `tests/test_policy.py` |
| GWS-4 (also SF-4) | medium [P1] | A streamed completion was relayed even when its audit event could not be written; the non-stream path already failed closed | Fixed: a `gateway.chat.stream_opened` event is committed before the first byte, and a request whose event cannot be written gets the same 500 "response withheld" as a non-stream one | `tests/test_gateway_openai.py` |

Resolved after the pass, the same day: `ferry pack` refuses a version that
rollback protection cannot order, before any hashing, so the publisher finds
out on the connected side instead of at import inside the enclave. The
ordering rule moved to `ferry/manifest.py` (tests in `tests/test_bundle_pack.py`).
The spec now matches the code: `docs/design/v1-spec.md` gives the 63-byte
tensor-name limit, the contiguous tensor layout and `gateway.chat.stream_opened`,
and `docs/design/v1-additions.md` A1 gives the new version order.

Full suite after the pass, on 2026-10-30: 1471 passed, 6 skipped, 1 failed.
The failure (`tests/test_preflight.py::test_leaky_app_fails_with_attribution_and_fix`)
and the sixth skip both depend on the macOS kernel sandbox log, which recorded
no denials during that run. The same test fails on an unmodified export of
f737b96 in the same session, so the pass did not cause it.
