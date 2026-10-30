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
| A header-less pickle stream hidden inside a safetensors header is not scanned (only the `\x80` protocol 2-5 polyglot check runs there) | Outside bundle-2's scope; needs its own review. Safetensors headers are validated as JSON, which such a stream would fail, but this has not been proven |
| `audit.query_events`, `get_event` and `export_jsonl` raise on a row whose `details` is not valid JSON (`verify_chain` reports it correctly) | Observation, not a finding; affects the console's audit list after tampering |
| `/api/policy/validate` warnings are uncapped (about 4x response amplification, reachable by auditors); `/api/bundles`, `/api/apps` and `/api/models` have no `limit` parameter | Noted by the web reviewer as not a defect in v1's single-admin setting |
| Linux isolation (`unshare --net`) and strace evidence paths | Never executed on a Linux host |
| React console source | Not reviewed |

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
