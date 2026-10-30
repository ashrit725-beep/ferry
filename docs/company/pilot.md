# Pilot 1: offline readiness for one real delivery

*Owner: founder. Written 2026-10-28. Status: offered to no one; 0 pilots, 0 customers, 0 revenue. Follows [02-decision-revision](../strategy/02-decision-revision.md) (overrides 01) and [customer-discovery](customer-discovery.md), whose concierge preflight (§8) comes first. Prices are in [pricing](pricing.md). Labels: VERIFIED (source or local check named), INFERRED, UNKNOWN. Every threshold below is a hypothesis.*

## 1. What the pilot is

The smallest test a qualified prospect can run without a procurement cycle. On its own connected-side host, with its own full-size weights, the prospect takes its **next real delivery** and:

1. runs `ferry preflight -- <launch command>` on up to 3 exact launch commands with egress denied;
2. turns the findings into a fix list and re-runs until the preflight passes or each remaining attempt is accepted in writing;
3. packs and signs the model files as a bundle;
4. gives its transfer reviewer a review sheet plus the preflight reports;
5. has the reviewer verify the bundle with stock tools (`sha256sum` or `shasum`, `tar`, OpenSSL 3+), without installing Ferry.

Phase 1 is connected side only and runs 10 business days. Phase 2 (receiving side) happens only if the enclave owner asks (§11). Nothing leaves the prospect's machines (§9). Fee: fixed per shipment (pricing.md §4.1).

| Component used | Status on 2026-10-28 |
|---|---|
| `ferry preflight` on macOS: `sandbox-exec` profile, in-sandbox egress probe, kernel sandbox log (process, PID, port), Python audit-hook attribution, output scan, rule base of documented offline fixes | VERIFIED on the build Mac (macOS, Apple Silicon): automated tests, plus a real llama.cpp `llama-server` serving Qwen2.5-0.5B-Instruct inside the sandbox |
| `ferry preflight` on Linux: network namespace via `unshare --net --map-root-user` | **Implemented, never run on Linux.** No Linux host was available. It must be validated in session 1 (§4.1) before any Linux result counts |
| Ed25519 signature over the exact manifest bytes, checked with `openssl pkeyutl -verify -rawin` | VERIFIED (with OpenSSL 3+; see §7 for hosts where it fails) |
| `ferry pack/sign/verify/import` with model-aware checks; `ferry rehearse` | v1 scope, being built and tested now. The pilot is their first outside use, not a proven feature |
| P-256, DSSE/in-toto, OMS, cosign/OCI outputs; Kubernetes; vLLM, NIM or container-specific handling | Not built. vLLM, NIM and containers are covered only by wrapping their launch command |

## 2. Who qualifies

All of:
- Passes the vendor-side screen ([customer-discovery §2](customer-discovery.md)) and has run the concierge preflight (§8 there) or another demo on its own stack.
- Has a real delivery (new install or update) to a customer-operated disconnected (D) or restricted (R) site, to be prepared within 60 days. One shipped in the last 30 days also qualifies if its artifacts can be replayed.
- Can run the exact launch command on a macOS or Linux host it controls, outside Kubernetes. Kubernetes-only delivery paths are out of scope (customer-discovery K5).
- Names three roles: a deployment engineer who runs everything; a transfer reviewer (vendor-side or customer-side) with about 1 hour; and a budget owner who can approve the fee without procurement.

Defer (do not start) if:
- The reviewer or target requires FIPS-mode verification, P-256 signatures or OCI/cosign artifacts (the preconditions in customer-discovery §7). Pilot 1 cannot satisfy that reviewer today.
- The only available host is inside an enclave or holds CUI or classified data. Never run there.

## 3. Baseline, measured before the first Ferry run

Collected in a 45-minute call plus records the prospect pulls itself (tickets, transfer requests, calendars). Mark each number "record" or "recollection"; ranges are fine. Record site type and month only, never site, customer, program or system names (OPSEC rules, customer-discovery §3).

| ID | Metric | How measured |
|---|---|---|
| B1 | How offline readiness is tested today | none / `docker run --network none` / Replicated CMX `airgap` / netns or firewall script / staging enclave / checklist / other. Last run date; which commands and code paths it exercises |
| B2 | Last 3 deliveries | Per delivery: month, D/R, stack (runtime, accelerator, containers); transfer cycles until it ran inside; calendar days from first media hand-off to running; days attributed to misses; what was missing or calling out (component codes, customer-discovery §5); who found it, and where |
| B3 | Time to prepare a delivery | Engineer-hours (all people) and calendar days from release candidate frozen to media handed to the reviewer, for the latest delivery |
| B4 | What the reviewer gets and does | File list, hashes, signatures, scan results; tools used to check on arrival; reviewer minutes per delivery |
| B5 | Deliveries per year | Last 12 months and planned next 12, per team. Feeds pricing, not pilot success |
| B6 | Control run | On the pilot host, the B1 method (if any) run on the same launch commands before any preflight. S1 credits Ferry only with what this run missed |

## 4. Phase 1 scope (connected side, 10 business days)

### 4.1 Session 1: install and isolation check (Day 1, about 2 hours)

- Install Ferry into a virtualenv from a wheelhouse (Ferry, its five direct runtime dependencies and their transitive dependencies) with a SHA-256 list. The source is readable for the prospect's own review.
- Preflight a trivial command. The report must name the isolation mechanism, show both probes blocked (TCP connect and DNS lookup) and show loopback working (a readiness URL checked from inside the sandbox).
- **Linux: first real test of this code path.** Check before running:

| Check | Why |
|---|---|
| `unshare` (util-linux) and `ip` (iproute2) present | The Linux sandbox is `unshare --net --map-root-user`, then `ip link set lo up` (ferry/sandbox.py) |
| `sysctl user.max_user_namespaces` is not 0 | The RHEL 8 STIG requires 0, unless use is "operationally required and documented with the ISSM" (VERIFIED [S1]). INFERRED: Ferry's Linux sandbox cannot start on such a host |
| `cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns` | Ubuntu 24.04 denies capabilities inside unprivileged user namespaces by default (VERIFIED [S2]). INFERRED: `ip link set lo up` then fails, and the preflight fails closed |
| `strace` present | Without it, attempts by non-Python processes on Linux show up only through output scanning; the Python hook still records Python calls (ferry/preflight.py; untested on Linux) |
| `ferry preflight -- nvidia-smi` lists the GPUs | A network namespace should not hide devices (INFERRED, untested) |
| Multi-GPU runtimes start | Runtimes that coordinate over TCP see only loopback; some may need loopback-specific settings (INFERRED, untested) |

- If isolation does not validate, the preflight fails rather than running unisolated, so it produces no misleading pass. A test covers a host with no isolation tool (VERIFIED). The `--allow-no-isolation` flag overrides this for diagnostics only; such runs never count toward the pilot (metrics.md §4). By the code, a failing `unshare` also fails the run (INFERRED; untested on Linux). Options, each the host owner's decision: another Linux host or VM they control that permits user namespaces; their own documented exception (ISSM approval, an AppArmor profile, or Ubuntu's documented temporary switch, which reboot resets [S2]); or a Ferry change to use a root-created namespace with no user namespace (not built). The pilot never asks anyone to weaken a host control for the product's sake. If nothing works within 5 business days, exit E1 (§12).
- **Containers.** A `docker run` started inside the sandbox is created by the Docker daemon, outside Ferry's namespace (INFERRED; confirm in session 1). Run containers with `--network none`, which leaves only loopback (VERIFIED [S3]), and expect output scanning only: neither the Python hook nor strace sees inside the container.

### 4.2 Preflight the real launch commands (Days 1-4)

- Up to 3 commands from the delivery (for example the model server, the application, an embedding or reranker service), exactly as they will run inside: same flags, environment, working directory and local paths.
- For each, a readiness URL and one smoke request that exercises first use (a chat completion, an embedding call, a retrieval query). Preflight observes only code paths that run.
- The smoke request records status, latency and token counts. The report never holds prompt or completion text: the code stores neither, and a test checks the completion (ferry/preflight.py, tests/test_preflight.py).

### 4.3 Fix list (Days 2-5)

One row per finding: evidence (process, PID, port; host and calling module for Python), library, documented fix from the rule base or "new", owner, status, re-run result. Re-run until the preflight passes, or until the engineer accepts a remaining attempt in writing with a reason (accepted attempts are reported as warnings). Make the final run with `--strict`: by default a blocked DNS lookup that the Python hook cannot attribute is only a warning (ferry/preflight.py), so a default pass can hide a DNS-only attempt by a non-Python process. New patterns become rule-base entries, described generically.

### 4.4 Pack and sign (Days 6-7, v1 scope)

- `ferry pack` on a TOML spec: weights (GGUF, safetensors), tokenizer, config and document files, with per-file SHA-256, size and content-detected format. Pickle, executables and nested archives are refused by default.
- Wheels, container images and runtime binaries are archives or executables, so v1 does not pack them. They travel through the prospect's existing process, and the fix list says so.
- The default import policy caps files at 100 GiB and bundles at 200 GiB (configurable; ferry/config.py).
- Optional countersignature by a second person (`ferry sign`) for a two-person release.
- GGUF + llama.cpp only: `ferry rehearse` imports the bundle into a throwaway directory and serves one prompt from the imported file with egress denied.

### 4.5 Reviewer packet and stock verification (Days 8-9, at most 1 hour of reviewer time)

Packet: `<bundle>.review.md` (bundle id, tar digest, signer key ids, artifact table, format flags, verification steps; per docs/design/v1-spec.md §4), the `.sha256` sidecar, the preflight reports and, if run, the rehearsal report. The publisher's key fingerprint goes by a separate channel.

On the reviewer's own machine, without Ferry:

```sh
sha256sum -c NAME-VERSION.ferry.tar.sha256          # or: shasum -a 256 -c
mkdir check && tar -xf NAME-VERSION.ferry.tar -C check
openssl pkeyutl -verify -rawin -pubin -inkey publisher.pub.pem \
  -in check/manifest.json -sigfile check/signatures/KEY_ID.sig
openssl pkey -pubin -in publisher.pub.pem -outform DER | tail -c 32 | sha256sum   # prints KEY_ID
# then compare sha256sum of each file under check/artifacts/ with manifest.json
```

The key-id line reproduces Ferry's key id (VERIFIED locally 2026-10-28). The reviewer repeats the procedure on a copy with one byte changed; it must fail (S6).

### 4.6 Readout (Day 10, 45 minutes)

Baseline against pilot numbers, criteria pass or fail, open product gaps, next step. Written for the prospect; the founder keeps only the coded results the prospect approves.

## 5. Schedule

| When | What | Prospect time | Founder time |
|---|---|---|---|
| Days -5 to 0 | Qualification, baseline B1-B5, host checklist, one-page order form, fee approval | 1.5 h | 3 h |
| Day 1 | Session 1: install, isolation check, control run B6, first preflight | 2 h | 3 h |
| Days 2-4 | Remaining commands, fixes, re-runs (async; founder triages within 1 business day) | 2-4 h | 4-6 h |
| Day 5 | Session 2: fix list review, re-run to pass | 1 h | 1.5 h |
| Days 6-7 | Pack, sign, countersign; rehearse if GGUF | 1-2 h | 2-3 h |
| Days 8-9 | Reviewer verification session | reviewer 1 h | 1 h |
| Day 10 | Readout | 45 min (+ budget owner) | 3 h incl. write-up |
| +30, +60, +90 days | Outcome of the real delivery (§13) | 15 min each | 0.5 h each |

All times are estimates (INFERRED) and are themselves pilot measurements. Paperwork: a one-page order form (scope, fee, data handling, no warranty, the E1 term) plus an evaluation licence for the Ferry build. Ferry's licence terms are undecided, and counsel has not reviewed the template (UNKNOWN). No data is exchanged, so a data processing agreement should not be needed (INFERRED; the prospect's policy decides).

## 6. Success criteria (agreed in writing before Day 1)

| ID | Criterion | Measure | Pass |
|---|---|---|---|
| S1 | Finds what the current process missed, or confirms readiness | Items preflight found that the B6 control run did not, confirmed real by the prospect's engineer (each dismissal needs a written reason); or a `--strict` pass on every in-scope command that the reviewer accepts as part of the transfer request | At least 1 confirmed item, or written acceptance by the reviewer |
| S2 | Attribution | Share of distinct attempts tied to a process or library, and share with a documented fix | Reported; hypothesis: 80%+ attributed in Python stacks |
| S3 | Noise | Findings the engineer judges irrelevant after review | Reported; hypothesis: at most 2 per command |
| S4 | Time to produce the delivery | Engineer-hours and calendar days, release candidate to reviewer, against B3. First-use overhead (install, learning) shown separately | Not worse than B3 net of first-use overhead. Reported but not scored if B3 is recollection only |
| S5 | Stock verification | Reviewer checks tar digest, signature, key id and every file digest on their own machine without Ferry; minutes taken | Pass; hypothesis: 30 minutes or less |
| S6 | Tamper detection | A one-byte change to a copy fails the S5 procedure | Pass |
| S7 | Platform | Isolation validated on the prospect's OS (§4.1) | Required before S1-S4 count |

**The pilot passes** when S7, S1 and S5 pass and S4 holds. S2, S3 and S6 are reported either way. Post-transfer outcomes are tracked afterwards (§13), not used to pass the pilot, because one media cycle can outlast the pilot (vendors claim updates every one to three months; research/06 §5).

## 7. Setup requirements

- **Host:** the prospect's connected-side build or staging host: macOS (verified on one Apple Silicon Mac) or Linux (untested). Never an enclave host or a system holding CUI or classified data.
- **Software:** Python 3.11+ (pyproject.toml). The prospect's runtime and model installed and working as they would ship them (llama.cpp, vLLM, SGLang, Ollama, a Python application or `docker run`).
- **macOS:** `sandbox-exec` (ships with macOS; Apple marks it deprecated) and a readable unified log (`log show`). If the log cannot be read, the report says the absence of denials is not conclusive (ferry/preflight.py). Whether managed Macs restrict `log show` is UNKNOWN.
- **Linux:** `unshare`, `ip`, preferably `strace`, and user namespaces available (§4.1).
- **Disk:** about 2-3x the weights: the originals, the bundle tar and the rehearsal's import copy (INFERRED from the design).
- **Reviewer machine:** `sha256sum` or `shasum`, `tar`, and OpenSSL 3.0 or later.
  - macOS's bundled `/usr/bin/openssl` is LibreSSL 3.3.6. It rejects `-rawin` and cannot load the Ed25519 key (VERIFIED locally 2026-10-28; Homebrew OpenSSL 4.1.0 verifies the same signature).
  - OpenSSL 1.1.1's `pkeyutl` does not support Ed25519 (VERIFIED [S4]). RHEL 8 ships the 1.1.1 series (INFERRED; check `openssl version`).
  - FIPS mode: CIQ's RHEL 9-compatible hardened distribution disables Ed25519 for SSH in FIPS mode through system crypto policy (VERIFIED [S5]). Whether `openssl pkeyutl` refuses it there is UNKNOWN. Test in session 1; if it fails, defer per §2 until P-256 exists.
- **Access:** none for the founder. Sessions run over the prospect's screen share, on its terms, or the prospect follows the runbook alone. No accounts, no SaaS, no inbound connections.

## 8. Responsibilities

**Prospect:** provides the host and runs every command; supplies the baseline; makes the fixes and decides which findings matter; provides reviewer and budget-owner time; owns any decision about host security settings; reviews reports before sharing anything; approves the readout.

**Founder:** supplies the wheelhouse, runbook and order form; joins sessions; triages findings within 1 business day; adds rules for new patterns; fixes Ferry defects found in the pilot, or says plainly that they cannot be fixed in time; writes the readout; follows the OPSEC rules (customer-discovery §3).

## 9. Data handling

- Everything runs on the prospect's machines and nothing leaves them. Ferry has no telemetry, update checks, licence checks or remote support channel (docs/network-dependencies.md).
- In phase 1, Ferry's only outbound attempts are its in-sandbox probes: one TCP connect to 192.0.2.1:443 (RFC 5737 TEST-NET-1, never routed) and one DNS lookup of example.com, both expected to fail. If isolation were broken, that lookup could reach the host's resolver (INFERRED).
- Reports stay with the prospect and can be sensitive. They hold the full command line and working directory, process names and PIDs, destination hosts or IPs and ports, the calling module with source path and line, and up to 25 output lines that look like network failures. They hold no prompts or completions. The command's full output log stays on the host (its path is in the report) and contains whatever the stack prints.
- The founder receives only the baseline worksheet, the criteria results and, with permission, generic descriptions of new patterns. Never weights, logs, prompts, completions, keys, or customer or site names.
- Signing keys are generated and kept on the prospect's host. The founder never sees private keys.
- Cleanup: delete the virtualenv, the work and bundle directories, and the `ferry-preflight-*` temporary directories.

## 10. What the pilot cannot show

- **That the delivery runs inside the target enclave.** Hardware, drivers, OS hardening, FIPS mode and firewall behaviour differ there. A pass means this command, on this host, with egress denied, made no attempt that preflight could see.
- **Untested code paths.** Features first used after the smoke request can still download or call out.
- **Some attempts, by construction:** processes that leave the command's process group (daemons calling `setsid`); calls from native code, which the Python hook cannot see; destination addresses on macOS, which the OS redacts (ports remain), and the names in non-Python DNS lookups there; on macOS, child processes that start and exit between the preflight's process-list polls (every 0.25-1 s), whose denials are not attributed to the command (INFERRED from ferry/preflight.py); anything beyond output scanning for non-Python processes on Linux without strace, and for anything inside containers (§4.1).
- **Acceptance by the enclave's reviewer, DTA or ISSM,** unless one of them takes part.
- **Compliance.** The artifacts produce evidence that can support SI-7(15), CM-14 and SR-4(3) reviews (research/04 §6). They satisfy no control by themselves.
- Malware or content scanning, model behaviour, performance or throughput.
- **Fewer failed transfer cycles over time.** One delivery is one data point (§13 tracks it).
- **Linux isolation,** until session 1 validates it.
- **Willingness to pay** beyond the pilot fee.

## 11. Phase 2 (optional): receiving side

Start only if the enclave owner (ISSM, platform or HPC lead) asks for import, provenance-gated serving, audit and evidence, and has admitted Ferry as a new executable through its own process. Admission may take months (see the phase-2 parking rule in customer-discovery §7) and belongs to the enclave owner.

- **Scope (v1, in progress, not proven):** fail-closed import into a content-addressed store; OpenAI-compatible gateway with API keys and a default-deny model policy; a check that `llama-server` serves the exact imported file (llama.cpp only; other OpenAI-compatible servers can be routed but not checked); hash-chained audit log; evidence report; web console.
- **Where:** a test or staging system the enclave owner chooses first. The founder has no remote access; support works from sanitized descriptions.
- **Success (hypotheses):** a tampered bundle and a pickle renamed `.gguf` are rejected; the good bundle is imported and served; an unapproved model is denied before inference; a provenance mismatch blocks routing; a modified audit event is detected; the ISSM judges the evidence report usable for their own documentation, in their words.
- **Schedule and price:** 2-3 weeks after admission (INFERRED); priced per enclave, separately (pricing.md §4.3).

## 12. Exit criteria

| ID | Condition | Result |
|---|---|---|
| E1 | Isolation cannot be validated on any host the prospect controls within 5 business days | Stop; log the product gap; no fee charged (proposed term) |
| E2 | The launch path cannot run outside Kubernetes or a provider cloud | Stop: out of scope (customer-discovery K5) |
| E3 | Reviewer or target requires FIPS-mode verification, P-256 or OCI/cosign | Stop or defer (customer-discovery §7 preconditions) |
| E4 | No real launch command or no engineer time by Day 3 | Pause once, for up to 10 business days; then stop |
| Done | Day 10 readout held | Pass or fail per §6, written down either way |

One extension of up to 5 business days is allowed for Ferry defects or host access, by mutual agreement.

## 13. After a successful pilot

1. Readout to the engineer and budget owner, with baseline against pilot numbers.
2. Offer the next shipments at the same fixed fee, or an annual subscription per delivering team with the pilot fee credited if signed within 90 days (pricing.md §4). No discount in exchange for a reference.
3. Track the real delivery at +30, +60 and +90 days: transfer cycles and calendar days to running inside, against B2. This is the number that matters, and the pilot itself cannot produce it.
4. With permission: generic rule-base additions; coded results into the customer-discovery tallies (K3, K4, K7 and the §7 preconditions); a reference only with written consent.
5. Phase 2 introduction only if the enclave owner asks.
6. If the pilot fails, record whether the cause was a product gap or absent pain, and apply customer-discovery §7.

## Sources (accessed 2026-10-28)

- S1 https://www.stigviewer.com/stigs/red_hat_enterprise_linux_8/2026-02-05/finding/V-230548 (mirror of the DISA RHEL 8 STIG, V-230548)
- S2 https://documentation.ubuntu.com/release-notes/24.04/ (unprivileged user namespace restrictions)
- S3 https://docs.docker.com/engine/network/drivers/none/
- S4 https://docs.openssl.org/1.1.1/man1/pkeyutl/ and https://docs.openssl.org/3.0/man1/openssl-pkeyutl/
- S5 https://docs.ciq.com/rlc-h/9/troubleshooting
- Local checks on the build Mac, 2026-10-28: LibreSSL 3.3.6 and OpenSSL 4.1.0 against an Ed25519 signature; the stock-tool key id matched `ferry.crypto.key_id`.
- Repository: ferry/sandbox.py, ferry/preflight.py, ferry/config.py, tests/test_preflight.py, docs/design/v1-spec.md, docs/design/v1-additions.md, docs/network-dependencies.md.
