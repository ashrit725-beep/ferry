# Known limitations (v0.1.0, 2026-10-28)

Read this before relying on Ferry for anything that matters. Each item says
what is missing, why it matters, and what would fix it. See also the residual
risks in [threat-model.md](threat-model.md).

## Where it has actually been run

- Developed and tested on one machine: macOS 26.5.1, Apple M3 Pro, Python 3.14,
  llama.cpp 0.7.0 (b11669), Homebrew OpenSSL 4.1. Code avoids syntax newer than
  Python 3.11, but 3.11 to 3.13 have not been executed.
- **Linux has not been tested at all.** No Linux host was available. The Linux
  isolation path is written but unproven (below).
- No GPU, no CUDA, no vLLM, no NIM, no containers were exercised. The only real
  inference runtime tested is llama.cpp on Apple Silicon with a 0.5B model.
- No customer has run any of it.

## Offline preflight and rehearsal (connected side)

| Limitation | Why it matters | Fix |
|---|---|---|
| Linux isolation has never been executed. Candidates are tried in order with a self-test (root `unshare --net`, unprivileged `unshare --net --map-root-user`, `bwrap --unshare-net`); hardened hosts often disable unprivileged user namespaces (RHEL STIG sets `user.max_user_namespaces = 0`, Ubuntu 24.04 restricts them through AppArmor), so on such hosts only the root or `bwrap` paths can work. When none works the preflight fails closed and names what was tried | Most prospects' build hosts are Linux | Run on RHEL 9 and Ubuntu 24.04 (the CI workflow does this on push); consider `docker run --network none` and systemd `PrivateNetwork=` as further candidates |
| macOS isolation uses `sandbox-exec`, which Apple marks deprecated | It could disappear in a future macOS | Keep it for demos and Mac-based packers; Linux is the customer platform |
| On macOS the kernel log redacts destination addresses; DNS lookups show up only as denied connections to the resolver socket, with no name | Non-Python processes are attributed to a process and port, not a host | Python processes are covered by the audit hook; for native code use Linux with `strace` |
| The Python audit hook only loads in Python processes that honour `PYTHONPATH` (not `python -I`, not processes with their own `sitecustomize`), and native extensions (C, Rust, e.g. `hf-xet`) bypass Python audit events | Some calls get only OS-level evidence | Document; consider `LD_PRELOAD`/DYLD interposition later |
| Child processes are tracked by process group, polled every 0.25 to 1 s. A process that detaches (`setsid`) or lives shorter than a poll is not attributed | A short-lived helper's denials may be missed on macOS | Use the sandbox's own process tree, or `strace -f` on Linux |
| A DNS lookup that cannot be attributed (a macOS resolver denial, or under Linux `strace` a query to a loopback stub resolver such as 127.0.0.53) is a warning, not a failure, unless `--strict` | Avoids failing on harmless local lookups such as Python's reverse lookup of 127.0.0.1 | Use `--strict` for release gates |
| Loopback connections (on macOS, to this host's own services) and Unix sockets stay allowed inside the sandbox, so traffic that a local service relays for the command is not seen: a proxy on 127.0.0.1 (cntlm, Px, mitmproxy, `ssh -D`), a local Ollama, the Docker daemon. Ferry removes `*_proxy` variables (any letter case) from the command's environment, sets `NO_PROXY=*`, and warns on macOS when one named a proxy on this host | A proxy set outside the environment (pip.conf, .npmrc, git config, the macOS system proxy settings used by native code) can still relay traffic unseen on macOS | Preflight on a host without local proxies or relaying daemons; on Linux the network namespace has its own loopback |
| Rehearsal fails on the runtime's blocked connection attempts and network-failure lines in its output, but only notes its blocked DNS lookups | A native runtime's lookup of a remote name looks the same as a harmless local one | Name-level DNS evidence, e.g. resolver interposition |
| Rehearsal only runs GGUF models with llama-server | Safetensors/vLLM stacks need `ferry preflight` with their own launch command | Runtime adapters for vLLM and containers |
| The sandbox is a test harness, not a containment boundary | Do not preflight untrusted code expecting it to be contained | Use a VM for untrusted code |
| `ferry preflight`'s outer runner timeout can be shorter than its own inner limits (for example `--ready-timeout 600` with `--request-url`). When the outer timeout fires, only the runner is killed, and the command it started can keep running in the sandbox. `ferry rehearse` was fixed for this on 2026-10-30; preflight was not (finding SF-11) | A timed-out preflight can leave the launched server running | Derive the outer budget from the inner limits, run the runner in its own session, and send SIGTERM and then SIGKILL to its process group, as `ferry rehearse` does now |

## Bundles

| Limitation | Why it matters | Fix |
|---|---|---|
| Signatures are Ed25519 over the manifest bytes. Independent verification needs OpenSSL 3.0 or newer (`pkeyutl -rawin`); macOS's built-in LibreSSL 3.3 cannot load Ed25519 keys and RHEL 8's OpenSSL 1.1.1 lacks `-rawin` | Some reviewers cannot check signatures with the tools they have | Add P-256 (ECDSA) signatures, verifiable with any OpenSSL or LibreSSL via `openssl dgst -sha256 -verify` |
| The bundle is a Ferry-specific tar layout, not OCI/ModelPack, Zarf or OpenSSF Model Signing | Teams standardized on those cannot consume it directly | Emit OCI/ModelPack and DSSE/in-toto attestations; verify upstream OMS signatures (e.g. NVIDIA NGC) at pack time |
| Signing keys are files with an optional passphrase; no HSM, smartcard or PKCS#11 | Key theft defeats the publisher check | PKCS#11 support |
| No delta updates: every version is a full transfer | Large models cost media and review time on each update | File-level deltas against a base manifest |
| Runtime binaries (llama.cpp, CUDA, wheels) are not carried in bundles; executables are rejected by policy | The operator installs the runtime through their own approved process | Signed runtime bundles with an explicit host opt-in |
| Rollback protection compares versions per bundle name on one host; it does not detect a rollback across hosts | Each receiving host keeps its own history | Signed, monotonic channel metadata |
| GGUF validation bounds header counts, lengths, dims, offsets and alignment, but does not compute exact tensor byte sizes per ggml type | A crafted file with in-bounds but wrong sizes reaches the runtime's own parser | Byte-exact accounting per ggml type (v1-additions A3) |
| Bundle versions must have a numeric core (`MAJOR.MINOR.PATCH`, optional leading `v`, `-pre-release`, `+build`) so rollback protection can order them. `ferry pack` refuses others, such as `latest` or `1.x`; a bundle built another way with such a version fails `policy.rollback` at verify and import, even with `--allow-downgrade` | Free-form version schemes cannot be used; a date works as `2026.10.30` | None planned |
| When two bundles ship the same bytes, the newest import that declares them as a model sets the shared store record (kind, model name, licence). The evidence report shows each bundle's own signed declaration, but the console bundle detail page and `ferry run <name>` read the shared record, so an older bundle's page shows the newer name and the older name stops resolving (finding VI-6) | An operator can see a licence on an older bundle's page that its signer did not declare | Read the per-bundle declaration from `bundles.manifest` in `/api/bundles/{id}` and the runtime name lookup |
| Malware scanning is out of scope | Ferry complements the transfer reviewer's scanner, it does not replace it | None planned |

## Receiving side (optional phase 2)

| Limitation | Why it matters | Fix |
|---|---|---|
| One host, one SQLite file, no high availability | A host failure stops serving until a restore | `ferry backup` / `ferry restore` exist (manifest-verified, online database snapshot); schedule them. HA later if demanded |
| No SSO, LDAP or MFA for console users; the login throttle is in memory | Weaker identity than enterprise consoles | SSO/OIDC when a design partner requires it |
| Provenance checks work only for llama.cpp (`/props` `model_path`); Ollama and generic OpenAI backends are always "unverified" | Routes to them must set `require_verified=false` | Adapter-specific provenance |
| Provenance is taken from the last health check (default every 30 s) | A backend restarted on a different file is served until the next check | Re-check on connection errors; shorter interval |
| Egress guard re-resolves names, but a DNS-rebinding window remains between check and connect | A hostile resolver could redirect a backend name | Use IP-literal backend URLs |
| Rate limiting is concurrency only; no per-app quotas | One app can use all capacity | Per-app quotas |
| A streamed completion is withheld unless its `gateway.chat.stream_opened` event commits. If the closing `gateway.chat.completions` write fails after delivery, the request has only the opening event (no usage, no final outcome) and an error log line, and the console traffic figures, which count only `gateway.chat.completions`, leave it out (finding GWS-4) | A database fault in the middle of a stream leaves an incomplete record | Reconcile opening events that have no closing event during audit verification |
| Policy validation caps the shadowed-rule analysis at 5,000,000 comparisons. When a very large policy (hundreds of rules with long principal and model lists) uses up that budget, the analysis is skipped with one warning; errors and the other warnings are still computed (finding GWS-3) | A rule that never takes effect may go unreported in such a policy | Use wildcards (`app:*`, `qwen2.5-*`) in place of long lists |
| The audit log is tamper-evident relative to checkpoints kept outside the database, not tamper-proof; no WORM storage | Someone with database write access and no external checkpoint can truncate or rebuild the chain | Export signed checkpoints regularly; WORM storage integration |
| No encryption at rest for the store or database | Host compromise exposes weights and metadata | Rely on full-disk encryption; envelope encryption later |

## Company and evidence

- No customer interviews, pilots, deployments or revenue exist yet. Every
  customer, pricing and market statement in `docs/company/` is a hypothesis.
- Ferry produces evidence that can support controls such as NIST SP 800-53
  SI-7(15), CM-14 and SR-4(3). It does not make any system compliant, and it
  has not been independently assessed or accredited for any classification level.
