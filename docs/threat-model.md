# Ferry threat model (v1)

Scope: Ferry v1 as specified in [design/v1-spec.md](design/v1-spec.md), i.e. the
bundle tools (`pack`, `sign`, `verify`, `import`), the receiving-side store and
registry, the OpenAI-compatible gateway, the admin console and the audit log.
This document is a design artifact written before implementation and revised
after review. It is not an accreditation artifact and does not claim compliance
with any framework.

## System and trust boundaries

```
 CONNECTED SIDE                     |  APPROVED TRANSFER  |  DISCONNECTED SIDE
                                    |  (customer process: |
 upstream model files               |   media, diode,     |  receiving host
   (Hugging Face, vendor, internal) |   reviewer, AV)     |  ┌────────────────────────────┐
        │                           |                     |  │ inbox dir (untrusted)       │
        ▼                           |                     |  │      │ ferry verify/import  │
 ferry pack  ── publisher key ──►  *.ferry.tar ─────────────►│      ▼                      │
 ferry sign  ── reviewer key  ──►  (+ review sheet)       |  │ trust dir (host-only)       │
                                    |                     |  │ store/sha256/<digest> (RO)  │
                                    |                     |  │ ferry.db (registry, policy, │
                                    |                     |  │   keys, audit chain)        │
                                    |                     |  │ gateway :8750 ──► backend   │
                                    |                     |  │   (llama-server, loopback,  │
                                    |                     |  │    per-backend token)       │
                                    |                     |  └───▲──────────────▲──────────┘
                                    |                     |      │ API key      │ session
                                    |                     |   applications   console users
```

| Boundary | Crosses it | Trust assumption |
|---|---|---|
| TB1 bundle | Bytes from the connected side | Untrusted until every check passes. Signatures establish who approved it, not that it is safe. |
| TB2 network clients | Apps (API keys), console users (sessions) | Authenticated per request; authorized server-side. |
| TB3 gateway to backend | Inference requests | The backend is trusted to run the model it was started with. Its `/props` report is used to catch misconfiguration, not to defend against a compromised backend. |
| TB4 host shell | Ferry user / root | Fully trusted. Can change config, trust anchors, the database. |
| TB5 console roles | `admin`, `auditor` | Admins manage apps, keys, policy, backends, routes, imports. They cannot add trust anchors or weaken import/egress settings; those are host-only. Auditors are read-only. |

## Assets

1. Integrity of model weights and configuration that end up being served.
2. Trust anchors (public keys and their roles) on the receiving host.
3. Signing private keys (connected side; never needed on the disconnected side).
4. Application API keys, admin passwords, session tokens, backend tokens.
5. Prompts and completions (customer data; Ferry does not store them).
6. Integrity of the audit log and of policy history.
7. Availability of inference for authorized applications.

## Threats and controls

| # | Threat | v1 control | Residual risk |
|---|---|---|---|
| 1 | Artifact modified in transit or at rest in the inbox | Per-file SHA-256 inside a signed manifest; size and digest checked while streaming; bytes stored are the bytes hashed (single pass) | None known for detected modification; detection only, not prevention |
| 2 | Bundle from an unknown or impersonated publisher | Ed25519 signatures checked against a host-only trust store; key ids are SHA-256 of the raw key; out-of-band fingerprint check on `trust add` | Operator must confirm fingerprints out of band; a careless `trust add` defeats it |
| 3 | Compromised or rogue signing key | Roles (`publisher`, `reviewer`), required-role policy with distinct signers (two-person rule), key expiry, revocation | Two colluding or compromised keys can approve malicious content. Signing keys are files in v1 (no HSM/smartcard yet) |
| 4 | Malicious model file executes code on load (pickle) | Pickle and torch zip formats rejected by default by content, not file name; executables and nested archives rejected; Ferry never loads, imports or unpickles bundle content | Allowing pickle is possible by explicit double opt-in on the host |
| 5 | Crafted GGUF/safetensors targets parser bugs in the inference runtime | Bounded structural validation of headers (counts, lengths, dims, offsets, alignment) before import | A structurally valid but hostile file can still hit unknown runtime bugs; keep llama.cpp patched |
| 6 | Archive tricks: path traversal, symlinks, hardlinks, devices, duplicate or case-colliding names, sparse files | Rejected; member names are never used as filesystem paths; content-addressed store | None known |
| 7 | Smuggling extra files | Exact inventory: unlisted members rejected | None known |
| 8 | Replay or downgrade to an older signed bundle | Every import records bundle name, version and id | No anti-rollback in v1 (roadmap: monotonic versions per bundle name) |
| 9 | Stolen application API key | Keys bound to one principal; default-deny policy limits which models it reaches; expiry and revocation; every request audited with key id | Usable until revoked; no mTLS or source binding in v1 |
| 10 | Unauthorized console access | scrypt passwords, HttpOnly SameSite=Strict session cookies with idle and absolute timeouts, CSRF header plus Origin check, login throttling, read-only auditor role | No MFA/SSO in v1. Without TLS, sessions on a non-loopback interface are exposed |
| 11 | Privilege escalation (app to another model, auditor to admin, app to admin API) | Server-side role checks on every endpoint; policy decided before routing; tests for each path | Bugs; see review findings |
| 12 | Policy mistakes | Default deny, deny overrides allow, validation before activation, warnings for risky rules, explain tool, versioned history with rollback | Admins can still activate an overly broad valid policy |
| 13 | Prompt or output leakage through logs | No prompt/completion storage; audit details sanitized and size-bounded; no request bodies in logs | Backends may log prompts at verbose log levels; OS swap and core dumps |
| 14 | Bypassing the gateway by calling the backend directly | Backend bound to loopback with its own token (llama-server `--api-key-file`), token file 0600 | Local users with access to the token file; Ollama has no native auth |
| 15 | Resource exhaustion | Body size limit, message count limits, `max_tokens` ceiling, global and per-backend concurrency with queue timeout, upstream timeouts, bundle size limits | No per-app quotas or rate limits in v1 |
| 16 | SSRF or data exfiltration through backend configuration | Backends must resolve to loopback/private addresses (link-local blocked), re-checked per request; no redirects; proxy environment variables ignored | DNS-rebinding window between check and connect |
| 17 | Hidden network dependencies (telemetry, CDN assets, update or licence checks) | None in Ferry; console assets bundled; offline tests; `ferry doctor` and a network inventory | Third-party runtimes are the operator's responsibility (documented) |
| 18 | Compromised dependency | Five direct runtime dependencies, versions recorded in evidence; offline install from a reviewed wheelhouse | No reproducible build or signed wheelhouse in v1 |
| 19 | Audit log tampering | SHA-256 hash chain; verification finds the first modified, inserted or deleted event; checkpoints (optionally signed) kept outside the DB catch tail truncation and rebuilds | An attacker with DB write access and no external checkpoint can truncate or rebuild the chain. Not WORM storage |
| 20 | Unauthorized update of Ferry itself | Out of scope for v1 tooling; documented manual verified install | Roadmap: ship Ferry upgrades as Ferry bundles |
| 21 | Clock manipulation on the receiving host | Key validity uses host time | Air-gapped clocks drift; expiry is only as good as the host clock |

## Insecure defaults avoided

Binds to 127.0.0.1; CORS off; console and API same-origin; pickle and
executables refused; public backends refused; trust anchors and import policy
are host-only; no default admin account (created on the host by CLI); API keys
shown once and stored only as hashes.

## Explicitly out of scope

Physical security and media handling; malware scanning (Ferry complements, not
replaces, the transfer reviewer's AV/content inspection); classified-system
accreditation; model behaviour and safety (jailbreaks, harmful output, poisoned
training data); confidentiality of weights at rest (no encryption at rest in v1);
high availability.
