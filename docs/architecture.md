# Architecture

Ferry has two halves that never talk to each other over a network: tools that
run where the model is obtained (the connected side) and a receiving
installation inside the disconnected network. The only thing that crosses is a
bundle file, through whatever transfer process the customer already approves.

```
CONNECTED SIDE                                   DISCONNECTED SIDE (one host)
──────────────                                   ─────────────────────────────────────────────
model files ─► ferry pack ─► bundle.ferry.tar ══►  inbox ─► ferry import ─► store/sha256/<digest>
              (publisher key)   + review sheet  ║          (trust dir,        │ (read-only, content-addressed)
             ferry sign         + .sha256        ║           import policy)    ▼
              (reviewer key)                    ║                     ferry runtime llamacpp
             ferry rehearse ── llama-server     ║                      └─► llama-server -m <store file>
              (sandbox: egress denied)          ║                           --offline, 127.0.0.1, token
                                                ║                                   ▲
                                      approved transfer                              │ private address only
                                  (media, diode, reviewer, AV)        apps ─► gateway :8750 (API key, policy)
                                                                     admins ─► console (session, RBAC)
                                                                     every decision ─► hash-chained audit log
```

## Components

| Component | Where | What it does |
|---|---|---|
| `ferry pack` / `sign` / `inspect` | Connected side | Builds a deterministic, signed tar: `manifest.json` (per-file SHA-256, size, kind, detected format, licence, upstream provenance), raw Ed25519 signatures, the artifacts. Writes a review sheet for the transfer reviewer |
| `ferry rehearse` | Connected side | Imports the bundle into a throwaway directory with the real verifier, runs llama-server on each GGUF inside an OS network sandbox, sends one prompt, writes a pass/fail report |
| `ferry verify` / `import` | Either side | Fail-closed verification: archive hygiene, signatures against a local trust store and required roles, exact inventory, digests, content-based format checks, pickle/executable/archive rejection, licence allow-list, limits. Import stages bytes while hashing, then moves them into the store |
| Store | Disconnected side | `store/sha256/<digest>`, files read-only, so a path names its own content |
| Registry and state | Disconnected side | One SQLite database: bundles, artifacts, apps, hashed API keys, admin users, sessions, backends, routes, versioned policies, verification history, audit events |
| Gateway | Disconnected side | OpenAI-compatible `/v1/models` and `/v1/chat/completions`. Authenticate, validate, authorize (default deny), check route provenance, take a concurrency slot, proxy, audit. Denied requests never reach a backend |
| Console | Disconnected side | Static React app served by the same process; admin API with session cookies, CSRF checks and two roles (admin, auditor) |
| Audit log | Disconnected side | Append-only table; each event carries the SHA-256 of its predecessor. Verification finds the first modified, inserted or deleted event; checkpoints kept outside the DB catch truncation |
| Evidence and doctor | Disconnected side | Evidence report (trust anchors, imports and signers, routes with provenance, policy versions, audit status, configuration, dependencies, network inventory) and host checks |

## Key decisions

| Decision | Why | Trade-off |
|---|---|---|
| Plain uncompressed tar | Transfer stations and malware scanners can open it; weights barely compress; streaming verification | Larger media than compressed formats |
| Raw Ed25519 over the exact manifest bytes | A reviewer can check it with stock OpenSSL (`openssl pkeyutl -verify -rawin`) without trusting Ferry | Not yet DSSE/in-toto or OMS; P-256 and PKCS#11 are on the roadmap |
| Signatures checked before the manifest is parsed | Untrusted input is never interpreted before authenticity is known | None |
| Content-based format detection | File-type confusion defeated pickle scanners in 2025 (docs/research/03) | Some valid formats are rejected until supported |
| Reject pickle instead of scanning it | Scanners were bypassed repeatedly; refusing is the only reliable rule | Pickle-only models need conversion on the connected side |
| Trust anchors and import policy are host-only | A stolen console session cannot add a signer or weaken checks | Changes need shell access to the receiving host |
| Default-deny policy, deny overrides allow, deterministic code | Explainable, testable decisions; no model in the decision path | Less expressive than a general policy language |
| Provenance-aware routing | The gateway confirms llama-server is serving the exact imported file (`/props` `model_path` inside the store) before routing to it | Only llama.cpp can report this today |
| SQLite, one process | One host, no extra services to carry across the gap | Not highly available; single-writer |
| No Kubernetes | The target is one to a few GPU servers without a cluster | Teams already on Zarf/UDS get less from this |

## What is deliberately absent

No cloud control plane, telemetry, remote support channel, licence server or
model downloads. No Kubernetes, container images, cross-domain transfer or
malware scanning. See [threat-model.md](threat-model.md) for the security
boundaries and [network-dependencies.md](network-dependencies.md) for every
network interaction.
