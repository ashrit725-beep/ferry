# Decision revision after adversarial review (2026-10-28)

Inputs: [01-wedge-decision.md](01-wedge-decision.md) and two adversarial reviews
(business lens and competition/scope lens). Both returned **modify**, neither
**switch**. Their full objections are in the research workflow journal; the
substance is summarized here, followed by what changed and what did not.

## What the reviewers established

1. **The v1 lane is the easy lane.** GGUF files are self-contained, and
   llama-server only reaches the network through explicit flags (`-hf`, model
   URLs) and has `--offline`. The documented failures (Hugging Face Hub calls,
   vLLM #1405, LiteLLM's cost map, tiktoken vocabularies, Open WebUI auxiliary
   models, wheels) live in Python and container stacks (docs/research/06).
2. **A network-denied smoke test already exists at the ICP's main incumbent.**
   The reviewer reports that Replicated's Compatibility Matrix has an `airgap`
   network policy and network reports with process, destination and DNS names,
   and that `docker run --network none` is a one-flag workaround elsewhere.
   (Reviewer-cited documentation; we have not yet run CMX ourselves.)
3. **The receiving side duplicates shipped tools and adds an admission
   problem.** `zarf package verify`, NIM's internal checksums and OpenSSF model
   signing (`model_signing verify`) already verify artifacts, and a vendor
   cannot put a new service into a customer's enclave without that customer's
   ISSM approving it.
4. **The payer and the controller are split.** The vendor feels the
   completeness pain; the enclave owner controls admission and cares most about
   the importer, the digest gate and the record.
5. **The ICP is unnamed.** No organization in the memos is verified to meet
   every filter, and the non-Kubernetes cut was never researched.
6. **Kill criteria tested pain but not buying,** and two had no thresholds.
7. **OCI model packaging is converging** (CNCF ModelPack, `docker model
   package`, KitOps ModelKits). A bespoke format risks being out-standardized.

## What changed

| Area | Before | After |
|---|---|---|
| Wedge statement | Prove a GGUF bundle is complete, safe and serves offline; serve nothing else after transfer | **Offline readiness for AI deliveries:** before media is written, prove that the exact launch command of an AI stack runs with egress denied, attribute every hidden network call to the library that made it and give the fix, and ship a signed manifest that the far side can check with stock tools |
| First deliverable | Pack, preflight inside the packer, sign, then import, activate, gate, record | `ferry preflight -- <any launch command>` (any runtime, including Python stacks and `docker run`), plus `ferry pack/sign/verify` whose outputs verify with `openssl` and `sha256sum`. `ferry rehearse` covers the GGUF + llama.cpp case end to end |
| Differentiation hypothesis | Model-aware gate plus digest-bound serving | (a) Runs on the vendor's own hardware with full-size weights, nothing uploaded; (b) library attribution with a fix for each known offline failure; (c) a signed, stock-verifiable manifest and a review sheet for the transfer reviewer. CMX limits (GPU VMs, upload size, CUI/ITAR) are unverified and must be checked |
| Platform | macOS sandbox first, Linux later | Linux network namespaces are the customer platform. macOS `sandbox-exec` (deprecated by Apple) is kept for demos and Mac-based packers. **The Linux path is implemented but untested here; testing it on a Linux host is the top engineering priority** |
| Receiving side | Required: importer is the only launcher, gateway is the only listener | **Optional phase 2** for enclave owners: import, provenance-gated gateway, hash-chained audit, evidence. Not part of pilot 1 or the pitch |
| Discovery | 15 ICP calls | About 10 vendor-side (deployment engineer plus VP Eng or Head of Delivery) and 5 receiving-side (ISSM, data transfer agent, enclave platform lead). The receiving-side platform teams at national labs and primes are tested as an alternative ICP in parallel |
| Pilot 1 | Full pipeline | Connected side only: preflight the vendor's real launch command, pack and sign, review sheet, verification with stock tools. Fixed fee per shipment as the pricing hypothesis |
| Pricing anchors | Replicated and JFrog platform fees | The real substitutes: an engineer-day script, `docker --network none`, CMX credits |
| Kill criteria | Pain-only, two without thresholds | Rewritten in docs/company/customer-discovery.md with numeric thresholds, buying signals and a runtime-fit precondition |

## What did not change, and why

- **The receiving-side components stay in the codebase.** The founding brief
  asks for a working end-to-end slice (backend configuration, authentication,
  deterministic authorization, denial before inference, audit, bundle
  verification and rejection). Those parts were already being built and
  tested, and they serve the alternative ICP. They are presented as phase 2,
  not as the wedge.
- **Signatures stay Ed25519 over the exact manifest bytes for now.** They are
  already verifiable with stock OpenSSL. P-256 keys (for customer crypto
  policies), cosign/OCI, Zarf and OMS-compatible outputs are on the roadmap and
  should follow the first discovery calls.
- **The ICP's primary segment stays vendor-side** until discovery picks between
  it and the receiving-side alternative on quantified incidents, a named
  budget owner and an admission path (decision date 2026-12-09).

## Product consequences implemented on 2026-10-28

- `ferry preflight` wraps any launch command in an OS network sandbox, probes
  egress from inside it, collects blocked attempts (macOS kernel sandbox log;
  Linux `strace` when present), scans output for network failures, and by
  default fails on any blocked outbound connection, any network call from Python
  code and any network error in the output. A blocked DNS lookup that macOS
  cannot attribute to a process's Python code (macOS does not log the name) is a
  warning unless `--strict` is set.
- Python stacks get library attribution: a startup hook records every DNS
  lookup and outbound connect with the calling module, and a rule base maps
  known hosts and messages (Hugging Face Hub, tiktoken, LiteLLM cost map, vLLM
  usage stats, Gradio analytics, Chroma telemetry, Ollama, PyPI update checks)
  to their documented offline settings.
