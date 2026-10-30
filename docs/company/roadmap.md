# Roadmap

*Owner: founder. Written 2026-10-28. Follows [02-decision-revision](../strategy/02-decision-revision.md). Items are grouped into five stages. Within a stage they are ordered by customer value, urgency, time, technical risk, security impact and the evidence needed to start. Each item gives why, an evidence gate and a rough size. Sizes assume one founder: **S** ≤ 3 days, **M** ≤ 2 weeks, **L** ≤ 6 weeks, **XL** > 6 weeks; they agree with the cost model in [pricing](pricing.md) §5. Gate codes K1-K8 are the kill and re-scope rules in [customer-discovery](customer-discovery.md) §7. P1, P2 and A1 are the three rules in its "Preconditions and parking" paragraph, labelled there; pilot.md and pricing.md cite them by content. (A1 here is not v1-additions A1, the anti-rollback spec, which this file always cites as "v1-additions A1".) **P1:** 5+ of 15 calls ship weights as OCI artifacts or Zarf packages, so OCI/cosign output must precede pilot 1. **P2:** 3+ require FIPS mode or an algorithm such as P-256, so P-256 must precede pilot 1. **A1:** 4+ of 5 receiving calls say a new executable takes over 6 months, so phase 2 stays parked and stock-tool verification is mandatory. S and E codes are in [pilot](pilot.md). Labels: VERIFIED (URL or a local check on the build Mac), INFERRED, UNKNOWN.*

## Baseline (2026-10-28)

| Status | Capability |
|---|---|
| VERIFIED on the build Mac (macOS, Apple Silicon) | `ferry preflight` wraps any launch command in a `sandbox-exec` profile. It proves egress is blocked with an in-sandbox probe, collects kernel sandbox denials (process, PID, port), attributes Python DNS lookups and connects to the calling module, scans output, matches 11 rules of offline fixes (9 documented, 2 inferred), and fails on any blocked connect, Python network call or network-failure output line (a blocked DNS lookup the hook cannot attribute is only a warning unless `--strict`). A real `llama-server` serving Qwen2.5-0.5B-Instruct passes. Ed25519 signatures over the exact manifest bytes verify with OpenSSL 3+. The hash-chained audit log detects modified events |
| IN PROGRESS (v1 scope) | pack/sign/verify/import with model-aware checks; `ferry rehearse`; receiving side (gateway, API keys, default-deny policy, provenance check, audit, evidence report, console) |
| UNTESTED | Linux network-namespace isolation (implemented; no Linux host yet) |
| NOT BUILT | Container-specific support beyond wrapping the launch command; Kubernetes; P-256, DSSE/in-toto, OMS, cosign and OCI outputs |

## Near-term items at a glance

| # | Item | Stage | Value | Urgency | Size | Tech risk | Security impact | Evidence to start |
|---|---|---|---|---|---|---|---|---|
| 1.1 | Validate Linux isolation on real hosts | 1 | High | Now | M | High | High | None |
| 1.2 | Finish pack/sign/verify with stock-tool checks | 1 | High | Before any pilot offer | M | Medium | High | None (v1 scope) |
| 1.3 | Rule-base growth from real runs | 1 | High | From the first concierge run | S per rule | Low | Medium | One real-run observation per rule |
| 1.4 | Report label and ledger fields | 1 | Medium | Before the first concierge run | S | Low | Low | None |
| 1.5 | `docker run` preflight wrapper | 1 | High if stacks are containers | First container prospect | M | High | Medium | A qualified prospect launching with `docker run` |
| 2.1 | P-256 keys | 2 | High at FIPS sites | Pilot | S-M | Low | High | P2, or the pilot's reviewer |
| 2.2 | vLLM + safetensors on CUDA | 2 (1 if K4) | High if K4 | Pilot | L | High | Medium | K4, or a pilot on vLLM |
| 2.3 | Compose wrapper | 2 | Medium | Pilot | M | Medium | Low | The pilot ships with compose |
| 2.4 | Anti-rollback | 2-3 | Medium | Second shipment | S-M | Low | High | Two versions of one bundle |
| 2.5 | DSSE/in-toto attestations | 2-3 | Medium | When asked | M | Medium | Medium | A reviewer names in-toto, OMS or cosign |
| 3.1 | Single static binary | 3 (2 if install blocks) | Medium | Production | M | Medium | Medium | Pilot install blocked or slow |
| 3.2 | OMS, cosign and ModelPack outputs | 3 (pre-pilot if P1) | Medium; high if P1 | Production | M each | Medium | Medium | P1, or a customer on Zarf, Hauler or a registry |

## Stage 1: required for the first useful product

Done when a concierge preflight on a prospect's real stack, on their own machine, gives a result we can stand behind and they can act on.

**1.1 Validate Linux network-namespace isolation on real Linux hosts.**
- *Why:* Linux is the customer platform (02). The path (`unshare --net --map-root-user`, then `ip link set lo up`; ferry/sandbox.py) has never run. Documented host settings are likely to break it:
  - Ubuntu 24.04 restricts unprivileged user namespaces by default and denies capabilities inside them (VERIFIED, https://documentation.ubuntu.com/release-notes/24.04/).
  - The DISA RHEL 9 STIG requires `user.max_user_namespaces = 0` unless the ISSM documents an operational need (VERIFIED, V-257816, https://stigviewer.com/stigs/red_hat_enterprise_linux_9/2026-02-05/finding/V-257816). pilot.md cites the same rule for RHEL 8.
  - On such hosts the runner should exit with an error and the preflight fail closed rather than pass (INFERRED from ferry/preflight.py; untested). That is safe but unusable.
- *Work:*
  - Run the existing tests on real hosts.
  - Add a fallback that needs no user namespace: a root-created network namespace that drops back to the invoking user, keeping the same in-sandbox probe. It must never ask the host owner to weaken a control (pilot.md §4.1).
  - Name the mechanism and any missing tool (`unshare`, `ip`, `strace`) in the report.
  - Check that GPUs stay visible (`ferry preflight -- nvidia-smi`) and that multi-GPU runtimes start on loopback only (both INFERRED, untested).
- *Evidence gate (done):* `tests/test_sandbox.py` and `tests/test_preflight.py` pass with the probe blocked on Ubuntu 22.04, on Ubuntu 24.04 with default AppArmor, and on RHEL 8 or 9 both stock and with `user.max_user_namespaces = 0` (using the fallback), each with and without `strace`. The real `llama-server` test passes on at least one of them. GPU visibility is checked on one CUDA host. A local Linux VM on the build Mac should cover the namespace behaviour, and an x86_64 host the rest (INFERRED). Until then, Linux runs are declared joint first tests (customer-discovery §8).
- *Size:* M. *Security:* a false "egress blocked" is the worst failure this product can have, so the probe must gate every pass on every mechanism.

**1.2 Finish pack/sign/verify with stock-tool verification and the review sheet** (IN PROGRESS).
- *Why:* the pilot 1 deliverable (02; pilot.md §4.4-4.5). The far-side reviewer must check the media without trusting Ferry. The model-aware checks are the security core: pickle and executables rejected by content, and GGUF and safetensors structure validated, because pickle scanners were bypassed and GGUF parser overflows recurred from 2024 to 2026 (research/03).
- *Evidence gate:* tests reject a one-byte-tampered bundle, a pickle renamed `.gguf` and malformed GGUF or safetensors. A packed Qwen bundle passes the pilot.md §4.5 procedure (`sha256sum -c`, `tar`, `openssl pkeyutl -verify -rawin`, key-id check) on a machine without Ferry. One receiving-side interviewee reviews the review sheet (the receiving-side close, customer-discovery §4b).
- *Size:* M. *Security:* high, because the verifier parses untrusted files.

**1.3 Rule-base growth from real runs.**
- *Why:* attribution with a fix is the differentiation hypothesis (02). Today's 11 rules come from documentation; 0 come from real stacks. The first gap is already visible: an internal dry run on 2026-10-28 of `llama-server -hf` (build 11669) showed a blocked DNS lookup and the line "failed to resolve commit", but no finding, because no rule matches llama.cpp's own Hub messages.
- *Loop:* every unmatched attempt from an evaluation, pilot or production run becomes a candidate. It ships as a rule when it has:
  - the observed host, package or message, described generically (no customer detail; pilot.md §9);
  - a fix taken from the project's own docs or source, or reproduced by a fail-then-pass re-run;
  - a `documented` or `inferred` confidence label;
  - a regression test using a test double.
  Track the share of attempts matched (metrics.md §4).
- *Evidence gate:* all four conditions above, per rule. *Size:* S per rule, ongoing. *Security:* a wrong fix misleads the engineer, so inferred rules stay labelled as inferred.

**1.4 Report label and run-ledger fields.**
- *Why:* metrics.md §3 separates internal, evaluation, pilot and production activity, but preflight and rehearsal reports carry no label. Add `label` (test, pilot or production), a hash of the command, environment variable names (never values), the platform and the isolation mechanism.
- *Evidence gate:* none; needed before the first concierge run. *Size:* S.

**1.5 Preflight wrapper for `docker run`.**
- *Why:* many serving stacks ship as container images (INFERRED), and `docker run --network none` is the substitute prospects already know: it leaves only loopback (VERIFIED, https://docs.docker.com/engine/network/drivers/none/). A container started inside the sandbox is created by the Docker daemon, outside Ferry's namespace, so today only output scanning applies (pilot.md §4.1, INFERRED). The wrapper is worth building only if it adds attribution: enforce `--network none`, bind-mount the Python hook and its log into Python images, and collect output. On macOS, Docker Desktop runs containers inside a Linux VM, so the host sandbox cannot observe them (INFERRED); build on Linux first.
- *Evidence gate:* a qualified prospect whose launch command is `docker run` (gtm.md §7, question 5), and the leaky test double packaged as an image that fails with attribution on Linux.
- *Size:* M. *Risk:* high, because collecting evidence inside a container without extra privileges is unproven.

**Watch item:** Apple marks `sandbox-exec` deprecated (01 local check). Re-run the macOS tests on each macOS release; macOS stays the demo and Mac-packer platform (02). Size: S per release.

## Stage 2: first pilot

Done when one real shipment completes pilot.md phase 1. Build only what the signed scope needs, in this order. The pilot kit (wheelhouse with a SHA-256 list, runbook, order form; pilot.md §8) is S and comes first.

**2.1 P-256 signing keys.**
- *Why:*
  - FIPS hosts: a RHEL-compatible distribution's documentation says FIPS-mode crypto policies disable Ed25519 keys and recommends ECDSA P-256/384/521 or RSA 3072+ (VERIFIED, https://docs.ciq.com/rlc-h/9/troubleshooting). In 2023, discussing the OpenSSL 3.0 FIPS provider, OpenSSL maintainers said Ed25519 is not FIPS-approved and is unsupported under the `fips=yes` property (VERIFIED, https://github.com/openssl/openssl/issues/20758); whether the validated module on a given target host accepts it today is UNKNOWN. Whether `openssl pkeyutl` refuses our signatures on a FIPS-mode RHEL 9 host is UNKNOWN (pilot.md §7).
  - Interoperability: `model_signing`'s key verifier accepts only EC P-256/384/521 keys, so today's Ed25519 manifests cannot be checked with it (research/07 §1.5). research/07 §4 ranks P-256 DSSE/in-toto output second overall, without waiting for a discovery gate; this roadmap waits for P2 or a reviewer. Settle the order at the call-5 tally.
  - Older OpenSSL: OpenSSL 1.1.1's `pkeyutl` does not support Ed25519 (pilot.md §7).
  - HSMs: `model_signing`'s PKCS#11 path needs P-256, P-384 or P-521 (research/03).
  - Local check, 2026-10-28: a P-256 signature over a manifest verified with `openssl dgst -sha256 -verify` under both OpenSSL 4.1.0 and macOS's LibreSSL 3.3.6, while Ed25519 `-rawin` failed on LibreSSL. P-256 widens the set of stock tools that can check a manifest.
- *Evidence gate:* P2 fires (3+ of 15 calls require FIPS mode or an algorithm), which makes P-256 a precondition for pilot 1; or a pilot reviewer needs it (pilot.md E3 defers that pilot until then); or a prospect's reviewer checks signatures with `model_signing` (research/07 §1.5). Test on a FIPS-mode RHEL 9 host before claiming anything.
- *Size:* S-M. *Security (design requirement, not built):* the manifest must name its algorithm, and verifiers must pin the algorithm per trusted key, so a signature cannot be downgraded to a weaker or different scheme.

**2.2 vLLM + safetensors on CUDA.**
- *Why:* if production serving is vLLM, SGLang or NIM on CUDA (H5), the GGUF + llama.cpp path proves the workflow, not the prospect's path (01 §9). vLLM is also where documented offline failures live: discussion #1405 and usage stats on by default (research/06).
- *Work:*
  - Preflight `vllm serve` with full weights on a Linux CUDA host.
  - Confirm the vLLM and Hub rules against a real run.
  - Validate safetensors structure in pack (in progress).
  - Extend rehearse to check the served model through vLLM's `/v1/models` `root` field (research/02).
- *Evidence gate:* K4 (8+ of 15 serve via vLLM, SGLang or NIM on CUDA), or a pilot that runs vLLM. Requires 1.1. If the call-5 tally points to K4, this moves to stage 1, because under K4 no demo counts toward K7 until that path works.
- *Size:* L: a rented GPU host, CUDA wheels, flash-attn builds (research/06). *Risk:* high.

**2.3 Compose wrapper.**
- *Why:* multi-service stacks (application, runtime, vector database) ship as compose files (INFERRED). `network_mode: none` turns off all networking (VERIFIED, https://docs.docker.com/reference/compose-file/services/), which also cuts service-to-service traffic. The wrapper therefore needs an internal-only network with evidence capture, an untested design.
- *Evidence gate:* the pilot's stack uses compose. *Size:* M, after 1.5.

**2.4 Anti-rollback.**
- *Why:* the TUF rollback rule (research/03). A replayed older bundle can bring back a superseded model or configuration.
  - The import side already specifies rollback and version-reuse checks (v1-additions A1, in progress).
  - A stateless stock-tool reviewer cannot enforce them. Add a channel, a monotonically increasing version and the previous bundle's digest to the manifest, and print them on the review sheet so the reviewer can check order by hand.
- *Evidence gate:* a pilot ships two versions of one bundle, or a receiving-side interviewee asks how an older bundle would be caught.
- *Size:* S for the manifest and review sheet; M for the import side with tests. *Security:* high.

**2.5 DSSE/in-toto attestations.**
- *Why:* an in-toto Statement v1 with one SHA-256 subject per file, inside a DSSE envelope, is the shape OMS uses; NVIDIA signs NGC models that way (research/03), and cosign verifies attestations. Trade-off: DSSE signs the PAE encoding, not the raw manifest bytes, so a plain `openssl` check gets harder. Emit it alongside the raw-bytes signature, never instead of it.
- *Evidence gate:* a prospect or reviewer names in-toto, OMS, Sigstore bundles or cosign as required or preferred (gtm.md §7, question 8), or P1 fires. *Size:* M (with 2.1: 10-15 days, pricing.md §5).

## Stage 3: production deployment

Done when the vendor runs Ferry on every shipment of a product line without the founder. An enclave may also run the receiving side.

**3.1 Single static binary.**
- *Why:* installing Python and wheels on a reviewed host is itself a dependency transfer: five direct runtime dependencies plus their transitive ones (docs/network-dependencies.md). One hashed file is easier to review and admit. Two routes:
  - A one-file build per platform (PyInstaller- or Nuitka-class). It is not truly static, and it must carry the preflight hook as a data file. LiteLLM #25062 shows such builds can drop bundled data, so preflight our own binary before shipping it.
  - A rewrite in a compiled language (XL).
- *Evidence gate:* in a pilot, installing the Python package takes more than a day or is blocked by review (session 1, pilot.md §4.1), or 2+ prospects say they cannot install Python packages on build hosts. If A1 fires (new executables take over 6 months inside), a binary does not help the receiving side; stock-tool verification does.
- *Size:* M (one-file build); XL (rewrite).

**3.2 OMS, cosign and ModelPack-compatible outputs.**
- *Why:* OCI model packaging is converging (02).
  - ModelPack has been a CNCF Sandbox project since 2025-05-13 (VERIFIED, https://www.cncf.io/projects/modelpack/).
  - Its spec defines `application/vnd.cncf.model.manifest.v1+json`, plus raw or tar weight layers such as `application/vnd.cncf.model.weight.v1.raw`, and recommends uncompressed weights (VERIFIED, https://github.com/modelpack/model-spec/blob/main/docs/spec.md).
  - `docker model package --format cncf` already writes that format (VERIFIED, https://docs.docker.com/reference/cli/docker/model/package/).
  - OMS bundles verify with `model_signing verify` (research/03); Zarf and Hauler verify with cosign (research/01).
- *Work:*
  - An OMS bundle (DSSE plus in-toto, P-256), tested against the OMS conformance suite.
  - A cosign-verifiable signature over the manifest. Confirm the offline flags first: cosign checks the transparency log by default (research/03).
  - Export of a bundle as an OCI image layout with ModelPack media types, so registries, Zarf and Hauler can carry it.
- *Evidence gate:* P1 (5+ of 15 ship weights as OCI artifacts or Zarf packages), which makes this a precondition for pilot 1; or a customer that moves artifacts with Zarf, Hauler or a registry, or verifies with cosign or `model_signing`.
- *Size:* M each (10-20 days for OCI and cosign together, pricing.md §5).

**3.3 Parser fuzzing and an external review of the verifier.**
- *Why:* the verifier parses untrusted GGUF and safetensors before any runtime does, and GGUF parser overflows recurred in 2024, 2025 and 2026 (research/03).
- *Evidence gate:* before the first production import on a receiving side, or when a customer security review asks. *Size:* M for fuzzing; the cost of an external review is UNKNOWN.

**3.4 Receiving side (phase 2) hardening.**
- *Why:* the alternative ICP (customer-discovery §1). Import, the provenance-gated gateway, audit, the evidence report and the console exist as v1 scope, in progress.
- *Evidence gate:* an ISSM or enclave platform lead asks in writing to evaluate it and names the admission path (pilot.md §11). If A1 fires, it stays parked. Until the gate fires, treat it as frozen: research/07 §4 recommends freezing it because Jozu, the Model Validation Operator and LiteLLM already occupy that ground. *Size:* L.

**3.5 Signed import receipts and signed audit checkpoints** (v1-additions A4).
- *Evidence gate:* a receiving site asks for proof of what was imported and when. *Size:* S-M.

## Stage 4: broader enterprise adoption

| Item | Why | Evidence gate | Size |
|---|---|---|---|
| PKCS#11/HSM signing (P-256) | NSA-led guidance keeps keys in a vault or HSM (research/04); `model_signing` supports PKCS#11 (research/03) | A customer requires HSM-held signing keys | M |
| Validated-module crypto path | FIPS 140-3 depends on the validated module actually used (v1-additions A4); whether customers need it is UNKNOWN (research/03) | A contract names FIPS 140-3 | M-L |
| Enforced two-person signing | Two-person control of weights in NSA-led guidance (research/04); `required_roles` is already in the v1 spec | A receiving site requires dual approval | S-M |
| File-level delta updates | Weights are the bulk of a delivery, and staging needs a multiple of their size in free disk (research/01) | A customer's transfer time per update is a stated cost | L |
| **Deferred: Kubernetes** (Helm, Zarf/UDS integration) | Most receiving paths assume Kubernetes (research/01), but the ICP cut is non-Kubernetes | K5 fires (10+ of 15 deliver to Kubernetes or provider clouds): re-scope as a Zarf/Hauler extension, with preflight as a package or CI step and OCI/cosign outputs; or 3+ qualified prospects, or one paying customer, ask for preflight inside their Zarf flow | L |
| **Deferred: fleet management** | Many sites, many versions | A paying customer runs Ferry in production at 3+ receiving sites and asks for cross-site status. No network crosses the gap, so a fleet view means status reports carried on media | XL |
| **Deferred: SSO** (OIDC, SAML or LDAP for the console) | Only the receiving-side console has human users; the vendor CLI needs none. LiteLLM sells SSO beyond 5 users as an Enterprise feature (research/02), so receivers may expect it | A receiving-side production deployment where the ISSM requires central identity, or more than a handful of console admins | M-L |

## Stage 5: longer-term platform expansion

| Item | Why | Evidence gate | Size |
|---|---|---|---|
| Own the AI import boundary | Every later update crosses it; operations and evidence follow (01 §3) | 3+ production receiving-side deployments | XL |
| Evidence packages for authorization | ISSMs maintain SSPs and CM plans (research/04). Wording stays "produces evidence that can support ...", never compliance | ISSMs ask for them, and the DAAG transfer text becomes readable (UNKNOWN today) | L |
| More runtimes: NIM, then Ollama after llama.cpp (not TGI, which is archived) | The runtime mix (research/02) | Paying customers on that runtime | M each |
| Signed pickle-to-safetensors conversion on the connected side | Pickle is rejected, not scanned (research/03) | Customers with pickle-only models; who signs a conversion is still open (research/03) | M |

**Never:** telemetry, a hosted control plane, remote support channels, cross-domain or media-scanning functions (01 §6).

## Review points

Re-rank this roadmap after the call-5 and call-10 tallies (K4, K5, P1, P2 can each move an item up a stage), after every pilot session 1 (Linux, install, FIPS findings), and at the 2026-12-09 decision.

Not yet ranked here, from research/07 §4 (written in parallel): preflight results as an in-toto predicate bound to manifest digests, attachable to ModelKit, ModelPack or Zarf packages; import of CMX network-report JSON so CMX users get fixes; rules for Docker Model Runner's Docker Hub requests and NIM remote model URIs (hypotheses until reproduced); and renaming `ferry preflight`, which collides with Replicated's open-source "preflight" checks. Rank them at the first re-rank.
