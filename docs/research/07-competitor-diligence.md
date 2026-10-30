# 07: Competitor diligence for the revised wedge

*Research note, 2026-10-28, on the wedge in [strategy/02](../strategy/02-decision-revision.md): connected-side offline-readiness preflight plus signed manifests for AI deliveries.*

*Tags: **V** VERIFIED in a primary source (URLs under Sources); **V-claim** vendor self-description; **V-local** checked in this repo today; **I** INFERRED; **U** UNKNOWN. We ran no competitor product.*

## Bottom line

1. **Replicated CMX is the closest substitute and is ahead of us on what it covers** (confirms strategy/02): egress blocking on VMs, per-attempt PID, command, pod, destination and DNS name, $500/month standalone [V C1, C4, C5]. Its gaps are our ICP's ground: no GPU under `airgap` [I from V C2, C3], weights staged on Replicated's servers, no CUI, ITAR or FedRAMP text [V C3, C6].
2. **`--network none` is the free substitute on the vendor's own GPU host** (Docker; RamaLama's default; suggested by NVIDIA's NIM guide). It records nothing [V C7, C12, C16].
3. **Packaging and signing are converging on OCI plus cosign or OMS** (KitOps, ModelPack, Docker, NGC), and `zarf package verify` needs no cluster [V C9, C11, C13, C16, C19]. Stock-tool verification is table stakes; `model_signing` rejects our Ed25519 keys [V C15].
4. **No product found attributes hidden calls to the calling Python library** [U; six searches], but the mechanism (PEP 578 audit events) is public [V C21]: a lead of weeks.
5. **Only the combination is defensible:** own GPU host, full weights, nothing uploaded, each attempt tied to a library and a fix, bound to a signed manifest. Verified only on macOS; Linux and GPU hosts are untested.

## 1. Findings

### 1.1 Replicated Compatibility Matrix (CMX)

- **Policy.** `open` (default) or `airgap` (blocks all egress), the latter only on VMs and VM-based clusters, not EKS, GKE, AKS or OKE [V C2].
- **Report.** Each event records timestamp, source IP, port and PID, `comm`, pod, destination IP and port, protocol, `likelyService` and `dnsQueryName`; JSON via `replicated network report`; external traffic only by default since Nov 2025 [V C1, C4, C6]. Attribution stops at the process.
- **GPU.** Cloud clusters only (EKS g4dn; GKE and AKS T4); no GPU VMs [V C3]. **I:** a CUDA or vLLM launch cannot run on CMX with egress blocked.
- **Limits.** VMs 2-32 vCPU, 8-128 GiB; `--disk` default 50 GiB, maximum per entitlement; TTL 1 h default, 48 h maximum; default quota 128 GiB RAM and 800 GiB disk, raised free; files arrive by scp or download before the policy switch [V C2, C3, C4, C6]. **I:** 100 GB+ weights fit but are restaged for each ephemeral VM; throughput **U**.
- **Residency.** Replicated bare metal in several data centers, some in the EU [V C3]. A full-text search of the docs repo (809 Markdown files) found nothing on ITAR, CUI, FedRAMP or data residency [V C6, by absence].
- **Price.** $500/month plus compute, no base plan [V C5]. VMs $0.096-1.536/h; GPU nodes $0.321-6.528/h; startup $0.50 per VM, $0.65 per cloud cluster; per-minute credits; creation refused if credits cannot cover the TTL [V C4].
- **Name clash.** Replicated's open-source "preflight" checks a customer's cluster before install [V C8].

### 1.2 Docker

- **`--network none`** leaves only loopback and documents no record of blocked attempts [V C7].
- **`docker model package`** packs GGUF, safetensors or DDUF (plus licenses) as an OCI artifact; `--format cncf` emits ModelPack. None of the 29 `docker model` subcommands signs, verifies, saves or loads (Model Runner v1.2.9, 22 Oct 2026) [V C9, C24].
- **Model Runner** has an unauthenticated API, and on Docker Engine its HEAD requests to Docker Hub record model names whatever the settings [V C10]. Our rule base lacks that call [V-local].
- **ModelPack** has been CNCF Sandbox since 13 May 2025; weights are opaque and the spec is silent on signing [V C11].
- **Docker Sandboxes** (AI coding agents) has a deny-all preset and `sbx policy log` of blocked hosts, without PIDs [V C23]. **I:** Docker has every offline-check primitive except attribution.

### 1.3 KitOps and Jozu

- **KitOps.** CNCF Sandbox since 4 Mar 2025; kit v1.16.0 (29 Sep 2026) [V C13, C24]. No sign or verify subcommand: the docs use `cosign sign/verify --key` on the registry reference; `pull` and `unpack` check layer SHA-256 digests; `kit import --attestation-output` writes SLSA provenance [V C13].
- **Jozu.** Jozu Hub is self-hosted on Kubernetes. Jozu says it "Runs fully disconnected", scans nine vulnerability classes, signs approved artifacts and is awardable on the CDAO Tradewinds and Platform One marketplaces [V-claim C14]. **I:** the most direct threat on signed AI delivery into DoD enclaves, with procurement standing we lack; it claims no network-denied rehearsal.

### 1.4 RamaLama and llamafile

- **RamaLama** v0.25.0 (25 Sep 2026): `ramalama run` uses `--network=none`, read-only model mounts and rootless containers; it converts to OCI, documents no signing and pulls GPU images on first run [V C12, C24].
- **llamafile** 0.10.6 (15 Sep 2026, Mozilla.ai) packs model and runtime into one executable (Windows: under 4 GB only); its README is silent on signing and network use [V C22, C24]. **I:** GGUF plus llama.cpp is the easy lane (memo 02); `ferry rehearse` is least differentiated there.

### 1.5 Sigstore model signing

- **`model_signing` 1.1.1** (10 Oct 2025) is still Alpha on PyPI, with no release since. Methods: Sigstore, key, certificate, PKCS#11. The key verifier accepts only EC P-256/384/521 (`sign_ec_key.py`), so Ed25519 fails [V C15].
- **NGC** models are OMS-signed and verified via `model_signing verify certificate`; NIM also checksums downloads [V C16].
- **Model Validation Operator** v1.0.1 (24 Apr 2025) is a Kubernetes webhook injecting a validating init container, a proof of concept per its README [V C18, C24].
- **Offline** certificate and keyless verification is undocumented [U].

### 1.6 NVIDIA NIM and AI Enterprise

- **Air-gap guide.** Stage with `download-to-cache` or `create-model-store`, mount via `NIM_MODEL_PATH`, leave `NGC_API_KEY` and `HF_TOKEN` unset, and validate with `--network none` [V C16].
- **Model-free NIM** serves any architecture its vLLM or SGLang backend supports from a local path, with no network; `hf://`, `ngc://` or `s3://` sources need network on first start, then a cached manifest [V C16]. **I:** NIM no longer serves only NIM models (contrast memo 01 §4).
- **Licensing.** Production needs NVIDIA AI Enterprise, from $4,500 per GPU-year; Developer Program members get up to 16 GPUs for non-production use; a 90-day evaluation exists [V C17]. Offline runtime license enforcement is **U**.

### 1.7 Zarf

- **`zarf package verify`** (v0.66.0, 13 Nov 2025) checks the signature and checksums of a local tarball or OCI package. The v0.88.0 source verifies strictly and never connects to a cluster. Without a key, an unsigned package passes with a warning [V C19].
- **Release notes.** None of 196 release notes (v0.11.0-v0.88.0) mentions model formats, Hugging Face, egress or offline testing [V C24, by absence].

### 1.8 Library-level attribution

- **No product found** [U]. The nearest stop at process, test or package [V C20]: StepSecurity Harden-Runner (process and CI step, block mode; process events Enterprise-only); netaudit (strace `connect()` per pytest test and PID, Linux only); Socket (static `networkAccess` alerts, PyPI included).
- **Mechanism.** CPython emits `socket.connect` and `socket.getaddrinfo` audit events [V C21]. **I:** CMX or StepSecurity could add attribution quickly. A broad, current rule base is slower to copy.

## 2. Comparison with Ferry preflight

| Capability | Ferry today | CMX | `--network none` | KitOps/Jozu | Zarf | model_signing/MVO |
|---|---|---|---|---|---|---|
| Any launch command, egress denied | Yes on macOS, with in-sandbox probe; Linux untested | CPU VMs only; manual probe | Containers; no probe | No | No | No |
| GPU host, full weights, nothing uploaded | Not proven | No | Yes | n/a | n/a | n/a |
| Attempts recorded | Process, PID, port; DNS names for Python; fails on blocked connects, Python calls and failure lines; an unattributed DNS lookup only warns unless `--strict` [V-local] | PID, command, pod, IPs, ports, DNS; gating scriptable [I] | No; fails only if the app crashes [I] | No | No | No |
| Calling library | Python | No | No | No | No | No |
| Fix per finding | 11 rules (9 documented, 2 inferred) [V-local] | `likelyService` label | No | No | No | No |
| Signed manifest, stock verify | Ed25519 via `openssl`; pack/import in v1 scope | n/a | No | cosign; layer digests | cosign; `verify` needs no cluster | OMS; EC keys, certificates |
| Model-aware checks | v1 scope, unproven | No | No | Jozu claims scanning | No | Digests only |
| Needs Kubernetes | No | No (VMs) | No | Hub yes, CLI no | No (verify) | Operator yes |
| Price | Pre-revenue | $500/mo + compute | Free | KitOps free; Jozu U | Free | Free |

## 3. Real, thin and fatal

**Real, if proven**
- **R1. Local GPU-host runs with full weights.** Beats CMX (no GPU under `airgap`; weights staged on servers that include EU sites) but not `--network none`; unproven until the Linux path is tested. Whether vendors refuse to upload weights is **U**.
- **R2. Library attribution plus the documented fix.** No competitor found, but a thin moat: public mechanism, CMX already reports PID, command and DNS, and only 11 rules, none yet derived from a real customer stack.
- **R3. Offline-run evidence bound to manifest digests in one signed record.** No tool reviewed binds runtime evidence to the artifact signature [I, by absence]. Reviewer value is **U**.

**Thin; do not lead with:** the egress-denied smoke test (CMX, `--network none`, NIM guide); stock-verifiable signatures (Zarf, cosign, OMS); fail-closed gating (a script over CMX JSON); GGUF rehearsal (RamaLama, llamafile, Model Runner). Model-aware checks are a real gap among transport tools (Zarf: none; KitOps: digests only), but Jozu claims scanning and ours are unbuilt.

**Moves that would kill the wedge** [I; check release notes monthly]
1. Replicated adds GPU VMs, `airgap` on GPU clusters or a self-hosted runner; it already owns the ICP relationship, reports and pricing.
2. NVIDIA adds an attempt log to NIM's `--network none` validation.
3. Docker extends `sbx policy log` to `docker run` or Model Runner.
4. Jozu or KitOps attaches offline-run attestations to ModelKits, with Jozu's DoD marketplace standing.
5. StepSecurity adds Python-level attribution to Harden-Runner.

## 4. Implications

**Positioning**
- Target message (true only on macOS today): *which library will phone home, and the setting that stops it, on the box holding your real weights, before media is written.* Drop the "network-denied smoke test" headline.
- Complement CMX, Zarf and KitOps: read their artifacts, emit attestations they can carry.
- Rename `ferry preflight` (clash, §1.1); test names in calls.
- Price against free (`--network none`) and $500/month (CMX) [I].

**Roadmap, in order**
1. Test Linux namespaces on an NVIDIA host (vLLM, 10-100 GB safetensors, `docker run --gpus`); CMX's report fields are the minimum bar.
2. P-256 DSSE/in-toto output that `model_signing` and cosign accept; keep the `openssl` path.
3. Preflight results as an in-toto predicate bound to manifest digests, attachable to ModelKit, ModelPack or Zarf packages.
4. Rules for Model Runner's Docker Hub HEAD requests [V C10] and NIM remote URIs [V C16], as hypotheses until reproduced.
5. Import CMX report JSON so CMX users get fixes.
6. Freeze the receiving side; Jozu, the Model Validation Operator and LiteLLM (memo 02) occupy it.

**Add to discovery:** Do you use CMX or `--network none`? Have you run with GPUs and egress blocked? May weights go to a third-party test cloud (CUI, ITAR, contracts)? Which signature formats do customers' transfer reviewers accept?

## Sources (accessed 2026-10-28)

- **Replicated.** C1 https://docs.replicated.com/vendor/testing-network-policy, https://docs.replicated.com/vendor/tutorial-cmx-airgap. C2 https://docs.replicated.com/vendor/testing-how-to (air-gap section). C3 https://docs.replicated.com/vendor/testing-supported-clusters, https://docs.replicated.com/vendor/testing-about. C4 https://docs.replicated.com/vendor/testing-pricing, https://docs.replicated.com/reference/replicated-cli-network-report, https://docs.replicated.com/reference/replicated-cli-vm-create, https://docs.replicated.com/vendor/testing-vm-create. C5 https://www.replicated.com/pricing. C6 https://github.com/replicatedhq/replicated-docs (full-text search; release notes). C8 https://troubleshoot.sh/docs/preflight/introduction/.
- **Docker.** C7 https://docs.docker.com/engine/network/drivers/none/. C9 https://docs.docker.com/reference/cli/docker/model/package/, https://docs.docker.com/reference/cli/docker/model/. C10 https://docs.docker.com/ai/model-runner/. C23 https://docs.docker.com/ai/sandboxes/, https://docs.docker.com/ai/sandboxes/security/policy/, https://docs.docker.com/ai/sandboxes/governance/monitoring/.
- **ModelPack, KitOps, Jozu.** C11 https://www.cncf.io/projects/modelpack/, https://github.com/modelpack/model-spec, https://www.cncf.io/blog/2026/08/12/advancing-ai-model-interoperability-with-docker-and-modelpack/. C13 https://kitops.org/docs/security/, https://kitops.org/docs/cli/cli-reference/, https://www.cncf.io/projects/kitops/. C14 https://jozu.com/.
- **RamaLama, llamafile.** C12 https://github.com/containers/ramalama. C22 https://github.com/mozilla-ai/llamafile.
- **Sigstore.** C15 https://github.com/sigstore/model-transparency (src/model_signing/_signing/sign_ec_key.py), https://pypi.org/project/model-signing/. C18 https://github.com/sigstore/model-validation-operator.
- **NVIDIA.** C16 https://docs.nvidia.com/nim/large-language-models/latest/deployment/air-gap-deployment.html, .../deployment/model-free-nim.html, .../reference/model-signature-verification.html. C17 https://docs.api.nvidia.com/nim/docs/product.
- **Zarf.** C19 https://docs.zarf.dev/commands/zarf_package_verify/, https://github.com/zarf-dev/zarf (v0.88.0 src/cmd/package.go; v0.66.0 release notes).
- **Attribution.** C20 https://docs.stepsecurity.io/harden-runner, https://netaudit.readthedocs.io/en/latest/pytest-plugin/, https://docs.socket.dev/docs/faq. C21 https://docs.python.org/3/library/audit_events.html.
- **Release dates.** C24 GitHub releases API: containers/ramalama, mozilla-ai/llamafile, kitops-ml/kitops, docker/model-runner, sigstore/model-validation-operator, zarf-dev/zarf.
