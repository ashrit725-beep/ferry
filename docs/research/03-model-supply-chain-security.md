# 03 — Model supply-chain security: what an offline bundle verifier must check

*Research date: 2026-10-28. **[V]** VERIFIED, primary source read. **[V-sec]** VERIFIED only via secondary coverage, a vulnerability database or a search summary. **[I]** INFERRED. **[U]** UNKNOWN.*

## Bottom line

- **Reject pickle by content; don't scan it.** Scanners were bypassed repeatedly in 2024–2025, and PyTorch's "safe" loader had a critical bypass. [I]
- **Validate safetensors and GGUF structure ourselves** before any runtime opens them. GGUF parsers had overflow bugs in 2024, 2025 and 2026. [I]
- **Interoperate with OMS** (Sigstore bundle → DSSE → in-toto Statement v1, per-file digests). NVIDIA NGC already signs this way. [V]
- **Be stricter than upstream defaults**: exact file set, declared sizes, no links, versions that only increase. [I]

## 1. Pickle formats (.bin/.pt/.pth/.ckpt/.pkl)

| Event | What happened | Label |
|---|---|---|
| JFrog, Feb 2024 | About 100 HF models with payloads in pickle `__reduce__`; one opened a reverse shell | [V-sec] |
| ReversingLabs "nullifAI", Feb 2025 | PyTorch archive compressed with **7z, not ZIP**; pickle **deliberately broken after the payload**; Picklescan errored and missed it; HF removed the models and patched the scanner | [V-sec] |
| JFrog, 2 Dec 2025 | 3 Picklescan CVEs, all CVSS 9.3, fixed in 0.0.31. **CVE-2025-10155**: pickle renamed .bin/.pt evades (scanner picks parser by extension). **-10156**: ZIP CRC errors crash the scanner, PyTorch still loads. **-10157**: a subclass of a denylisted module rated only "Suspicious" | [V] |
| CVE-2025-713xx series | At least 9 more denylist gaps (e.g. `cProfile.runctx`, `ensurepip._run_pip`), fixed in 0.0.25–0.0.33 | [V-sec] |
| GHSA-9gvj-pp9x-gcfr | One parsing flaw hit Picklescan, ModelScan and HF's online scanners | [V-sec] |
| PickleBall (arXiv 2508.15987) | Hand-built pickles evaded ModelScan and ModelTracer; almost all malicious HF models found use pickle | [V-sec] |
| 2026 | No newly confirmed incident found | [U] |

**PyTorch.** From 2.6, `torch.load` defaults to `weights_only=True` when no `pickle_module` is passed. `add_safe_globals` adds to the list of objects allowed to run during unpickling [V-sec]. **CVE-2025-32434** (GHSA-53q9-r3pm-6pq6, published 2025-04-17, Critical) allowed remote code execution *with* `weights_only=True` in versions up to 2.5.1, fixed in 2.6.0 [V]. I did not research fickling bypasses [U].

**Takeaway [I]:** Denylists failed in three ways: missing gadgets, parsers that desynced or crashed, and file-type confusion. Air-gapped sites can take days to re-import a fixed model, so refuse pickle and offer safetensors conversion on the connected side.

## 2. Safetensors

**Format [V]:**
- An 8-byte **unsigned little-endian u64** header length N, then N bytes of UTF-8 JSON starting with `{` (trailing 0x20 padding allowed).
- Each tensor has `dtype`, `shape` and `data_offsets [begin, end)`, counted from the start of the byte buffer. The optional `__metadata__` maps strings to strings.
- Duplicate keys are forbidden (not all parsers enforce this). The buffer must be **fully indexed with no holes** (anti-polyglot) and tensors must not overlap. Data is little-endian, row-major. Header ≤ **100 MB**.

Trail of Bits audited it for HF, EleutherAI and Stability AI, published 2023-05-23. It found no code-execution flaw; imprecise spec wording and a polyglot-validation gap were fixed [V-sec]. Sharded checkpoints use `model.safetensors.index.json` with a `weight_map` [V].

**Checks [I]:**
- 2 ≤ N ≤ min(100 MB, size − 8).
- Strict JSON that rejects duplicate keys; dtype allowlist.
- Checked math: product(shape) × dtype size = end − begin.
- Offsets contiguous from 0 to end of file; metadata values all strings.
- Index shards exactly match the manifest.

## 3. GGUF

**Format [V]:**
- Magic `GGUF` (0x47 0x47 0x55 0x46), then u32 version 3 (v2 widened counts to u64; v3 added big-endian **with no in-file flag**).
- u64 `tensor_count`, u64 `metadata_kv_count`, then key-value pairs with u32 type IDs 0–12.
- Strings are a u64 length plus UTF-8 with no NUL; arrays are a type plus a u64 count and can nest.
- Tensor info: name ≤ 64 bytes, u32 n_dims ≤ 4, u64 dims, u32 `ggml_type`, and a u64 offset that is aligned and relative to the start of tensor data.
- `general.alignment` is a multiple of 8 (default 32), padded with 0x00. `general.architecture` is required.

| Source | Finding | Label |
|---|---|---|
| Databricks, 2024-03-22 | **CVE-2024-25664…25668**: heap overflows from unchecked `n_kv`, string-length wraparound, `n_tensors` × struct size, array count × type size. Reached via `gguf_init_from_file()`; patched 2024-01-29 | [V] |
| Cisco Talos, 2024 | TALOS-2024-1912…1916 (e.g. CVE-2024-21825): heap overflows, CVSS 8.8 | [V-sec] |
| CVE-2025-53630 | Integer overflow in `gguf_init_from_file_impl`, out-of-bounds heap read/write | [V-sec] |
| CVE-2026-27940 | Bypass of that fix, fixed in b8146; main loader unaffected, tooling paths affected | [V-sec] |
| CVE-2026-33298 | Tensor-size integer overflow, fixed in b7824 | [V-sec] |

**Takeaway [I]:** The same bug class has recurred for more than 2 years. Our parser must:
- Cap counts, string and array lengths, and nesting depth; require n_dims ≤ 4.
- Use checked byte-size math per `ggml_type`.
- Require aligned, in-bounds, non-overlapping offsets and account for every byte.
- Reject big-endian files by default.

## 4. Model signing: OMS and `model_signing`

- **Format [V]:** a Sigstore bundle containing a **DSSE envelope** over an **in-toto Statement**. Subjects are (path, digest) pairs; the predicate type is `https://model_signing/signature/v1.0`. The OMS spec covers every file, defaults to SHA-256 (BLAKE2b optional), and allows bare keys, self-signed certificates, a private CA, or Sigstore. It ships a 79-test conformance suite.
- **Releases [V]:**
  - 1.0.0 (2025-04-04) was the first stable release.
  - 1.0.1 **fixed a CLI that reported success when verification failed**.
  - 1.1.0 (2025-10-10) added PKCS#11, private Sigstore, `allow_symlinks`, `--ignore_unsigned_files` and BLAKE3.
  - The latest version is 1.1.1, still classified "3 - Alpha" on PyPI.
- **Keys [V]:** EC keys (P-256 in the docs); PKCS#11 needs P-256, P-384 or P-521. Ed25519 support is unknown [U].
- **Offline [I/U]:** Verifying with a key or certificate needs only local files, so it should work offline [I]. The docs don't cover offline mode explicitly [U]. Sigstore verification checks the transparency log against a trusted root [V], which would have to be brought across the gap.
- **Adoption [V]:** NVIDIA has signed every NVIDIA-published NGC model with OMS since March 2025, verified with `model_signing verify` and NVIDIA's certificate chain. Google is trying it on Kaggle [V-sec].

## 5. DSSE, in-toto, TUF and cosign

- **DSSE [V]:** The signature covers PAE (`"DSSEv1" SP len(type) SP type SP len(body) SP body`). Verifiers accept both base64 alphabets, never trust `keyid`, reject unknown `payloadType` values, and pass on exactly the verified bytes. t-of-n is optional.
- **in-toto Statement v1 [V]:** `_type` is `https://in-toto.io/Statement/v1`, with `subject[]` matched by digest only, plus `predicateType` and `predicate`. SLSA Provenance is an example predicate; I didn't research SLSA guidance for models [U].
- **TUF v1.0.37 [V]:** root, targets, snapshot and timestamp roles. Defends against rollback, freeze, mix-and-match and endless data, with threshold keys. Clients abort on expired metadata.
- **cosign [V]:** `verify --key` uses a public key, the protobuf bundle supports offline verification, and `SIGSTORE_ROOT_FILE` sets a custom root. The log is checked by default; I didn't confirm which flags skip it [U].

## 6. AI BOMs and custom code

- **CycloneDX ML-BOM [V]:** covers models, datasets, configurations, provenance and training. The spec version and ECMA-424 details were not on the page [U].
- **SPDX 3.0.1 AI profile [V]:** `AIPackage` has typeOfModel, autonomyType, hyperparameter, metric, limitation, informationAboutTraining, safetyRiskAssessment and energy fields. A separate Dataset profile defines `DatasetPackage`.
- **`trust_remote_code` [V]:** Custom models run repo code, not Transformers code. The docs urge caution and pinning a commit `revision`; `auto_map` in the config points to that code.
- **What this means [I]:** BOMs describe a model; they don't protect its integrity. Carry them as signed payloads and don't gate on them. Bundles with `*.py` or `auto_map` are software and need their own review path.

## 7. Recommendations for the v1 verifier

### MUST checks (any failure rejects the bundle)

| # | Check | Basis |
|---|---|---|
| 1 | Verify the manifest signature **before parsing any content**: DSSE/PAE, keys or X.509 chains pinned in local policy, unknown payloadType rejected | DSSE [V] |
| 2 | Hash every file with SHA-256 and match both the digest **and the declared size** | in-toto, TUF [V] |
| 3 | **Exact file set**: no extra files, no missing files, no ignore lists by default | [I] |
| 4 | Archive hygiene: reject absolute paths, `..`, **symlinks, hardlinks**, devices, setuid bits, and names that collide by case or Unicode form | symlink fixes [V]; [I] |
| 5 | Limits on file size, total size, entry count, compression ratio and header size | §2–3 [V] |
| 6 | Detect file type **by magic bytes, not extension**, against an allowlist (safetensors, GGUF, JSON, text) | CVE-2025-10155 [V] |
| 7 | **Reject pickle everywhere**, including inside ZIP and 7z containers | §1 [V] |
| 8 | Validate safetensors and GGUF structure with checked arithmetic | §2–3 [V] |
| 9 | Reject executable content unless policy allows it and it carries its own signature | §6 [V] |
| 10 | Rollback protection: store the highest version seen per channel and refuse anything lower | TUF [V]; [I] |
| 11 | Treat any parser or scanner error as a rejection | JFrog, nullifAI [V] |
| 12 | Emit a signed verification record | [I] |

### Standards alignment [I]

- **Align now:**
  - DSSE plus in-toto Statement v1 with one SHA-256 subject per file.
  - An OMS-compatible Sigstore bundle, so NGC and `model_signing` signatures interoperate.
  - P-256 keys and private-CA X.509 chains, with PKCS#11 for HSM signing.
  - SHA-256 only; BLAKE variants may conflict with customer crypto policy (unverified).
- **Premature for v1:**
  - A full TUF client: the timestamp role's freshness window suits network updates, not removable media. Borrow its rollback and expiry rules.
  - Public-good Sigstore keyless signing as the default.
  - SLSA requirements.
  - Gating on BOMs.
  - Tensor-level hashing, which the model-transparency README lists only as possible future work [V].

## Implications by wedge

- **A [I]:** These checks are A's core, and they go well beyond tar plus sha256sum. NGC's OMS signatures allow end-to-end checks. The library is Alpha and has shipped a false-success bug, so we should own the verifier and test it against the OMS conformance suite.
- **B [I]:** The manifest digest gives every model a content-addressed identity that policies can name. Little other overlap.
- **C [I]:** Re-verify at install and at load to catch drift, and track which runtime builds are patched (for example llama.cpp b8146 or later).
- **D [I]:** Signed verification records and ML-BOMs are D's evidence, and A produces them.
- **E [I]:** Runtimes are where the attacks land. E must refuse pickle and pin patched builds.

## Open questions

1. Can `model_signing` verify certificate chains fully offline, without CRL/OCSP or a TSA? Test this with NGC's chain.
2. How does OMS handle extra files, and how do the ignored-file records added in 1.1.0 interact with a strict policy?
3. Ed25519 support and FIPS 140 requirements for defense customers (not researched).
4. Who signs a pickle-to-safetensors conversion?
5. Is there a reusable memory-safe GGUF validator?
6. Databricks lists 5 CVEs but says 6 vulnerabilities were fixed; the sixth is not explained.

## Sources (accessed 2026-10-28)

- https://www.bleepingcomputer.com/news/security/malicious-ai-models-on-hugging-face-backdoor-users-machines/
- https://www.darkreading.com/application-security/hugging-face-ai-platform-100-malicious-code-execution-models
- https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/ (located, not opened)
- https://thehackernews.com/2025/02/malicious-ml-models-found-on-hugging.html
- https://www.helpnetsecurity.com/2025/02/10/malicious-ml-models-found-on-hugging-face-hub/
- https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face (located, not opened)
- https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/
- https://www.sentinelone.com/vulnerability-database/cve-2025-71378/ (and sibling CVE-2025-713xx entries)
- https://www.wiz.io/vulnerability-database/cve/ghsa-jgw4-cr84-mqxg
- https://advisories.gitlab.com/pypi/picklescan/GHSA-9gvj-pp9x-gcfr/
- https://arxiv.org/pdf/2508.15987
- https://github.com/pytorch/pytorch/security/advisories/GHSA-53q9-r3pm-6pq6
- https://advisories.gitlab.com/pypi/torch/CVE-2025-32434/
- https://docs.pytorch.org/docs/2.6/_sources/notes/serialization.rst.txt
- https://github.com/huggingface/safetensors
- https://huggingface.co/blog/safetensors-security-audit
- https://www.trailofbits.com/documents/2023-03-eleutherai-huggingface-safetensors-securityreview%20(2).pdf
- https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
- https://www.databricks.com/blog/ggml-gguf-file-format-vulnerabilities
- https://talosintelligence.com/vulnerability_reports/TALOS-2024-1912 (also -1913 to -1916)
- https://osv.dev/vulnerability/CVE-2025-53630
- https://nvd.nist.gov/vuln/detail/CVE-2026-27940
- https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v
- https://osv.dev/vulnerability/CVE-2026-33298
- https://github.com/sigstore/model-transparency
- https://github.com/sigstore/model-transparency/blob/main/CHANGELOG.md
- https://pypi.org/project/model-signing/
- https://github.com/ossf/model-signing-spec
- https://developer.nvidia.com/blog/bringing-verifiable-trust-to-ai-models-model-signing-in-ngc
- https://hiddenlayer.com/insight/openssf-model-signing-for-safer-ai-supply-chains
- https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- https://theupdateframework.github.io/specification/latest/
- https://docs.sigstore.dev/cosign/verifying/verify/
- https://cyclonedx.org/capabilities/mlbom/
- https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/
- https://huggingface.co/docs/transformers/en/models
- https://huggingface.co/docs/transformers/en/custom_models
