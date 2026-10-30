# Wedge decision: a verified offline release channel for open-weight AI

*Decision memo, 2026-10-28, from memos 01-06. Labels: **V** VERIFIED, **I** INFERRED, **U** UNKNOWN, with source memo (V-06); **V-sec** secondary-only (03); **local** checked today on the build Mac. Thresholds are ours, not evidence.*

## 1. Summary decision

- **Decision:** wedge A, offline deployment and upgrades, narrowed to one job: prove before transfer that an open-weight model bundle is complete, safe and serves with networking denied; after transfer, serve nothing else.
- **Plus thin B** (the workflow needs it): a default-deny gateway serving only verified digests. Verification records are A's output, not a D product; C, D and E are out.
- **Problem:** open-weight LLM bundles bound for genuinely disconnected enclaves fail after transfer (missing files, hidden network calls, unsafe artifacts); each failure costs another reviewed transfer cycle.
- **ICP:** deployment engineers at small AI vendors serving open-weight models on non-Kubernetes GPU servers in customer-operated, disconnected enclaves.
- **Next:** 15 discovery calls and the §4 demo; apply §8 on 2026-12-09.

## 2. Wedge scoring table

Unlabeled cells are our judgment.

| | **A** Deploy/upgrade | **B** Access control | **C** Operations | **D** Evidence | **E** Inference |
|---|---|---|---|---|---|
| Pain | High where a miss costs a transfer cycle [I-06] | Almost none found [U-06] | Diffuse: auto-updates, version checks [V-06] | Indirect: ISSMs keep authorization docs [V-04] | Low; offline hygiene, not runtimes [I-06] |
| Felt by | Vendor deployment engineers, enclave admins | Platform, security teams | Cleared operators | ISSMs, assessors | ML engineers |
| Budget | Vendor VP Eng; enclave program lead | No separate budget evident [I-05] | Program offices, via services [I-05] | Compliance; CMMC Phase 2 suspended [V-05] | NVIDIA/hyperscaler deals [I-05] |
| Frequency | Every install and update; vendors claim 1-3 months [V-06] | Continuous | Daily | Per authorization or change | Continuous |
| Solved today | Hand-built bundles [I]; Zarf/Hauler, NIM caches [V-01] | LiteLLM, Kong, Open WebUI [V-02] | UDS, OpenShift, Apollo [V-01, V-05] | Manual SSPs [I]; container evidence [V-01] | llama.cpp, vLLM, NIM; TS clouds [V-02, V-05] |
| Incumbents do well | Container packaging, cosign, SBOMs, splitting [V-01] | Keys, allow-lists, budgets; paid RBAC/audit [V-02] | Kubernetes lifecycle [V-01] | Container SBOMs, signatures [V-01] | Mature runtimes [V-02] |
| Still hard | Model-aware gate, offline completeness proof, non-K8s targets [I-01, I-06] | Digest-bound routing [I-02] | Single-box ops without vendor access [I-01] | Model evidence [U-01]; DAAG rules [U-04] | Offline startup, an A problem [I-06] |
| Solo v1 | 6-8 weeks, CPU-only | 2-4 weeks; thin moat | Slow, site-specific [I-04] | Target format unknown [U-04] | Needs GPUs |
| Customer test | Same day, connected side | Same day | Inside enclaves only | At assessment only | Needs GPUs |
| Expansion | Owns the AI import boundary; C, D, B follow | Incumbents hold it [I-02] | Large, after delivery [I-05] | Medium; accreditation is the customer's [I-04] | Huge, capital-heavy [I-05] |
| Validate by talking | Yes: #zarf Slack [V-05]; no clearance [I-05] | Yes; expect "we use LiteLLM" | Hard; cleared staff rarely post [I-06] | Slowly, via ISSMs | Answers favor incumbents |
| Falsified if | Post-transfer failures rare, or re-transfer takes days | Buyers accept LiteLLM, OPA and WORM logs [I, U-02] | Ops pain is just updates (A) [I-06] | AOs don't treat weights as SI-7(15)/CM-14 components [U-04] | Already: crowded [I-05] |
| **Score /10** | **8** | **4** | **3** | **5** | **2** |

## 3. Why this wedge

- **Convergence.** Every memo points to A: strongest wedge in 01, 04, 05, 06; prerequisite for B and D in 02, 03 [I]. YC's RFS names "deployment tooling" [V-05].
- **Proof, not transport.** Zarf and Hauler move opaque blobs well [V, I-01]. Recorded failures (hidden network calls, missing tokenizer and auxiliary files, wheel gaps [V-06]) are completeness failures caused outside, found inside [I-06]; a working chat test does not prove isolation [V-06].
- **Defensible security.** Pickle scanners were bypassed; GGUF parsers overflowed through 2026 [V, V-sec-03]; `model_signing` is Alpha and once reported false success [V-03]. Strict rejection evidences SI-7(15), CM-14, SR-4(3) (text V-04; mapping I-04).
- **Thin B is required.** Ollama has no server auth; llama.cpp and vLLM keys are flat [V-02]. Without a gate, verification is advisory; digest-bound routing is B's clearest gap [I-02].
- **Fits constraints.** CPU-only; llama-server 0.7.0 is installed; the macOS sandbox blocks outbound, allows loopback [V-local].
- **Expansion.** Every later update crosses this boundary: C is mostly "another bundle" [I-06]; evidence falls out [I-01]. Defense Unicorns' >$1B valuation [V-05] marks ceiling and threat [I].

## 4. ICP (hypothesis, unvalidated)

**Segment.** US AI vendors and integrators (10-200 staff) serving open-weight models on 1-4 Linux GPU servers without Kubernetes, with at least one live or contracted deployment in a customer-operated, genuinely disconnected enclave (prime-contractor or national-lab sites; updates cross by reviewed media). Memo 05 ranks the segment first (access high; evidence medium, mostly INFERRED); the non-Kubernetes cut is ours [I-01].

**Environments.** *In:* genuinely disconnected, customer-operated. *Later:* restricted networks with an internal mirror (a miss is a change request, not a media cycle) [I]. *Out:* private and IL5 commercial cloud; provider-run classified regions (AWS TS, Azure Gov TS, GDC) [V-05]; on-prem with egress; hospitals and banks (none named disconnected [U-05]). Regulated is not disconnected [I].

- **User:** the vendor's deployment engineer, who builds the bundle and takes the failure call; second, the customer's enclave admin or data transfer agent (DTA).
- **Buyer:** vendor VP Engineering or Head of Delivery. Anchors: Replicated $2k-3k/month base, JFrog self-managed $27k-51k/yr [V-05]; our fit is INFERRED [05].
- **Friction workflow:** stage weights, tokenizer, runtime, configs and wheels on media; the DTA scans and transfers under CSA rules we cannot read [U-04]; install; a missing file or phone-home surfaces inside [V-06, I-06]; repeat.
- **Workaround:** hand-built bundles; per-tool offline flags (`HF_HUB_OFFLINE`, `LITELLM_LOCAL_MODEL_COST_MAP`) that leak [V-06]; ad hoc `--network none` tests [I-06]; site visits.
- **Cost:** a cycle per miss; vendors claim weeks [V-06, vendor claims], no primary figure found [U-06]; plus delayed go-live and travel [I].
- **Minimum product:** connected-side packer, network-denied preflight and signer; receiving-side importer that verifies fail-closed, activates llama.cpp, gates serving by digest and writes a signed record.
- **Security requirements:** zero outbound traffic, telemetry or license call-home; customer-pinned P-256/private-CA keys checked before parsing; fail closed, enforced server-side; tamper-evident records; no vendor remote access (largely outside CMMC scope [I-05]); FIPS 140-3 cited by NSA guidance [V-04], need unconfirmed [U-03].
- **Why existing tools fall short:** movers skip model checks [V-01, by absence]; most receivers assume Kubernetes [V-01]; NIM's flow serves only NIM [I-06]; JFrog air-gap export needs Enterprise+ and RLM is sunsetting [V-01]; no gateway binds routing to digests [I-02].
- **Simplest demo (one laptop; Wi-Fi off once a small GGUF is fetched):** a Hub-referencing config fails preflight, listing the blocked connection; a one-byte-tampered bundle and a pickle renamed `.gguf` are rejected; a good bundle streams real tokens through the gateway; an unverified model is denied; the signed record opens.

## 5. MVP vertical slice

1. **Trust setup (receiving side).** The admin starts the importer (Python 3.14 stdlib, SQLite) with pinned P-256 keys and a policy (formats, size limits, channel); only it writes the verified store and launches runtimes.
2. **Pack (connected side).** GGUF weights, auxiliary files, launch config and a pinned llama.cpp build (≥ b8146, fixing CVE-2026-27940 [V-sec-03]); per-file SHA-256, size and magic-byte type; pickle and executables rejected; GGUF/safetensors structure bounds-checked [03].
3. **Preflight.** The exact launch command and a real prompt run in a deny-outbound sandbox (`sandbox-exec` now, Linux network namespace later [I]); any outbound attempt or missing file fails the pack.
4. **Sign.** in-toto Statement v1, one subject per file, in a P-256 DSSE envelope via system OpenSSL, OMS-compatible [V-03 formats].
5. **Transfer sheet.** Media-sized parts plus a file, type, size and hash list for the DTA; we neither transfer nor scan.
6. **Import.** Signature before any parsing; then exact file set, sizes, digests, path/link hygiene, magic bytes, structure, no pickle, increasing channel version; any error rejects [03 MUST list].
7. **Activate.** `llama-server -m <verified path> --offline` on 127.0.0.1 with a service-held key; re-hash at load; match `/props` `model_path` and `build_info` [V-02].
8. **Gate (thin B).** The sole exposed listener is OpenAI-compatible; hashed client tokens map to approved digests; default deny.
9. **Prove.** A real smoke prompt through the gateway with networking denied; an unapproved model gets 403. Nothing is simulated: no runtime, no pass.
10. **Record.** Hash-chained event log plus signed verification record (digest, checks, runtime build, smoke result), worded as evidence supporting SI-7(15)/CM-14, never compliance [I-04].
11. **Upgrade and rollback.** File-level deltas reference a base manifest digest; the prior version stays for rollback; lower versions are refused.

## 6. Explicitly out of scope (v1)

- **A, later:** Kubernetes, Helm, container images, replacing Zarf/UDS; vLLM/NIM adapters; Ollama after llama.cpp (absent here [V-local]; its digest hashes the manifest, not weights [I-02]); pickle scanning or conversion; full TUF, keyless Sigstore, SLSA, BOM gating, tensor hashing [I-03]; enforced two-person signing, chunk deltas, HSM/PKCS#11.
- **Other wedges:** B's SSO, RBAC, budgets, rate limits, OPA/Cedar; C's monitoring and fleet ops; D's control mappings, SSP/eMASS exports, compliance claims; E's runtime or GPU work.
- **Never:** cross-domain or media-scanning functions; hosted control plane, telemetry, remote support.

## 7. Evidence ledger

**VERIFIED**
- [01] Delivery docs omit model formats, pickle and licenses (by absence); most receivers assume Kubernetes; JFrog RLM EOL planned 31 Jan 2028.
- [02] No runtime has per-model authorization; Ollama has none; LiteLLM RBAC, audit and SSO beyond 5 users are Enterprise.
- [03] Picklescan CVEs (CVSS 9.3); PyTorch `weights_only` bypass; NGC models OMS-signed; `model_signing` false-success bug.
- [04] SI-7(15), CM-14, SR-4(3), AU-10(3) text; 800-171r3 tailors out SI-7; NISP defaults to low integrity.
- [05] CMMC Phase 2 suspended 13 Jul 2026, overriding memo 04's INFERRED 10 Nov 2026 start; much classified AI runs in provider-operated clouds.
- [06] "Offline" modes still call out; vLLM #1405 unresolved since Oct 2023; cadence and delay figures are vendor claims.
- [local] llama-server 0.7.0 present; `sandbox-exec` blocks outbound but is DEPRECATED; Ollama absent; no GGUF in common caches.

**INFERRED.** No end-to-end open-weight pipeline found [01]; failures caused outside, found inside [06]; digest-bound routing is B's real gap [02]; room in customer-operated enclaves [05]; no remote access keeps vendors largely outside CMMC scope [05]; SI-7 may go unselected under NISP defaults [04]; price range [05].

**UNKNOWN.** Transfer cycle times [06]; DAAG transfer rules [04]; AO treatment of weights [04]; offline X.509 validation and FIPS needs [03]; disconnected banks and hospitals [05]; whether buyers accept self-built gateways [02]; share of disconnected installs without Kubernetes (not researched).

## 8. Falsification criteria

After 15 ICP discovery calls, kill or re-scope if:

1. Fewer than 5 name a post-transfer AI-bundle failure in the last 12 months.
2. Typical re-transfer takes two business days or less.
3. Two-thirds or more deliver to Kubernetes (Zarf/UDS) or provider clouds; then re-scope as a Zarf extension.
4. Zarf/Hauler plus scripts already cover model checks and offline preflight, or an incumbent ships this before we sign 3 design partners.
5. Enclave ISSMs or DTAs won't admit the importer, or say the record adds nothing.
6. No prospect runs the demo on a real bundle within 2 weeks, or none commits to a paid pilot within 90 days.

## 9. Biggest uncertainties

1. **Pain magnitude:** failure frequency and cycle cost; no primary data [U-06].
2. **ICP size:** vendors shipping open weights to non-Kubernetes, customer-operated enclaves [U].
3. **Admission:** the importer itself needs approval; AO treatment of weights under SI-7(15)/CM-14 is UNKNOWN [04].
4. **Payer:** the vendor feels the pain; the enclave owner controls the receiving side [I].
5. **Runtime mix:** if prospects serve vLLM on CUDA, v1 proves the workflow, not their production path [I].
6. **Incumbents:** Defense Unicorns, NVIDIA or JFrog adding model-aware checks [I].
7. **Crypto policy:** FIPS 140-3, Ed25519, chain validation without CRL/OCSP [U-03].
