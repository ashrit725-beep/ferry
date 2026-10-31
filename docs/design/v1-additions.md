# v1 additions after the research pass (2026-10-28)

These extend [v1-spec.md](v1-spec.md). They come from the research memos in
`docs/research/` and are implemented during integration, after the first build.

## A1. Rollback and version-reuse protection (import)

Basis: docs/research/03 (MUST check #10, TUF rollback rule) and 01 (no movers
reviewed offer it for models).

- Versions compare semver-style. An optional leading `v` is ignored; the core
  is dot-separated numbers compared numerically, trailing zero parts do not
  count (`1.0` = `1.0.0`); a pre-release (`-rc.1`, or a letter suffix on the
  last core part as in `1.0.0rc1`) sorts below its release, with numeric
  identifiers below alphanumeric ones and digit runs compared as numbers
  (`rc9` < `rc10`); build metadata after `+` is ignored. A version whose core
  is not numbers (`latest`, `1.x`) cannot be ordered: `ferry pack` refuses it,
  and verify and import fail it as `policy.rollback`, even with
  `--allow-downgrade`. (Revised 2026-10-30: the earlier text-wise comparison
  of non-numeric parts ranked `v10` below `v9`.)
- On import of bundle (name N, version V, id B):
  - If any imported bundle named N has a version greater than V, reject with
    check `policy.rollback` ("1.2.0 of N is already imported; refusing to import
    older 1.1.0"). A host-only override `ferry import --allow-downgrade` exists
    and is audited with `details.allow_downgrade = true`.
  - If N at version V was already imported with a different bundle id, reject
    with check `policy.version_reuse` (same name and version but different
    content is a red flag, never an update).
  - Same id again stays idempotent.
- `verify` (standalone) reports these checks as `skip` because it has no
  history; `verify` with a data dir reports them.

## A2. Offline rehearsal on the connected side (`ferry rehearse`)

Basis: docs/research/06. The best-documented practitioner pain is a bundle that
is incomplete or still reaches for the network. It is found only inside the
enclave, after a transfer that costs a full review cycle. A rehearsal finds it
before the media is written.

`ferry rehearse BUNDLE --trust-dir D [--runtime llama-server] [--prompt TEXT] [--json] [--out report]`

1. Create a temporary data dir. Verify and import the bundle with the given
   trust dir and the default import policy (same code path as the real import).
2. For each imported GGUF model, start `llama-server` on the imported store file
   with `--offline --no-webui --host 127.0.0.1` and a random port and token,
   inside an OS network sandbox when one is available:
   - macOS: `sandbox-exec` with a profile that denies all network except loopback.
   - Linux: `unshare --net --map-root-user` (no network namespace = no egress).
   - Otherwise run without isolation and say so in the report.
3. Prove the sandbox actually blocks egress by running a probe in the same
   sandbox (a TCP connect to a public address must fail).
4. Wait for `/health`, send one chat completion, record build info, load time,
   latency and token counts. Never record the completion text.
5. Report (JSON + Markdown, attachable to the transfer request):
   `{report_version, verdict: pass|fail, bundle_id, verification_verdict,
   isolation: {mechanism, egress_blocked, probe}, runtime: {binary, build_info},
   models: [{name, digest, load_seconds, latency_ms, prompt_tokens,
   completion_tokens, ok, error}], started_at, finished_at, notes}`.

A pass shows this bundle, on this runtime build, served a completion with
egress blocked on this machine. It does not prove the same on different
hardware, a different runtime build or another OS.

## A3. GGUF byte accounting

Basis: docs/research/03 (GGUF overflow bugs recurring 2024 to 2026). Compute
each tensor's byte size from its ggml type (block size, bytes per block) with
checked arithmetic. Require tensors to be aligned, non-overlapping and inside
the data region. An unknown ggml type is a warning (size not checked), not a
rejection. Validate against the real Qwen2.5 Q4_K_M file before enabling.

## A4. Roadmap (not v1)

- DSSE/in-toto Statement v1 attestation output, and OMS (OpenSSF Model Signing)
  verification of upstream signatures such as NVIDIA NGC's at pack time.
- P-256 and PKCS#11/HSM signing keys for customers whose crypto policy needs
  them. Note that Ed25519 is approved in FIPS 186-5, but FIPS 140-3 depends on
  the validated module that is actually used.
- Signed import receipts from a site key.
