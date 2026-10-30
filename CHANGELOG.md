# Changelog

## 0.1.0 (2026-10-29)

First working version. Verified on macOS (Apple Silicon) only; see
`docs/limitations.md` for what is untested.

- `ferry preflight`: runs any launch command inside an OS network sandbox,
  proves egress is blocked, collects blocked connection attempts, attributes
  network calls made by Python code to the responsible library, and maps them
  to documented offline fixes.
- `ferry pack`, `sign`, `inspect`, `verify`, `import`: deterministic signed
  bundles (Ed25519 over the manifest), review sheet for the transfer reviewer,
  fail-closed verification (signatures before parsing, exact inventory,
  content-based format detection, pickle and executable rejection, GGUF and
  safetensors structure checks, licence allow-list, rollback and version-reuse
  protection), content-addressed store.
- `ferry rehearse`: imports a bundle into a throwaway store and serves each
  GGUF model with llama-server inside the sandbox.
- Receiving side: OpenAI-compatible gateway with API keys and a default-deny
  policy, provenance check that llama-server serves the imported file,
  hash-chained audit log with signed checkpoints, evidence report, host
  doctor, web console with admin and auditor roles.
- Internal adversarial review: 21 findings fixed (`docs/security-review.md`).
- Deployment assets, untested on a real host: offline wheelhouse installer,
  systemd units, GitHub Actions workflow.
