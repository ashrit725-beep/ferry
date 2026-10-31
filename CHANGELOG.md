# Changelog

## Unreleased: console redesign (2026-10-30)

The operator console is rebuilt as the enclave's pre-flight checklist. Pages,
hash routes, API calls, actions and the admin/auditor split are unchanged; the
design is recorded in `PRODUCT.md` and `DESIGN.md`.

- Overview opens with the bundle lifecycle: packed and signed on the connected
  side, then verified, imported and serving with live counts, and an amber
  marker for bundles waiting in the inbox. Below it, Enclave readiness lists
  trusted signing keys, imported bundles, the inbox, backends, routes with
  verified provenance, the active policy, API keys and the audit chain as
  checklist lines: item, dotted leader, stamped state. Lines that need
  attention come first (failed, then pending in amber), and the primary action
  sits on the first open line ("Verify 1 bundle in the inbox"). Gateway
  requests, success rate, denied requests and p50 latency for the last 24 hours
  sit beside it.
- The audit chain line states what the last check covered ("Checked #1-20")
  and asks for a recheck when events were added after it, instead of stamping
  the whole log intact; the overview's `last_verify` now carries `head_seq`
  and `seq` for this.
- Tables stack into label and value rows below 768 px and keep every row
  action visible at laptop widths.
- Command palette (Cmd-K or Ctrl-K, or the field in the top bar): go to a page,
  open a bundle by its full id or first 12 digits, open a verification by
  number, refresh, sign out.
- Toasts report finished imports and verifications (failures stay until
  dismissed), backend checks, a new backend or route, and policy activation.
  The top bar counts running jobs, and job progress is announced to screen
  readers.
- Dark scene: charcoal-navy ground, a deep-blue rail that shows the gateway
  (serving state, backends healthy, host, local time) on every page, bone-white
  type, hairline panels. Amber is the one attention colour; green, red and blue
  appear only where they carry state. Archivo Variable for the interface, Azeret
  Mono for digests, ids, paths and times, tabular numerals throughout. State
  changes take 150 to 250 ms; the lifecycle beam and the sign-in dot field are
  the only ambient motion, and `prefers-reduced-motion` makes them still. A
  light theme is not part of this release.
- Models draws routes and their provenance as a route map. Bundle detail
  keeps the full recorded verification report behind a disclosure instead of
  repeating the checks, signers and artifacts. Every page has a visible amber
  focus ring and one heading that takes focus on navigation; icon buttons have
  40 px hit areas; every state is stamped with a word as well as a colour.
- Still offline under the same CSP: fonts ship as files (Archivo Variable and
  Azeret Mono replace IBM Plex), Sonner's runtime `<style>` injection is
  stripped at build time, and the build fails on any off-origin reference.
  The built console is 898 KiB of JS (276 KiB gzipped, one chunk), 140 KiB of
  CSS and 207 KiB of fonts; the previous console was 380 KiB of JS and 31 KiB
  of CSS.
- Dependencies added, all pinned exactly and installed without scripts:
  `@base-ui/react`, `class-variance-authority`, `cmdk`, `cn`, `lucide-react`,
  `motion`, `sonner`, `@fontsource-variable/archivo`, `@fontsource/azeret-mono`;
  for the build only, `tailwindcss`, `@tailwindcss/vite`, `tw-animate-css` and
  `shadcn`. The two `@fontsource/ibm-plex-*` packages are removed. Each package
  is reviewed in `docs/network-dependencies.md`.
- Tests: `web/tests/test_static_build.py` (24 tests) now expects the new package
  set, the Archivo and Azeret Mono files, Sonner's rules in the built CSS rather
  than an injected `<style>`, and a size budget sized for the new stack; the
  vendored shadcn and effect components may set CSS variables through the style
  prop, every other source rule still applies to them. The console unit tests pass
  (136, four of them new, for how much of the audit chain a recorded check
  covers).

## Unreleased: correctness and security fixes (2026-10-30)

A second review pass over the Python package and CLI found 44 defects; all are
fixed or recorded, each fix with a test. The full list, with how each finding
was reproduced, is in `docs/reviews/quality-pass-2026-10-30.md`; the
security-relevant ones are summarised in `docs/security-review.md`.

- Verification and import: a GGUF that is also a pickle is refused; rollback
  protection orders versions semver-style (`v10` after `v9`, pre-releases
  before their release) and runs inside the transaction that registers the
  bundle, so concurrent imports cannot both pass; re-import re-hashes a store
  file that is already present and replaces a corrupted one; tar extended
  headers are bounded before any size check; GGUF checks match llama.cpp
  (63-byte tensor names, contiguous tensor data); more archive formats are
  detected inside bundles; a trust store owned by another user trusts nothing.
- Gateway: the login throttle counts attempts in flight, so parallel guesses
  cannot exceed it; `X-Forwarded-For`/`-Proto` are ignored unless the peer is
  listed in the new `[server] trusted_proxies`; policy validation is bounded;
  a streamed completion is withheld unless its new
  `gateway.chat.stream_opened` audit event commits; expired console sessions
  are purged.
- CLI and operations: `ferry pack` refuses a version rollback protection cannot
  order; backups and audit checkpoints are recorded only after the file exists,
  and backups check every file against its digest; a restored `ferry.toml`
  points at the restored data; `preflight` and `rehearse` check their output
  paths before running; integrity refusals exit 1 (rejected), not 2;
  multi-gigabyte hashing shows progress; a killed import's staging files are
  cleaned up.
- Performance: the Evidence page no longer re-verifies the whole audit chain on
  every view, and new audit indexes keep the Overview's traffic summary and the
  audit filters off full table scans.
- To know before upgrading: a schema migration (v2) adds the audit indexes;
  a reverse proxy must now be listed in `trusted_proxies`; bundle versions need
  a numeric core (`latest` and `1.x` are refused); streamed requests write one
  extra audit event.

## Unreleased (branch production-hardening)

- `ferry backup` and `ferry restore`: plain-tar backups with a SHA-256
  manifest of every member, database snapshotted online; restore verifies
  everything before putting it in place and checks the restored audit chain.
- Linux network isolation now tries candidates in order (root `unshare --net`,
  unprivileged `unshare`, `bwrap --unshare-net`), self-tests each, and fails
  closed with the reasons when none works. Still not executed on a Linux host.
- Preflight and rehearsal no longer compare mechanism names; `--ready-url` and
  `--request-url` must be http(s) URLs.
- Audit readers and the export survive tampered `details` rows and mark them;
  policy validation caps warnings at 200; `/api/bundles`, `/api/apps` and
  `/api/models` take `limit`; the header-less pickle scan also covers files
  that parse as safetensors.
- Manifest/record pairings use `zip(strict=True)`; a rehearsal reports a runner
  that returned results for the wrong number of models.
- `deploy/requirements.lock` pins the dependency closure; the offline installer
  uses it as a constraints file.
- Console: `npm ci && npm run build` reproduces the committed `ferry/static`
  byte for byte.

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
