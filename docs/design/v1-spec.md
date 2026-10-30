# Ferry v1 implementation spec

Status: engineering contract for v1 (2026-10-28). Implementation agents build
against this document; where code and this spec disagree, fix one of them
deliberately. User-facing docs live elsewhere in `docs/`.

## 1. What v1 does

One end-to-end workflow for moving an open-weight model into a disconnected
network and serving it under policy:

1. **Connected side**: `ferry pack` turns a TOML spec (model files, licence,
   upstream provenance) into a deterministic, signed bundle (`*.ferry.tar`) plus
   a human-readable review sheet for the person who approves the transfer.
2. **Review**: a second person can check integrity and countersign with
   `ferry sign` (separate key, separate role).
3. **Transfer**: the operator's approved process (media, diode, etc.). Ferry
   does not move bytes across the gap.
4. **Disconnected side**: `ferry verify` / `ferry import` check structure,
   signatures against a local trust store and role policy, every digest, file
   formats (no pickle, no executables), licences and limits. A failure rejects
   the bundle with reasons. An accepted bundle is copied into a
   content-addressed store and recorded.
5. **Serve**: the gateway exposes an OpenAI-compatible API. Apps authenticate
   with API keys. A deterministic, default-deny policy decides which app may
   use which model before anything reaches the inference backend (llama.cpp,
   Ollama or any OpenAI-compatible server on a private address). For llama.cpp
   the gateway confirms the backend is serving the exact imported file.
6. **Evidence**: security-relevant outcomes go to a hash-chained audit log. An
   evidence report summarises trust anchors, imports, policy versions, model
   provenance and audit-chain status.

Out of scope for v1: Kubernetes, container image transport, multi-site fleet
management, SSO/LDAP, delta updates, GPU scheduling, prompt logging.

## 2. Ground rules for all code

- Python >= 3.11 (develop on 3.14). No syntax newer than 3.11. Type hints everywhere.
- Runtime deps are only: fastapi, uvicorn, httpx, cryptography, pydantic. Adding a
  dependency needs a written reason in docs/network-dependencies.md. Stdlib otherwise.
- **No network access** except (a) the gateway's inbound listener and (b) outbound
  requests to backends explicitly configured by an admin. No telemetry, update
  checks, licence checks, CDN assets, or fallbacks to public AI providers.
  `httpx` clients are created with `trust_env=False` and `follow_redirects=False`.
- Never log or store prompts, completions, API keys, passwords, session tokens or
  private keys. Audit details go through `ferry.audit.sanitize` (it redacts keys
  such as `messages`, `content`, `prompt`, `api_key`, `password`, `token`, `authorization`).
- Never execute, import, unpickle or `eval` anything from a bundle. Never call
  `tarfile.extract*`; read member bytes and write them where *we* choose.
- Security decisions are deterministic code. Never use an LLM to decide authorization.
- Errors shown to users are specific and actionable but contain no secrets.
- Timestamps: RFC 3339 UTC with milliseconds via `ferry.util.rfc3339()`.
- All DB writes go through `ferry.db.write_tx(conn)` (BEGIN IMMEDIATE). Open a
  connection per request/command via `Database.session()` / `Database.connect()`.
- Every state-changing operation appends exactly one audit event (in the same
  transaction where the operation itself writes to the DB).

### Foundation modules (already implemented; read the code)

| Module | Provides |
|---|---|
| `ferry/util.py` | `utc_now`, `rfc3339`, `parse_rfc3339`, `canonical_json`, `sha256_hex`, `new_event_id`, `ensure_private_dir`, `atomic_write` |
| `ferry/errors.py` | `FerryError(message, code=, details=)`, `ConfigError`, `NotFound`, `Conflict`, `ValidationFailed`, `CryptoError`, `PermissionDenied` |
| `ferry/config.py` | `Settings` (+ `ServerSettings`, `GatewaySettings`, `ImportSettings`), `load_settings`, `validate`, `default_config_toml`, constants `SIGNER_ROLES`, `ARTIFACT_KINDS`, `MODEL_FORMATS` |
| `ferry/db.py` | schema v1 (see the SQL), `Database(path).init()/connect()/session()`, `write_tx`, `migrate` |
| `ferry/audit.py` | `append_event`, `verify_chain`, `head`, `make_checkpoint`, `verify_checkpoint_signature`, `query_events`, `get_event`, `facets`, `export_jsonl`, `sanitize` |
| `ferry/crypto.py` | Ed25519: `write_keypair`, `load_private_key_file`, `load_public_key_file`, `load_public_key_pem`, `public_key_to_pem`, `key_id`, `short_id`, `sign`, `verify` |

Audit vocabulary (use these action names): `auth.login`, `auth.logout`,
`gateway.chat.completions`, `gateway.models.list`, `bundle.verify`,
`bundle.import`, `bundle.sign`, `bundle.pack`, `policy.activate`,
`principal.create`, `principal.update`, `api_key.create`, `api_key.revoke`,
`backend.create`, `backend.update`, `backend.delete`, `backend.health`,
`route.create`, `route.update`, `route.delete`, `trust.add`, `trust.revoke`,
`admin.user_create`, `audit.verify`, `audit.export`, `audit.checkpoint`,
`store.verify`, `system.start`. Outcomes are limited to `audit.OUTCOMES`.
Actor types: `admin` (console user), `app` (API key principal), `cli` (local OS
user, `getpass.getuser()`), `system`.

## 3. Repository layout and ownership

```
ferry/
  __init__.py util.py errors.py config.py db.py audit.py crypto.py   foundation (done)
  formats.py manifest.py trust.py                                    bundle agent
  bundle/__init__.py reader.py pack.py verify.py importer.py store.py bundle agent
  policy.py auth.py backends.py                                      gateway agent
  gateway/__init__.py state.py limits.py openai_api.py               gateway agent
  gateway/app.py gateway/admin_api.py gateway/jobs.py gateway/security.py   app agent
  evidence.py doctor.py runtime.py cli.py                            app agent
  static/                                                            web agent (build output)
web/                                                                 web agent
tests/                                                               each agent: own files only
docs/                                                                docs agent / integration
```

Test files are owned by prefix: bundle agent `test_formats.py`, `test_manifest.py`,
`test_trust.py`, `test_bundle_*.py`; gateway agent `test_audit.py`,
`test_crypto.py`, `test_policy.py`, `test_auth.py`, `test_backends.py`,
`test_gateway_*.py`; app agent `test_app_*.py`, `test_cli*.py`, `test_e2e_*.py`,
`test_evidence.py`, `test_doctor.py`, `test_offline*.py`. Shared helpers go in
`tests/helpers_<area>.py`. Do not edit `tests/conftest.py` (fixtures:
`data_dir`, `settings`, `database`, `conn`).

## 4. Bundle format v1

A bundle is an uncompressed POSIX tar (PAX format) named
`<name>-<version>.ferry.tar`. It stays a plain tar on purpose: transfer stations
and malware scanners can open it.

Members:

| Member | Content |
|---|---|
| `manifest.json` | UTF-8 JSON (below). Written first. <= `max_manifest_bytes`. |
| `signatures/<key_id>.sig` | Raw 64-byte Ed25519 signature over the **exact bytes** of `manifest.json`. `key_id` = lowercase hex SHA-256 of the raw 32-byte public key. More may be appended later (`ferry sign`). |
| `artifacts/<path>` | Every file listed in the manifest, nothing else. |

Packing normalizes members: regular files only, mode 0644, uid/gid 0, empty
uname/gname, mtime = manifest `created_at` (integer seconds), sorted artifact
order after manifest and signatures. Given the same inputs and `--created-at`,
the tar is byte-identical.

Bundle identity: `bundle_id = "sha256:" + sha256(manifest.json bytes)`. It does
not change when countersignatures are appended.

### manifest.json (schema `ferry.dev/bundle-manifest/v1`)

```json
{
  "schema": "ferry.dev/bundle-manifest/v1",
  "bundle": {
    "name": "qwen2.5-0.5b-instruct",
    "version": "1.0.0",
    "created_at": "2026-10-28T02:00:00.000Z",
    "description": "Qwen2.5 0.5B Instruct, Q4_K_M GGUF, for llama.cpp"
  },
  "producer": {"tool": "ferry", "tool_version": "0.1.0"},
  "requires": {
    "ferry_min_version": "0.1.0",
    "runtime": "llama.cpp",
    "runtime_min_version": null,
    "min_memory_bytes": 1073741824
  },
  "artifacts": [
    {
      "path": "artifacts/models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
      "size": 491400032,
      "sha256": "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db",
      "kind": "model",
      "format": "gguf",
      "model": {
        "name": "qwen2.5-0.5b-instruct",
        "license": "Apache-2.0",
        "source_uri": "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF",
        "source_revision": "9217f5db79a29953eb74d5343926648285ec7e67",
        "upstream_sha256": "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
      },
      "metadata": {"gguf": {"version": 3, "architecture": "qwen2", "name": "...", "file_type": "MOSTLY_Q4_K_M", "context_length": 32768, "tensor_count": 290, "parameter_count": 494032768}}
    },
    {"path": "artifacts/docs/LICENSE", "size": 11343, "sha256": "...", "kind": "document", "format": "text", "metadata": {}}
  ]
}
```

Field rules (enforced by `ferry/manifest.py`, strict: unknown keys rejected):

- `bundle.name`: `^[a-z0-9][a-z0-9._-]{0,63}$`. `bundle.version`: `^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`.
  `created_at`: RFC 3339 with timezone. `description` <= 2000 chars.
- `requires.ferry_min_version`: dotted numeric (`^\d+(\.\d+){0,2}$`); compare numerically.
  `runtime`: optional string <= 64; `min_memory_bytes`: optional int >= 0.
- `artifacts`: 1..`max_artifacts` items; `path` unique (also case-insensitively),
  must match `^artifacts/[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`, <= 255 chars.
- `size`: int 0..`max_artifact_bytes`; `sha256`: `^[0-9a-f]{64}$`.
- `kind` in `ARTIFACT_KINDS`; `format` in `gguf, safetensors, pickle, json, text, binary, executable, archive`.
- `model` object required iff `kind == "model"`: `name` `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
  `license` SPDX-style id, optional `source_uri` (<= 2048), `source_revision` (<= 128),
  `upstream_sha256` (64 hex).
- `metadata`: object, informational (recomputed at verify time; never trusted for decisions).

### Format detection (`ferry/formats.py`, content-based, never trusts names)

`detect_format(fileobj, size, name) -> FormatInfo(format, metadata, problems)`

- **gguf**: magic `GGUF`; version uint32 LE in {2, 3}; then tensor_count uint64,
  kv_count uint64, KV pairs (key: uint64 len + UTF-8; value_type uint32; value),
  then tensor infos (name, n_dims uint32, dims uint64[], ggml type uint32, offset uint64).
  Value types: 0 u8, 1 i8, 2 u16, 3 i16, 4 u32, 5 i32, 6 f32, 7 bool, 8 string,
  9 array (elem type u32 + count u64 + elems), 10 u64, 11 i64, 12 f64.
  Bounded parsing (reject as malformed, never allocate from untrusted counts):
  kv_count <= 65536, tensor_count <= 1,000,000, string len <= 16 MiB, key len <= 65535,
  array count <= 16,000,000, array nesting <= 2, n_dims 1..4, each dim >= 1,
  element-count product < 2^63, ggml type < 64, tensor names unique and <= 64 bytes,
  total header bytes parsed <= 256 MiB, every tensor offset < (file size - data start),
  offsets multiple of `general.alignment` (default 32). Extract: `version`,
  `architecture` (`general.architecture`), `name` (`general.name`), `file_type`
  (`general.file_type` mapped to llama ftype names, e.g. 15 -> `MOSTLY_Q4_K_M`,
  unknown -> `type_<n>`), `context_length` (`<arch>.context_length`),
  `tensor_count`, `parameter_count` (sum of element counts), `license` (`general.license` if present).
- **safetensors**: 8-byte LE header length N (8 <= N <= 100 MiB, N + 8 <= size);
  header is a UTF-8 JSON object starting with `{`; each non-`__metadata__` entry
  has `dtype` (known set: F64 F32 F16 BF16 I64 I32 I16 I8 U8 BOOL F8_E4M3 F8_E5M2 U16 U32 U64),
  `shape` (ints >= 0), `data_offsets` [begin, end] with begin <= end,
  end - begin == product(shape) * dtype size, offsets within the data region,
  no overlaps, and the entries cover the whole data region with no gaps.
  `__metadata__` must be a str->str map. Extract tensor count, parameter count, dtypes.
- **pickle**: raw pickle (first byte 0x80, protocol byte 2..5); a header-less
  (protocol 0/1) stream that a static opcode scan of the first MiB, tracking stack
  and MARK depth, shows reaching GLOBAL/INST/STACK_GLOBAL (also after a STOP, and
  fail-closed when the window ends mid-stream); or a ZIP whose member
  names include `data.pkl` or end in `.pkl` (torch.save format), or extension in
  `.pkl .pickle .pt .pth .ckpt .joblib` with non-safetensors/non-gguf content.
  Listing ZIP member names via `zipfile` is fine; never read or unpickle members.
- **executable**: ELF (`\x7fELF`), Mach-O (feedface/feedfacf/cefaedfe/cffaedfe, fat cafebabe),
  PE (`MZ`), shebang (`#!`), or extensions `.sh .bash .py .ps1 .bat .cmd .exe .dll .so .dylib .bin.exe`.
- **archive**: ZIP (non-pickle), gzip `1f8b`, tar (`ustar` at offset 257), xz, zstd, bzip2, 7z.
- **json**: UTF-8 and parses as JSON (only attempt for files <= 64 MiB).
- **text**: first 1 MiB decodes as UTF-8 without NUL bytes.
- **binary**: anything else.

### Verification (`ferry/bundle/verify.py`)

`verify_bundle(source: Path, settings: ImportSettings-like policy, trust: TrustStore, *, now=None, full=False, progress=None, sink=None) -> VerificationReport`

`source` is a tar file or an extracted directory (`BundleReader` abstraction in
`reader.py`: `TarBundleReader` uses `tarfile.open(path, "r:")` random access and
`extractfile`; `DirBundleReader` walks with `os.lstat`, rejects symlinks).
`sink`, when given, receives each artifact's bytes while they are hashed (the
importer uses it to stage files so imported bytes are exactly the hashed bytes).

Checks run in this order; each produces a check record. Stop after the first
failing *structural or signature* group unless `full=True`.

| Check id | Fails when |
|---|---|
| `archive.readable` | not a tar/dir, compressed tar, truncated/corrupt tar |
| `archive.members` | any member that is not a regular file or directory: symlink, hardlink, device, FIFO, sparse; more than `max_artifacts + 64` members |
| `archive.paths` | absolute paths, `..`, backslashes, NUL, empty components, names outside `manifest.json`, `signatures/<64hex>.sig`, `artifacts/...` |
| `archive.duplicates` | duplicate member names (also case-insensitive) |
| `archive.limits` | total size > `max_bundle_bytes` or any member > `max_artifact_bytes` |
| `manifest.present` | missing `manifest.json` or larger than `max_manifest_bytes` |
| `signatures.valid` | a signature file is not exactly 64 bytes; a signature from a trusted key does not verify (treat as tampering); report untrusted, revoked, expired, not-yet-valid keys individually |
| `signatures.roles` | `required_roles` not each satisfied by a valid signature from an active trusted key holding that role (with `distinct_signers`, one key cannot satisfy two roles) |
| `manifest.schema` | JSON or schema invalid (parse only after signature checks) |
| `compat.ferry_version` | `ferry_min_version` > installed version |
| `inventory.missing` | listed artifact not present |
| `inventory.extra` | artifact member present but not listed |
| `artifact.size` | member size != manifest size |
| `artifact.digest` | SHA-256 mismatch |
| `artifact.format` | detected format != declared format, or malformed GGUF/safetensors |
| `policy.kinds` | kind not in `allowed_kinds` |
| `policy.formats` | model format not in `allowed_model_formats` |
| `policy.pickle` | any pickle content and `allow_pickle` is false |
| `policy.executables` | any executable and `allow_executables` is false |
| `policy.archives` | any nested archive unless kind is `file` and `file` is allowed |
| `policy.licenses` | model licence not in `allowed_licenses` |
| `compat.memory` | warn only: host memory < `min_memory_bytes` |

Report (JSON-serializable dict, `report_version: 1`):

```json
{
  "report_version": 1,
  "verdict": "accepted",
  "bundle_id": "sha256:...",
  "bundle": {"name": "...", "version": "...", "created_at": "..."},
  "source": {"name": "qwen2.5-0.5b-instruct-1.0.0.ferry.tar", "type": "tar", "size": 491427840},
  "verified_at": "...", "tool_version": "0.1.0",
  "policy": {"required_roles": ["publisher", "reviewer"], "...": "effective import policy"},
  "signatures": [{"key_id": "...", "name": "...", "roles": ["publisher"], "status": "valid", "detail": ""}],
  "artifacts": [{"path": "...", "kind": "model", "declared_format": "gguf", "detected_format": "gguf",
                  "size": 1, "expected_sha256": "...", "actual_sha256": "...", "status": "ok", "detail": "", "metadata": {}}],
  "checks": [{"id": "signatures.roles", "status": "pass", "message": "..."}],
  "errors": ["human-readable reason", "..."],
  "warnings": []
}
```

`status` values: signatures `valid|invalid|untrusted|revoked|expired|not_yet_valid|malformed`;
artifacts `ok|mismatch|missing|malformed|rejected|skipped`; checks `pass|fail|warn|skip`.
CLI exit codes: 0 accepted, 1 rejected, 2 usage/IO/config error.

### Trust store (`ferry/trust.py`)

A directory of `<key_id>.json` files (dir 0755 owner-writable, files 0644 via `atomic_write`):

```json
{"key_id": "<64 hex>", "name": "Acme low-side build", "roles": ["publisher"],
 "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...", "not_before": null, "not_after": "2027-10-28T00:00:00.000Z",
 "revoked_at": null, "revocation_reason": null, "added_at": "...", "comment": ""}
```

On load, recompute the key id from the PEM; an entry whose file name, `key_id`
and computed id disagree is ignored and reported as a problem. Status at time
`now`: `revoked` > `not_yet_valid` > `expired` > `active`. API:
`load_trust_store(dir) -> TrustStore` (`.entries`, `.problems`, `.get(key_id)`, `.find(prefix)`),
`add_key(dir, pem_bytes, *, name, roles, not_before=None, not_after=None, comment="", expect_fingerprint=None)`
(refuses duplicates; if `expect_fingerprint` is given it must be a prefix (>= 16 hex) of the key id),
`revoke_key(dir, key_id_or_prefix, reason)`. Trust changes are host-only: CLI, never the web API.

### Pack spec (`ferry pack SPEC.toml`)

```toml
[bundle]
name = "qwen2.5-0.5b-instruct"
version = "1.0.0"
description = "..."

[requires]
ferry_min_version = "0.1.0"
runtime = "llama.cpp"
min_memory_bytes = 1073741824

[[artifacts]]
source = "models/qwen2.5-0.5b-instruct-q4_k_m.gguf"   # relative to the spec file
path = "models/qwen2.5-0.5b-instruct-q4_k_m.gguf"     # inside artifacts/
kind = "model"
[artifacts.model]
name = "qwen2.5-0.5b-instruct"
license = "Apache-2.0"
source_uri = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF"
source_revision = "9217f5db79a29953eb74d5343926648285ec7e67"
upstream_sha256 = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"

[[artifacts]]
source = "models/LICENSE"
path = "docs/LICENSE"
kind = "document"
```

`pack_bundle(spec_path, signing_key, out_dir, *, created_at=None, progress=None) -> PackResult`
hashes every source, detects formats, refuses formats the default import policy
would reject (pickle/executables) unless `--allow-unsafe` is passed (prints a loud
warning), fails if `upstream_sha256` is given and does not match, builds the
manifest, signs it, writes the tar, and writes two sidecars next to it:
`<bundle>.ferry.tar.sha256` (sha256sum format) and `<bundle>.review.md`, a
review sheet for the transfer reviewer: bundle id, tar digest, signer key ids,
artifact table (path, kind, format, size, sha256, licence, source), flags (pickle,
executables, archives: none), and instructions for checking the signature with
OpenSSL and the digests with `sha256sum`/`shasum -a 256`, independent of Ferry.

`sign_bundle(bundle_path, signing_key) -> SignResult` (countersign): runs the full
integrity pipeline without trust/role checks (structure, schema, inventory,
digests, formats); refuses if anything fails or if this key already signed;
appends `signatures/<key_id>.sig` (tar `"a"` mode, same normalization) or writes
the file for a directory bundle; rewrites the `.sha256` sidecar if present.

### Import and store (`ferry/bundle/importer.py`, `store.py`)

Store: `<data_dir>/store/sha256/<64hex>` (files 0444), staging in
`<data_dir>/store/tmp/`. `import_bundle(settings, database, source, *, actor_type, actor_id, progress=None) -> ImportResult`:

1. Verify with a sink that stages each artifact while hashing.
2. Rejected: delete staged files; insert a `verifications` row (`mode='import'`,
   `verdict='rejected'`) and audit `bundle.import` outcome `rejected` with the
   error list; return the report.
3. Accepted: move staged files into the store (`os.replace`; if the digest file
   already exists keep the existing one), then in one `write_tx`: insert
   `bundles` (if `bundle_id` already exists, do not duplicate; report
   `already_imported: true`), `artifacts` (INSERT OR IGNORE), `bundle_artifacts`,
   a `verifications` row and audit `bundle.import` outcome `success` with
   bundle id/name/version, signer key ids and artifact digests.

`verify_only(...)` records a `verifications` row (`mode='verify'`) and audit
`bundle.verify` (outcome `accepted`/`rejected`). `store.verify_store(settings)`
re-hashes every store file and reports mismatches (audit `store.verify`).
`store.path_for(settings, digest)` and `store.digest_for_path(settings, path)`
(returns the digest when `path` resolves to a file inside the store, else None).

## 5. Access policy v1 (`ferry/policy.py`)

```json
{
  "schema": "ferry.dev/access-policy/v1",
  "description": "Pilot policy",
  "rules": [
    {"id": "report-assistant-chat", "effect": "allow",
     "principals": ["app:report-assistant"], "actions": ["chat.completions"],
     "models": ["qwen2.5-0.5b-instruct"], "limits": {"max_tokens": 512, "allow_stream": true}},
    {"id": "no-experimental", "effect": "deny",
     "principals": ["*"], "actions": ["*"], "models": ["experimental-*"]}
  ]
}
```

- Principals: `app:<name>`, `app:*`, `*`. Actions: `chat.completions`, `*`.
  Models: exact name, `*`, or a trailing-wildcard prefix `foo-*`. Rule ids
  `^[a-z0-9][a-z0-9_-]{0,63}$`, unique. Lists non-empty. `limits` only on allow
  rules; `max_tokens` int 1..1,000,000 or absent; `allow_stream` bool (default true).
  Unknown keys are errors. Default effect is deny; there is no way to change it.
- Evaluation of (principal, action, model): matching rules = all three match.
  Any matching deny -> **deny** (decisive = first matching deny in document order).
  Else any matching allow -> **allow**; limits are the most permissive across
  matching allows (no `max_tokens` on any matching allow = no policy cap;
  `allow_stream` true if any is true). Else **deny** with reason "no rule allows".
  No active policy -> deny everything.
- `validate_policy(doc, known_apps=None, known_models=None) -> {valid, errors: [{path, message}], warnings: [{rule_id, message}]}`.
  Warnings (not errors): unknown app names, models with no route, allow rules
  granting `*` to `*`, rules fully shadowed by an earlier deny.
- `evaluate(compiled, principal=, action=, model=) -> Decision{allowed, decisive_rule, matched_rules[{id, effect}], reason, limits{max_tokens, allow_stream}, policy_version, policy_sha256}`.
- Storage: `activate_policy(conn, doc, actor_type=, actor_id=, comment="") -> {version, sha256}`
  validates (errors block activation), stores canonical JSON + sha256 as the next
  version, sets `active_policy`, audits `policy.activate`. Rolling back = activating
  an old document as a new version. `get_active_policy(conn)`, `policy_history(conn)`.
- Effective `max_tokens` sent upstream = min(request value if any, policy cap if
  any, `gateway.max_tokens_ceiling`). A request for streaming when `allow_stream`
  is false is denied.

## 6. Identity

- **API keys** (apps): `fyk_<12 lowercase hex key id>_<43-char base64url secret>`
  from 32 random bytes. Store `sha256_hex(secret)`; compare with
  `hmac.compare_digest`. Shown once at creation. `Authorization: Bearer <key>`.
  Failure reasons (audited, never returned in detail to the caller): malformed,
  unknown_key, bad_secret, revoked, expired, principal_disabled. Update
  `last_used_at` at most once per minute per key.
- **Principals**: `name` `^[a-z0-9][a-z0-9_-]{0,63}$`, `environment` in
  test/pilot/production (lets metrics separate test traffic from pilot/production).
- **Admin users** (console): created only by CLI on the host. Password >= 12
  chars, `hashlib.scrypt` (n=2**15, r=8, p=1, 16-byte salt, maxmem 64 MiB), stored
  `scrypt$32768$8$1$<b64 salt>$<b64 hash>`. Roles: `admin` (everything) and
  `auditor` (read-only: GET endpoints plus `POST /api/audit/verify`,
  `POST /api/policy/validate`, `POST /api/policy/explain`).
- **Sessions**: 32-byte `secrets.token_urlsafe`, cookie `ferry_session`
  (HttpOnly, SameSite=Strict, Path=/, Secure per `cookie_secure`; `auto` = Secure
  unless the request is plain HTTP to a loopback host). DB stores
  `sha256_hex(token)`. Idle timeout `session_idle_minutes`, absolute
  `session_max_hours`.
- **CSRF**: every POST/PUT/PATCH/DELETE under `/api/` (including login) requires
  header `X-Ferry-CSRF: 1`; if an `Origin` header is present it must equal the
  request's own origin. Otherwise 403.
- **Login throttle** (in memory): 5 failures per username in 15 min, or 20 per
  client IP, lock for 15 min -> 429 with `retry_after_s`.

## 7. Backends, routes, provenance (`ferry/backends.py`)

- Kinds: `llamacpp`, `ollama`, `openai` (any OpenAI-compatible server such as vLLM).
- `base_url`: `http`/`https`, host required, no userinfo, no query/fragment, path
  empty or `/`. Egress guard `check_backend_url(url, allow_public=False)`:
  resolve the host (`socket.getaddrinfo`); every address must be loopback or
  private (`ip.is_loopback` or (`ip.is_private` and not `ip.is_link_local`)),
  never link-local (blocks 169.254.169.254), multicast, unspecified or reserved.
  6to4 (`2002::/16`) and Teredo (`2001::/32`) count as public although
  `is_private` is true for them: they are relayed over the public IPv4 internet.
  Re-checked before each upstream request (cache resolutions 30 s). Public
  addresses only if `gateway.allow_public_backends = true` in ferry.toml.
- Backend credentials: optional `auth_token_file` (first line is a bearer token);
  read at request time; refuse files readable by group/other; never returned by
  any API (expose `has_token: true/false`).
- Health (`check_backend`): llamacpp `GET /health` (200 ready, 503 loading) +
  `GET /v1/models` + `GET /props` (`model_path`, `model_alias`, `build_info`);
  ollama `GET /api/version` + `GET /api/tags`; openai `GET /v1/models`.
  Status JSON: `{state: up|down|loading, checked_at, latency_ms, http_status,
  version, models: [ids], served: [{model_id, path, digest}], error}`; stored in
  `backends.last_status`. Audit `backend.health` only when `state` changes.
  Background loop every `health_interval_s`.
- Routes map a public model name to (backend, upstream model id, pinned artifact
  digest, `require_verified`). Provenance state: `verified` (backend reports a
  `model_path` inside the store whose digest equals the pin), `mismatch`
  (different digest), `unverified` (backend cannot prove what it serves, or it
  serves a file outside the store), `not_pinned`, `unknown` (backend down).
  `available` = route enabled, backend enabled and up, and (`require_verified`
  false or provenance `verified`). Observed fact: llama-server ignores the
  request's `model` field and answers with whatever it has loaded, so routing and
  authorization must be decided before the request reaches it.

## 8. Gateway API (OpenAI-compatible, `ferry/gateway/openai_api.py`)

- `GET /v1/models`: models with a route for which the caller's principal is
  allowed `chat.completions` (filtered by policy). OpenAI list shape.
- `POST /v1/chat/completions`: order is fixed: request id -> body size limit ->
  authenticate -> parse/validate -> **authorize** -> route/provenance check ->
  concurrency slot -> upstream call -> audit. Denied, invalid and unauthenticated
  requests never touch a backend.
- Accepted fields: `model` (required), `messages` (1..512; roles system, user,
  assistant, tool; content string or list of `{"type":"text","text":...}` parts),
  `stream`, `max_tokens`, `max_completion_tokens`, `temperature` (0..2), `top_p`
  (0..1), `stop` (str or <= 4 strs), `seed`, `presence_penalty`,
  `frequency_penalty` (-2..2), `n` (must be 1), `response_format`, `tools`,
  `tool_choice`, `user`. Other fields are dropped, not forwarded.
- Upstream request: `model` = route's upstream id, effective `max_tokens`, for
  streams `stream_options.include_usage = true`; header `Authorization: Bearer
  <backend token>` if configured. Responses (and every stream chunk that parses
  as JSON) get `model` rewritten to the public name.
- Errors use the OpenAI shape `{"error": {"message", "type", "code", "param": null}}`:
  400 `invalid_request_error`, 401 `authentication_error`, 403 `permission_denied`
  (message includes the decisive rule id or "no rule allows"), 404 `model_not_found`
  (no route), 413 `request_too_large`, 429 `rate_limit_error` (+ `Retry-After`),
  502 `backend_error`, 503 `backend_unavailable` (reason: down, provenance), 504 `timeout`.
  Every response carries `X-Request-ID` (accept a caller's value if it matches
  `^[A-Za-z0-9._-]{1,64}$`, else generate) and, when clamped, `X-Ferry-Max-Tokens: <n>`.
- Limits: global semaphore `gateway.max_concurrency` and per-backend
  `backends.max_concurrency`, waiting at most `queue_timeout_s`; timeouts from
  config/backend (`connect_timeout_s`, backend `timeout_s` for reads).
- One audit event per request: action `gateway.chat.completions`, actor `app`,
  resource `model:<name>`, outcome `success|denied|error|unavailable|rejected|unauthenticated`,
  details `{status_code, decision, decisive_rule, model, backend, route_id,
  artifact_digest, provenance, stream, max_tokens_requested, max_tokens_effective,
  prompt_tokens, completion_tokens, latency_ms, error_type}`, `policy_version` set.
  Never prompt or completion text.
- `ferry/gateway/state.py` defines `GatewayState` (settings, db, http client,
  limiter, policy cache, started_at) stored at `app.state.ferry`.
  `build_state(settings) -> GatewayState`; `PolicyCache.get(conn)` recompiles when
  `active_policy.version` changes.

## 9. Admin API (`ferry/gateway/admin_api.py`, JSON, prefix `/api`)

Conventions: session cookie auth; errors `{"error": {"code", "message", "details"?}}`;
lists `{"items": [...]}`; 401 not logged in, 403 role/CSRF, 404, 409 conflict,
422 validation. `Cache-Control: no-store` on all `/api` responses.

| Method & path | Role | Body / query | Response |
|---|---|---|---|
| POST /api/auth/login | - | `{username, password}` | `{user: {username, role}}` + cookie |
| POST /api/auth/logout | any | | 204 |
| GET /api/auth/me | any | | `{user: {username, role}}` |
| GET /api/overview | any | | see below |
| GET /api/inbox | any | | `{inbox_dir, items: [{name, type: tar|dir, size, modified_at, last_verification: {verdict, created_at, bundle_id}|null}]}` |
| POST /api/inbox/verify | admin | `{name}` | 202 `{job_id}` |
| POST /api/inbox/import | admin | `{name}` | 202 `{job_id}` |
| GET /api/jobs/{id} | any | | `{job_id, kind, source_name, state: queued|running|succeeded|failed, progress: {bytes_done, bytes_total}, started_at, finished_at, result: {verdict, bundle_id, report, already_imported}|null, error}` |
| GET /api/verifications | any | `limit` | `{items: [{id, source_name, bundle_id, bundle_name, bundle_version, verdict, mode, created_at, actor, error_count, warning_count}]}` |
| GET /api/verifications/{id} | any | | item + `report` |
| GET /api/bundles | any | | `{items: [{bundle_id, name, version, imported_at, imported_by, source_name, signers: [{key_id, name, roles}], artifact_count, total_bytes}]}` |
| GET /api/bundles/{bundle_id} | any | | bundle + `manifest`, `report`, `artifacts` |
| GET /api/trust | any | | `{trust_dir, required_roles, distinct_signers, items: [{key_id, name, roles, not_before, not_after, revoked_at, revocation_reason, status}], problems: [str]}` |
| GET /api/models | any | | `{items: [{digest, model_name, size, format, metadata, license, first_bundle_id, bundle_name, bundle_version, imported_at, routes: [model]}]}` |
| GET /api/backends | any | | `{items: [{id, name, kind, base_url, has_token, timeout_s, max_concurrency, enabled, last_status, last_checked_at}]}` |
| POST /api/backends | admin | `{name, kind, base_url, auth_token_file?, timeout_s?, max_concurrency?}` | 201 backend |
| PATCH /api/backends/{id} | admin | subset of the above + `enabled` | backend |
| DELETE /api/backends/{id} | admin | | 204, 409 if routes use it |
| POST /api/backends/{id}/check | admin | | `{status, checked_at}` |
| GET /api/routes | any | | `{items: [{id, model, backend_id, backend_name, upstream_model, artifact_digest, require_verified, enabled, provenance: {state, detail, served_digest}, available, reason}]}` |
| POST /api/routes | admin | `{model, backend_id, upstream_model, artifact_digest?, require_verified?}` | 201 route |
| PATCH /api/routes/{id} | admin | subset + `enabled` | route |
| DELETE /api/routes/{id} | admin | | 204 |
| GET /api/apps | any | | `{items: [{id, name, environment, description, disabled, created_at, keys: [{key_id, created_at, expires_at, revoked_at, last_used_at}]}]}` |
| POST /api/apps | admin | `{name, environment, description?}` | 201 app |
| PATCH /api/apps/{id} | admin | `{disabled?, description?, environment?}` | app |
| POST /api/apps/{id}/keys | admin | `{expires_in_days?}` | 201 `{key_id, api_key, expires_at}` (only time the secret is shown) |
| POST /api/keys/{key_id}/revoke | admin | | key |
| GET /api/policy | any | | `{active: {version, sha256, document, created_at, created_by, activated_at, activated_by, comment}|null, history: [{version, sha256, created_at, created_by, comment, active}]}` |
| GET /api/policy/{version} | any | | policy version incl. document |
| POST /api/policy/validate | admin, auditor | `{document}` | `{valid, errors, warnings}` |
| POST /api/policy/activate | admin | `{document, comment}` | 201 `{version, sha256}`; 422 `{error, validation}` |
| POST /api/policy/explain | admin, auditor | `{app, action, model}` | Decision + `{principal}` |
| GET /api/audit | any | `action, outcome, actor_id, actor_type, resource, correlation_id, q, since, until, before_seq, limit` | `{items: [event], next_before_seq}` |
| GET /api/audit/facets | any | | `{actions, outcomes, actor_types}` |
| GET /api/audit/{seq} | any | | event |
| POST /api/audit/verify | admin, auditor | | `verify_chain` result |
| GET /api/audit/export | any | | `application/x-ndjson` attachment |
| GET /api/evidence | any | | evidence JSON (section 10) |
| GET /api/evidence.md | any | | Markdown attachment |
| GET /api/system | any | | `{version, python, platform, config: settings.public_dict(), network_inventory, dependencies: [{name, version}]}` |
| GET /healthz | - | | `{status: "ok"}` (no auth, no details) |

`GET /api/overview` returns real counts only:
`{version, started_at, policy: {version, sha256, activated_at, rule_count}|null,
counts: {apps, active_keys, backends, routes, bundles, model_artifacts, trusted_keys},
backends: [{id, name, kind, state, checked_at}],
routes: [{model, backend, provenance, available, reason}],
traffic_24h: {total, success, denied, error, unavailable, rejected, unauthenticated, p50_ms, p95_ms},
traffic_by_environment_24h: {test, pilot, production},
inbox_pending, audit: {head_seq, head_hash, last_verify: {ok, verified_at, problem}|null},
attention: [{severity: error|warning|info, message, href}]}`
(traffic numbers are computed from `gateway.chat.completions` audit events).

Jobs (`ferry/gateway/jobs.py`): in-memory registry, a small thread pool (2
workers), progress via the verifier's `progress(bytes_done, bytes_total)`
callback. Results are persisted through the importer (verifications table +
audit), so a restart loses only in-flight job status.

Static console: `ferry/static/index.html` served at `/`, assets at `/assets/*`.
Hash-based client routing (`#/bundles`), so no server-side route fallback.
Security headers on every response: `Content-Security-Policy: default-src 'self';
script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
`X-Frame-Options: DENY`. CORS off unless `server.cors_origins` is set.

## 10. Evidence, doctor, runtime, CLI

- `ferry/evidence.py`: `build_evidence(settings, conn) -> dict` with
  `generated_at, ferry_version, host {platform, python}, config (public_dict),
  import_policy, trust_anchors [entries + status], bundles [id, name, version,
  imported_at, signers, artifacts], routes [model, backend, pin, provenance],
  active_policy {version, sha256, activated_at, activated_by}, policy_history,
  audit {verify_chain result}, network_inventory, dependencies` and
  `render_markdown(evidence) -> str`. The report states plainly what it is
  (configuration and event evidence) and is not (a compliance certification).
- `ferry/doctor.py`: `network_inventory(settings, conn) -> list[{component,
  direction, destination, purpose, configurable, notes}]` (static facts about
  Ferry + the configured listener and backends) and `run_checks(settings, conn,
  probe_network=False) -> list[{id, status: pass|warn|fail, message}]`: data
  dir permissions, trust store problems, backends on private addresses, TLS
  status, proxy env vars present (ignored by Ferry, but reported), static assets
  contain no `http://`/`https://` references, no telemetry-capable packages
  installed (e.g. `opentelemetry-sdk`, `sentry-sdk`; note `opentelemetry-api` is
  pulled in by FastAPI and is inert without an SDK). `probe_network=True` (opt-in
  only) tries a 2 s TCP connect to a public IP and reports whether the host is
  actually isolated.
- `ferry/runtime.py`: `llamacpp_command(settings, conn, model, port, ctx_size=None) -> list[str]`
  for an imported model: `llama-server -m <store path> --alias <model> --host
  127.0.0.1 --port <port> --api-key-file <secrets/llamacpp-<model>.token> --offline
  --no-webui [-c N]`; `ensure_llamacpp_registration(...)` creates the token file
  (0600) if missing and the backend `llamacpp-<model>` + pinned route
  (`require_verified=1`) if absent, audited.
- `ferry/cli.py` (`ferry` entry point, argparse, stdlib only):
  `version`, `init --data-dir`, `keygen NAME [--out-dir] [--passphrase-file F | --no-passphrase]`,
  `pack SPEC --key K [--out DIR] [--created-at TS] [--allow-unsafe]`,
  `sign BUNDLE --key K`, `inspect BUNDLE [--json]`,
  `verify BUNDLE [--trust-dir D] [--config F | --data-dir D] [--require-role R ...] [--json] [--full]`
  (works standalone without a database: if no data dir is given, nothing is recorded),
  `import BUNDLE` (data dir required),
  `trust add PEM --name N --role R [--role R] [--expires TS] [--expect-fingerprint FP]`, `trust list`, `trust revoke ID --reason R`,
  `admin create-user USERNAME --role admin|auditor [--password-stdin]`,
  `app create NAME [--environment E] [--description D]`, `app list`, `app key NAME [--expires-in-days N]`, `app revoke-key KEY_ID`,
  `backend add NAME --kind K --url U [--token-file F]`, `backend list`, `backend check NAME`,
  `route add MODEL --backend NAME [--upstream-model ID] [--artifact DIGEST] [--no-require-verified]`, `route list`,
  `policy validate FILE`, `policy activate FILE [--comment C]`, `policy show`, `policy explain --app A --model M [--action chat.completions]`,
  `runtime llamacpp MODEL [--port P] [--ctx-size N] [--print-only]`,
  `audit verify [--checkpoint F]`, `audit export [--out F]`, `audit checkpoint [--sign-key K] [--out F]`,
  `store verify`, `evidence [--format md|json] [--out F]`, `doctor [--probe-network]`,
  `serve [--host H] [--port P]`.
  Passphrases: `--passphrase-file` or env `FERRY_KEY_PASSPHRASE`; never a CLI argument.
  Global options `--config`, `--data-dir`. Exit codes 0/1/2 as above.

## 11. Console (web/)

React + TypeScript + Vite. Build output goes to `ferry/static/` (committed build
artifacts are fine). Everything bundled locally: no CDN, no remote fonts, no
analytics. Pages: Login, Overview, Bundles (inbox with Verify/Import and live
job progress; verification history; bundle detail with checks, signers,
artifacts), Models (imported models, routes with provenance badges, backends
with health and Check button, add backend/route forms), Access (apps and keys
with one-time key display; policy editor with Validate/Activate, version
history; Explain tool), Audit (filterable, searchable event table, event detail
with hash/prev_hash, Verify chain, Export), Evidence (rendered evidence report,
Markdown/JSON download, network inventory, effective config). Auditor role sees
read-only UI (admin-only controls hidden and also rejected server-side).
Restrained, information-dense design for infrastructure and security engineers;
real data only; clear loading, empty and error states; keyboard accessible.
