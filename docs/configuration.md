# Configuration reference

Ferry reads one TOML file, `ferry.toml`, written by `ferry init` into the data
directory. Precedence: `--config` / `--data-dir` flags, then `FERRY_CONFIG` /
`FERRY_DATA_DIR`, then `<data dir>/ferry.toml`. **Unknown keys are rejected**,
so a typo in a security setting fails loudly. Settings that weaken security
(public backends, pickle, executables, signer roles) can only be changed in
this file on the host; the console shows them but cannot change them. Relative
paths are resolved against the file's directory. Source of truth:
[ferry/config.py](../ferry/config.py).

## Top level

| Key | Default | Meaning |
|---|---|---|
| `data_dir` | required (flag, env or file) | Database, store, inbox, trust store and secrets live here (mode 0700) |

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `host` | `127.0.0.1` | Listen address for the gateway, admin API and console |
| `port` | `8750` | Listen port |
| `tls_cert_file`, `tls_key_file` | empty | Serve HTTPS; set both or neither. Required before listening beyond loopback |
| `cookie_secure` | `auto` | `auto` marks the session cookie Secure unless serving plain HTTP on loopback; `true` or `false` force it |
| `cors_origins` | `[]` | Explicit origins allowed to call `/v1` from a browser; the admin API never allows CORS |
| `max_body_bytes` | `1048576` | Largest request body (1 KiB to 64 MiB) |
| `session_idle_minutes` | `30` | Console session idle timeout |
| `session_max_hours` | `8` | Console session absolute lifetime |

## `[gateway]`

| Key | Default | Meaning |
|---|---|---|
| `max_concurrency` | `8` | Requests in flight across all backends |
| `queue_timeout_s` | `10.0` | How long a request may wait for a slot before 429 |
| `connect_timeout_s` | `5.0` | Backend connect timeout |
| `read_timeout_s` | `120.0` | Backend read timeout (backends can set their own `timeout_s`) |
| `allow_public_backends` | `false` | Allow backends that resolve to public addresses. Link-local and cloud metadata addresses are refused regardless |
| `health_interval_s` | `30.0` | Background backend health and provenance checks; `0` disables |
| `max_tokens_ceiling` | `8192` | Hard cap on `max_tokens`, whatever the policy allows |

## `[import]`

| Key | Default | Meaning |
|---|---|---|
| `inbox_dir` | `<data_dir>/inbox` | Where bundles arrive; the console lists and imports from here only |
| `trust_dir` | `<data_dir>/trust` | Trusted signing keys (`ferry trust add/revoke`, host only) |
| `required_roles` | `["publisher"]` | Signer roles a bundle must carry; `["publisher", "reviewer"]` enforces a second, independent signature |
| `distinct_signers` | `true` | One key cannot satisfy two required roles |
| `allowed_kinds` | `["model", "tokenizer", "config", "document"]` | Artifact kinds accepted (`file` must be added explicitly) |
| `allowed_model_formats` | `["gguf", "safetensors"]` | Model formats accepted; `pickle` also needs `allow_pickle = true` |
| `allow_pickle` | `false` | Pickle-based weights can execute code when loaded; keep false |
| `allow_executables` | `false` | Executables and scripts in bundles |
| `allowed_licenses` | `["Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"]` | SPDX ids accepted for model licences |
| `max_bundle_bytes` | 200 GiB | Total bundle size limit |
| `max_artifact_bytes` | 100 GiB | Per-file limit |
| `max_artifacts` | `1000` | Files per bundle |
| `max_manifest_bytes` | 4 MiB | Manifest size limit |

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `FERRY_CONFIG`, `FERRY_DATA_DIR` | all commands | Config file and data directory |
| `FERRY_KEY_PASSPHRASE` | `keygen`, `pack`, `sign` | Signing-key passphrase (or use `--passphrase-file`; never a flag value) |
| `FERRY_TEST_LLAMACPP_MODEL` | tests | Path to a GGUF file to enable the real llama.cpp tests |

Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, ...) are ignored by Ferry's HTTP
client; `ferry doctor` reports them if set.
