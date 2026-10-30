# Network dependency inventory

Every network interaction of Ferry and of the components it is designed to run
with. "Verified" means observed on the build machine (macOS 26.5.1, Apple M3 Pro)
on 2026-10-28 or enforced by an automated test; everything else is labelled.
Running locally is not the same as being air-gapped; this inventory is what lets
you check the difference.

## Ferry on the disconnected side (gateway, console, importer)

| Direction | Destination | Purpose | When | Control |
|---|---|---|---|---|
| Inbound | `server.host:server.port` (default `127.0.0.1:8750`) | OpenAI-compatible API, admin API, console | While `ferry serve` runs | `[server]` in ferry.toml. Plain HTTP unless `tls_cert_file`/`tls_key_file` are set |
| Outbound | Each configured backend `base_url` | Inference requests and health checks | Per request; health every `health_interval_s` | Admins add backends. Addresses must resolve to loopback/private ranges unless `allow_public_backends = true` in ferry.toml. Link-local (e.g. 169.254.169.254) is always refused. Proxy environment variables are ignored; redirects are not followed |
| DNS | Backend host names | Resolving names for the egress check | When a backend is saved and before upstream requests (cached 30 s) | Use IP literals to avoid DNS entirely |
| None | Telemetry, crash reporting, update checks, licence checks, CDNs, remote fonts, time sync | Not implemented | Never | Nothing to disable |

`ferry import`, `ferry verify`, `ferry audit`, `ferry evidence` and the other
local commands make no network connections.

## Ferry on the connected side

| Command | Network behaviour |
|---|---|
| `ferry keygen`, `pack`, `sign`, `inspect`, `verify` | None |
| `ferry rehearse` | Starts llama-server inside a network sandbox and talks to it over loopback. From inside the sandbox it attempts one TCP connection to `192.0.2.1:443` (RFC 5737 TEST-NET-1, never routed on the internet) and one DNS lookup of `example.com`; both are expected to fail, which is the evidence that egress was blocked. **Verified** on macOS: both denied, loopback served a real completion (tests/test_sandbox.py) |
| `demo/fetch-model.sh` | Operator step, not part of Ferry: `curl` from huggingface.co at a pinned revision, then a SHA-256 check against the published digest |

## Python runtime dependencies

Direct: fastapi, uvicorn, httpx, cryptography, pydantic. None of them make
network connections on import. Ferry's HTTP client is used only for backends.

| Package (version installed here) | Network behaviour | Status |
|---|---|---|
| fastapi 0.162.0, starlette 1.10.0 | None. FastAPI's own `/docs` page loads assets from a CDN, so Ferry disables `/docs`, `/redoc` and `/openapi.json` | Docs routes disabled in `create_app` (checked by tests) |
| opentelemetry-api 1.45.1 (required by fastapi 0.162) | API only. Without an OpenTelemetry SDK and exporter it records and sends nothing | **Verified** dependency chain (`pip show`). `ferry doctor` warns if an SDK or exporter package is installed |
| uvicorn 0.54.0, h11, click | Listener only | |
| httpx 0.28.1, httpcore, anyio, idna, certifi | Outbound only when Ferry calls a backend. Created with `trust_env=False` | certifi is a CA bundle file; no network |
| cryptography 50.0.2, cffi, pycparser | None | |
| pydantic 2.14.1, pydantic-core, typing-extensions, annotated-types, annotated-doc, typing-inspection | None | |

Build-time only: setuptools (wheel build), pytest (tests).

## Console (web/)

Built on the connected side with npm (React, Vite, TypeScript, IBM Plex fonts
from `@fontsource`). The output in `ferry/static/` is served by Ferry itself:
no CDN, no remote fonts, no analytics. A test greps the built files for
external URLs.

## Inference runtimes (installed by the operator)

| Runtime | Network behaviour | What Ferry does about it | Source |
|---|---|---|---|
| llama.cpp `llama-server` | Can download models (`-hf`, model URLs). `--offline` "forces use of cache, prevents network access" | `ferry runtime llamacpp` and `ferry rehearse` always pass `--offline --no-webui`, bind 127.0.0.1 and set `--api-key-file` | `llama-server --help` (0.7.0, b11669). **Verified**: served a completion inside the sandbox with egress and DNS denied |
| Ollama | No server-side auth. Desktop builds auto-update. `OLLAMA_NO_CLOUD=1` disables cloud models and web search | Put the gateway in front; bind Ollama to loopback; set `OLLAMA_NO_CLOUD=1` | docs/research/02, 06 |
| vLLM | Usage statistics unless `VLLM_NO_USAGE_STATS=1` or `DO_NOT_TRACK=1`; Hugging Face Hub calls unless `HF_HUB_OFFLINE=1` (set before start) | Documented here; Ferry cannot change vLLM's behaviour | docs/research/02, 06 |

## How to check a host yourself

1. `ferry doctor` lists configured listeners and backends, flags proxy
   variables, public backend addresses, telemetry-capable packages and external
   URLs in the console build. `ferry doctor --probe-network` (opt-in) tries one
   TCP connection to a public address and reports whether the host is actually
   isolated.
2. `ferry rehearse` runs the model with egress blocked and reports the probe.
3. Run the whole stack under an OS sandbox (`sandbox-exec` on macOS,
   `unshare --net` on Linux) the same way the rehearsal does.
