# 02: Private inference runtimes and AI gateways (access control, audit, offline)

Research note, accessed 2026-10-28. Labels: **[V]** verified in the cited source, **[I]** inferred from verified facts, **[U]** unknown. `[S#]` refers to the Sources list at the end.

## Bottom line

1. **No inference runtime has per-model or per-user authorization.** llama.cpp and vLLM accept a flat list of shared API keys. The Ollama server has no authentication at all [V S2, S11, S13, S17]. Authorization therefore has to live in a gateway [I].
2. **Gateways already cover basic model allow-listing.** LiteLLM's open-source tier has virtual keys, budgets, and model access groups. Kong scopes model access per consumer group [V S26, S28, S32]. The controls regulated buyers ask for are paid features: LiteLLM Enterprise holds SSO beyond 5 users, RBAC, JWT, audit logs, IP ACLs, and secret managers [V S26], and Kong's advanced AI plugins sit in the `ai_gateway_enterprise` tier [V S34].
3. **Offline operation is mostly a configuration problem.** The runtimes run disconnected. LiteLLM supports a signed license key that can be verified offline, but its defaults still reach the internet unless you configure them not to [V S25, S29, S30].
4. **Policy engines already decide deterministically.** Cedar, OPA, and Cerbos give default-deny decisions, explanations, and decision logs [V S43–S45]. I found nothing that packages them as an LLM model-access decision point with tamper-evident logs and routing tied to approved artifact digests [I; this is absence of evidence, not an exhaustive search].
5. **The gap is real but narrow.** What is missing is integration and evidence, not a new policy engine. Wedge B on its own competes with LiteLLM Enterprise. It is strongest fused with D and fed by A's artifact manifests [I].

## 1. Runtimes

| Runtime | License and status | Native auth | Per-model authz | Offline and telemetry |
|---|---|---|---|---|
| llama.cpp `llama-server` | MIT, very active [V S24] | `--api-key` list or file; `Authorization: Bearer` or `X-Api-Key` [V S2, S5] | None: any valid key can use any loaded model [I] | The `--offline` flag "forces use of cache, prevents network access" [V S5] |
| Ollama | MIT [V S24] | None on the server. Clients must send a key, which Ollama ignores [V S10, S11] | None | Binds `127.0.0.1:11434` by default. `OLLAMA_NO_CLOUD=1` disables cloud models and web search [V S9, S14] |
| vLLM | Apache-2.0 [V S24] | `--api-key` (several allowed) or `VLLM_API_KEY`. Only `/v1`, `/v2`, `/inference`, and `/cohere` are guarded [V S17, S18] | None | Sends usage stats to `https://stats.vllm.ai` unless `VLLM_NO_USAGE_STATS=1` or `DO_NOT_TRACK` is set [V S23] |
| HF TGI | Apache-2.0. The repo is archived and the README says "maintenance mode" [V S24, S40] | n/a | n/a | Do not target it [I] |
| NVIDIA NIM | Licensing is not stated on the air-gap page [U] | Not described; the examples send no auth header [V S41] | Not described [U] | Documented air-gap workflow: `download-to-cache`, `create-model-store`, `NIM_MODEL_PATH`, `airgap-bundle.sh`. No `NGC_API_KEY` or `HF_TOKEN` at runtime [V S41] |
| LocalAI | MIT [V S24] | `LOCALAI_API_KEY` or `API_KEY`. Optional user auth (`LOCALAI_AUTH`, OIDC, admin role, hashed API keys that can expire) [V S42] | [U] | n/a |

## 2. Gateways and front-ends

**LiteLLM proxy**
- **License:** MIT, except the `enterprise/` directory, which has its own license [V S27]. The repo now describes itself as "Rust core with Python SDK" [V S24].
- **Free features:** virtual keys, budgets and rate limits, spend tracking, the admin UI, and the guardrail framework [V S26]. Model access groups are documented and do not appear in the Enterprise list [V S26, S28], so they are probably free [I].
- **Enterprise features** (need a license key): SSO beyond 5 users, SCIM, JWT auth, RBAC, org and team admins, audit logs with retention, IP ACLs, secret managers, key rotation, per-key guardrails, and enforced parameters [V S26].
- **License check** [V S25]: LiteLLM reads `LITELLM_LICENSE` and tries an offline check first. That check verifies an RSA-PSS/SHA-256 signature against the bundled `public_key.pem`, checks `expiration_date`, and reads `allowed_features`, `max_users`, and `max_teams`. Only if it fails does LiteLLM call `https://license.litellm.ai/verify_license/<key>`. Any failure counts as no license (fail-closed). An air-gapped site therefore needs a signed offline key [I].
- **Offline mode:** by default LiteLLM fetches its model cost map from raw.githubusercontent.com. Setting `LITELLM_LOCAL_MODEL_COST_MAP=True` or `LITELLM_OFFLINE_MODE=true` makes it use the bundled copy [V S29, S30].
- **Telemetry:** a consent-managed telemetry module was added recently. It is configured through `LITELLM_TELEMETRY_*` variables. Sending reports over HTTP requires an endpoint, and a local exporter keeps reports in the proxy database for manual export [V S31]. The default consent setting is unknown [U].

**Kong AI Gateway**
- The open-source Kong repo (Apache-2.0) ships `ai-proxy`, `ai-prompt-guard`, `ai-prompt-template`, `ai-prompt-decorator`, `ai-request-transformer`, and `ai-response-transformer` [V S33].
- `ai-proxy-advanced`, `ai-rate-limiting-advanced`, `ai-semantic-cache`, and `ai-sanitizer` are `tier: ai_gateway_enterprise` [V S34].
- AI Gateway 2.x moves proxying to an "AI Model entity." "AI Consumer Group" scopes model access and token budgets by team. The docs list FIPS 140-3 and support self-hosted deployment [V S32].
- The latest open-source GitHub release is 3.9.4 (2026-10-12) [V S33]. Whether the 2.x AI features exist in the open-source build is unknown [U].

**Agent Router (formerly Envoy AI Gateway)**
- The project was renamed and is now an Agentic AI Foundation project: Apache-2.0, repo `theagentrouter/agent-router`, latest release v1.2.0 (2026-10-07) [V S35].
- It uses two gateway tiers. Tier One handles authentication, routing, and global rate limits. Tier Two controls access to self-hosted models [V S35]. Client authorization presumably relies on Envoy Gateway policies; I did not verify this [I].

**Portkey gateway**
- MIT, runs with `npx`, Docker, or self-hosting [V S24, S36].
- The README is inconsistent: it lists guardrails, virtual keys, and RBAC as general features, but also lists key management and access control under "Enterprise." A 2.0 pre-release says the enterprise gateway is merging into the open-source code [V S36]. The last push was 2026-05-25 [V S24].

**Open WebUI** (a chat front-end, not a general-purpose gateway [I])
- **License:** the Open WebUI License (BSD-3 plus a branding clause) since v0.6.6. Branding can be removed only for deployments with 50 or fewer users in 30 days, or with an enterprise license [V S37].
- **Access control:** groups grant access to private models, knowledge bases, and tools [V S39]. Related settings: `BYPASS_MODEL_ACCESS_CONTROL` (default false), `ENABLE_API_KEYS` (default false), and SCIM [V S38].
- **Audit log:** a file whose level is set by `AUDIT_LOG_LEVEL` (default `NONE`), written to `DATA_DIR/audit.log` with 10MB rotation [V S38].
- **Offline:** `OFFLINE_MODE` turns off update checks and automatic model downloads [V S38].

## 3. Authorization engines

| Engine | Relevant facts |
|---|---|
| Cedar (Apache-2.0) | Returns Deny if any forbid matches, otherwise Allow if any permit matches, otherwise Deny ("default deny", "forbid overrides permit"). Policies that error are skipped. The response lists the policies that determined the decision, which gives explainability [V S43]. A symbolic compiler can verify properties of a policy set [V S43]. |
| OPA (Apache-2.0) | A graduated CNCF project. Policies are written in Rego, and a management API provides decision logs [V S44]. |
| Cerbos (Apache-2.0, open-core) | A stateless policy decision point. Its audit backends write access logs and decision logs, with filters [V S45]. |

Design note: because Cedar skips policies that error, a `forbid` that errors stops denying without any warning. The gateway should treat any evaluation error as a deny [I].

## 4. Gap assessment

| Requirement | Closest existing | Gap |
|---|---|---|
| Deterministic, explainable, default-deny model access | LiteLLM access groups (free) plus RBAC and JWT (Enterprise); Kong consumer groups; Open WebUI groups; Cedar, OPA, or Cerbos in general | **Small to moderate.** Allow-lists exist. No verified product reports which policy and which version denied a request as a first-class output [I]. |
| Tamper-evident audit | LiteLLM audit logs (Enterprise); Open WebUI audit file; OPA and Cerbos decision logs | **Moderate.** I found no claims of hash-chained or signed logs [U]. |
| Provenance-aware routing | Runtimes expose identifiers: the Ollama manifest `digest`, llama.cpp `model_path` and `build_info`, vLLM `root` | **The clearest gap.** No gateway I checked ties a routing decision to an approved artifact digest or signature [I]. This needs an approved-artifact manifest, which is wedge A. |
| Offline operation | All runtimes; NIM's air-gap guide; LiteLLM's offline license key and offline mode | **Small.** It is configuration and packaging [I]. |

Honest read: LiteLLM Enterprise plus an OPA sidecar plus logs shipped to write-once storage covers most of what B does. What is left is binding routing to provenance, explaining decisions, and packaging evidence [I].

## 5. Implementation facts (for adapter engineers)

### (1) llama.cpp `llama-server`

- **`GET /health` and `/v1/health`**
  - Both are public: no key needed [V S1, S2].
  - While the model loads they return HTTP 503 with `{"error":{"code":503,"message":"Loading model","type":"unavailable_error"}}`. When ready they return 200 with `{"status":"ok"}` [V S1, S2].
  - The same loading check returns 503 for every non-UI path during load, not just `/health` [V S2].
- **`GET /v1/models`** (also served at `/models`)
  - Shape: `{"object":"list","data":[…]}`.
  - Each item has `id`, `aliases`, `tags`, `object:"model"`, `architecture{input_modalities,output_modalities}`, `created`, `owned_by:"llamacpp"`, and `meta{vocab_type,n_vocab,n_ctx,n_ctx_train,n_embd,n_params,size}` [V S3].
  - In single-model mode the list has one entry. `id` defaults to the `-m` path, and `meta` can be `null` [V S1].
  - This endpoint is not public, so it needs the key whenever `--api-key` is set [V S2]. In router mode, entries also carry a `status` field [V S3].
- **`GET /props`**
  - Fields: `default_generation_settings`, `total_slots`, `model_alias`, `model_path` (the `-m` path), `chat_template`, `chat_template_caps`, `modalities`, `media_marker`, `build_info`, `is_sleeping` [V S1, S3].
  - Router mode reports `model_path:"none"` [V S3].
  - `POST /props` requires starting the server with `--props` [V S1].
- **Streaming**
  - Each event is a `data: <json>\n\n` frame [V S4].
  - OpenAI chat and completions streams end with `data: [DONE]\n\n`. Responses-API and Anthropic-format streams send no `[DONE]` [V S3].
  - `--sse-ping-interval` (default 30s) sends SSE comment lines. Adapters should skip lines that start with `:` [V S1; parsing rule I].
- **`--api-key`**
  - Flags: `--api-key KEY[,KEY…]` (env `LLAMA_API_KEY`) and `--api-key-file` (one key per line, `#` starts a comment) [V S1, S5].
  - The key is read from `Authorization`, with an optional `Bearer ` prefix stripped. If that header is empty, `X-Api-Key` is used [V S2].
  - Exempt: `/health`, `/v1/health`, web-UI paths, and CORS `OPTIONS` requests [V S2].
  - A bad or missing key returns 401 `{"error":{"message":"Invalid API Key","type":"authentication_error","code":401}}` [V S2].
- **`-a, --alias`**: comma-separated model aliases (env `LLAMA_ARG_ALIAS`). The alias becomes the `id` in `/v1/models` [V S1, S5].
- **Release naming:** two schemes run side by side.
  - Rolling builds are tagged `bNNNN`, for example `b11946` on 2026-10-28, marked prerelease [V S6].
  - Stable releases use semver tags `v0.1.0`…`v0.7.0`. The `nightly-tag.txt` file attached to v0.7.0 (2026-10-15) contains `b11669` [V S6].
  - The Homebrew formula is `llama.cpp`, stable version `0.7.0` from tag `v0.7.0` [V S7].
  - Adapters should accept both formats and read `build_info` from `/props` [I].

### (2) Ollama

- **Bind address:** `OLLAMA_HOST` (for example `0.0.0.0:11434`). The default is `127.0.0.1:11434` [V S9, S14].
- **`GET` or `HEAD /api/version`** returns `{"version":"…"}` [V S11].
- **`GET /api/tags`** returns `{"models":[{name, model, remote_model?, remote_host?, modified_at, size, digest, details{parent_model, format, family, families, parameter_size, quantization_level}, capabilities?}]}` [V S8, S12].
- **What `digest` means:** a 64-hex SHA-256 that identifies the model's **manifest**, produced when the manifest file is read and verified. It is not a hash of the weights; weight layers are separate blobs named `sha256-<64hex>` [I from S15, S16; the docs do not define it, S8]. For the newer multi-runner manifest lists, which digest is reported is unknown [U].
- **`POST /api/show`** takes `{"model":"…","verbose":false}`. The response has `license`, `modelfile`, `parameters`, `template`, `system`, `details`, `messages`, `model_info`, `projector_info`, `tensors`, `capabilities`, `modified_at`, `requires`, `manifests`, `remote_model`, and `remote_host` [V S8, S12].
- **OpenAI-compatible API**
  - Endpoints: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/models`, `/v1/models/{model}`, `/v1/responses` (no server-side state), and `/v1/audio/*`. There is also an Anthropic-style `/v1/messages` [V S10, S11].
  - Not supported: `tool_choice`, `logit_bias`, `user`, `n`, and logprobs. Images must be base64 [V S10].
  - In `/v1/models`, `created` is the last-modified time and `owned_by` is the namespace (default `library`) [V S10].
- **Auth: none on the server.** `OLLAMA_AUTH` only makes the Ollama *client* sign its requests (challenge `METHOD,PATH?ts=<unix>`), which it always does for ollama.com. `server/routes.go` has no reference to it [V S13, S14, S11]. Put a gateway in front, and set `OLLAMA_NO_CLOUD=1` on disconnected sites [I].

### (3) vLLM OpenAI-compatible server

- **`GET /health`**
  - Returns 200 when healthy and 503 on `EngineDeadError`. Servers that only render (no engine) always return 200. The endpoint is not behind the API key [V S21, S17].
  - Behavior while the model is still loading is unverified; check it empirically [U].
- **`GET /v1/models`** returns `{"object":"list","data":[{"id","object":"model","created","owned_by":"vllm","root","parent","max_model_len","permission":[]}]}` [V S22].
- **`--api-key`**
  - Accepts several keys (`list[str]`) or falls back to `VLLM_API_KEY`; the CLI flag takes precedence [V S18, S20].
  - The key must be sent as `Authorization: Bearer <key>`. The scheme name is case-insensitive, and keys are compared as SHA-256 digests with a constant-time check [V S17].
  - It is enforced only on paths starting with `/v1`, `/v2`, `/inference`, or `/cohere`. All other paths (including `/health` and `/invocations`) and `OPTIONS` requests are open. A failure returns 401 `{"error":"Unauthorized"}` [V S17].
  - The CLI help warns not to rely on `--api-key` alone [V S20].
  - The keys form one flat list with no per-model scope [V S17].

## Open questions

1. Does any gateway (LiteLLM Enterprise, Kong, Portkey, Agent Router) offer hash-chained or signed audit logs? [U]
2. For LiteLLM telemetry: what is the default consent, and where do HTTP reports go? What do LiteLLM air-gapped licenses cost? [U]
3. What are NIM's license terms, and does its endpoint support authentication? Are Kong AI Gateway 2.x features in the open-source build? [U]
4. What is Agent Router's client authorization model in detail? Does LocalAI scope users to specific models? [U]
5. Customer discovery: will buyers accept "gateway + OPA/Cedar + WORM logs" built themselves, or do they need a vendor-backed evidence package? [U]

Fetch notes: these pages returned 404 or redirects and were replaced with the sources below: `docs.litellm.ai/docs/proxy/enterprise`, `docs.openwebui.com/features/rbac/`, the old vLLM `openai_compatible_server` URL, Ollama's `server/manifest.go`, and NIM's `deploy-air-gap.html`. `aigateway.envoyproxy.io/docs/` redirects to `theagentrouter.ai/docs/`.

## Sources (accessed 2026-10-28)

- S1 https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
- S2 https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-http.cpp
- S3 https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-context.cpp ; https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-models.cpp
- S4 https://github.com/ggml-org/llama.cpp/blob/master/tools/server/server-common.cpp
- S5 https://github.com/ggml-org/llama.cpp/blob/master/common/arg.cpp
- S6 https://github.com/ggml-org/llama.cpp/releases ; https://api.github.com/repos/ggml-org/llama.cpp/tags
- S7 https://formulae.brew.sh/api/formula/llama.cpp.json
- S8 https://github.com/ollama/ollama/blob/main/docs/api.md
- S9 https://docs.ollama.com/faq
- S10 https://docs.ollama.com/api/openai-compatibility
- S11 https://github.com/ollama/ollama/blob/main/server/routes.go
- S12 https://github.com/ollama/ollama/blob/main/api/types.go
- S13 https://github.com/ollama/ollama/blob/main/api/client.go
- S14 https://github.com/ollama/ollama/blob/main/envconfig/config.go
- S15 https://github.com/ollama/ollama/blob/main/manifest/manifest.go
- S16 https://github.com/ollama/ollama/blob/main/server/model_list.go
- S17 https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/serve/middleware/authenticate.py
- S18 https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/serve/middleware/register.py
- S19 https://docs.vllm.ai/en/latest/serving/online_serving/
- S20 https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/common/cli_args.py
- S21 https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/serve/instrumentator/health.py
- S22 https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/serve/engine/protocol.py
- S23 https://github.com/vllm-project/vllm/blob/main/vllm/envs.py
- S24 GitHub repo metadata via https://api.github.com/repos/{BerriAI/litellm, Kong/kong, envoyproxy/ai-gateway, Portkey-AI/gateway, open-webui/open-webui, ollama/ollama, vllm-project/vllm, ggml-org/llama.cpp, huggingface/text-generation-inference, mudler/LocalAI, open-policy-agent/opa, cedar-policy/cedar, cerbos/cerbos}
- S25 https://github.com/BerriAI/litellm/blob/main/litellm/proxy/auth/litellm_license.py (and `public_key.pem` in the same directory)
- S26 https://docs.litellm.ai/docs/enterprise
- S27 https://github.com/BerriAI/litellm/blob/main/LICENSE
- S28 https://docs.litellm.ai/docs/proxy/model_access
- S29 https://github.com/BerriAI/litellm/blob/main/litellm/litellm_core_utils/get_model_cost_map.py ; https://github.com/BerriAI/litellm/blob/main/litellm/__init__.py
- S30 https://github.com/BerriAI/litellm/blob/main/litellm/litellm_core_utils/offline_mode.py
- S31 https://github.com/BerriAI/litellm/tree/main/litellm/proxy/telemetry ; https://github.com/BerriAI/litellm/blob/main/litellm-proxy-extras/litellm_proxy_extras/migrations/20261009000100_telemetry_reports/migration.sql
- S32 https://developer.konghq.com/ai-gateway/
- S33 https://github.com/Kong/kong/tree/master/kong/plugins ; https://github.com/Kong/kong/releases
- S34 https://github.com/Kong/developer.konghq.com/tree/main/app/_kong_plugins (ai-proxy, ai-proxy-advanced, ai-rate-limiting-advanced, ai-semantic-cache, ai-sanitizer, ai-prompt-guard `index.md`)
- S35 https://github.com/theagentrouter/agent-router (README, releases)
- S36 https://github.com/Portkey-AI/gateway
- S37 https://docs.openwebui.com/license/
- S38 https://github.com/open-webui/open-webui/blob/main/backend/open_webui/env.py ; https://github.com/open-webui/open-webui/blob/main/backend/open_webui/config.py
- S39 https://github.com/open-webui/docs/blob/main/docs/features/authentication-access/rbac/groups.md ; https://github.com/open-webui/docs/blob/main/docs/features/authentication-access/rbac/permissions.md
- S40 https://github.com/huggingface/text-generation-inference
- S41 https://docs.nvidia.com/nim/large-language-models/latest/deployment/air-gap-deployment.html
- S42 https://github.com/mudler/LocalAI/blob/master/core/cli/run.go
- S43 https://docs.cedarpolicy.com/auth/authorization.html ; https://github.com/cedar-policy/cedar
- S44 https://github.com/open-policy-agent/opa ; https://www.openpolicyagent.org/docs/management-decision-logs
- S45 https://github.com/cerbos/cerbos ; https://docs.cerbos.dev/cerbos/latest/configuration/audit.html
