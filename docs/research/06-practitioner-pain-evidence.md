# Practitioner Pain Evidence: Open-Weight LLM Stacks in Air-Gapped Environments

*Research note 06. Sources accessed 2026-10-28. Labels: **VERIFIED** means read in the cited source. **INFERRED** means analyst reasoning from verified facts. **UNKNOWN** means not confirmed. Source IDs [S#] are listed at the end.*

## Bottom line

1. **VERIFIED:** The best-documented failure is an "offline mode" that still uses the network. Popular tools reach out at startup or on first use: Hugging Face freshness checks, LiteLLM's cost map pulled from GitHub, tiktoken vocabulary files, Open WebUI's embedding and Whisper downloads, and telemetry that is on by default. Open WebUI's own offline guide says its settings do not block outbound traffic and that a working chat test does not prove isolation. [S1, S3, S10, S13]
2. **VERIFIED:** The pain lasts for years. In vLLM discussion #1405, opened in Oct 2023, vLLM still called the Hub with `HF_HUB_OFFLINE=1` set. It was still drawing unanswered questions in Sep 2026 and has no maintainer reply. [S6]
3. **INFERRED:** Nearly every failure is *caused* on the connected side, because something was left out of the bundle. It is *found* on the disconnected side, after a transfer that costs a full review cycle. That gap is the main evidence for Wedge A.
4. **UNKNOWN:** No government or other primary source puts a number on transfer or approval times. The only figures (updates every one to three months, "weeks" of delay per change) come from vendor blogs. [S27-S30]
5. **VERIFIED/INFERRED:** Almost all first-person public reports come from individual developers and hobbyists. Enterprise and government pain shows up mainly in vendor docs, such as NVIDIA NIM's two-phase air-gap workflow, and in vendor marketing. How severe the problem is for enterprises still has to be confirmed in interviews. [S18]

## 1. Failure modes and evidence counts

Context tags: **H** is an individual or hobbyist report, **D** is official docs or source code, **G** is a government publication, **V** is vendor marketing or a third-party guide, and **U** means the context is unclear. Counts are the number of distinct sources found in this pass. They are not estimates of how common each problem is.

| Failure mode | Sources | Mix | Representative evidence |
|---|---|---|---|
| Hidden runtime network calls; incomplete offline flags | 10 | H3 D4 U1 V2 | vLLM #1405 [S6] and forum thread [S7]; HF Hub checks cached files over HTTP unless offline mode is set [S1]; LiteLLM pulls its cost map from GitHub at startup [S10], plus #25062 [S11]; tiktoken fetches on a cache miss [S13], with a matching connection error on the OpenAI forum [S14]; Open WebUI [S3]; guides [S32, S33] |
| Missing tokenizer or auxiliary model files (embeddings, reranker, Whisper, tiktoken vocab) | 7 | H3 D4 | A fresh offline Open WebUI reports "No embedding model is loaded" [S3, S4]; NVIDIA AIPerf needs local tokenizer folders in HF format [S19]; Phi-3-small repo commit about where its tiktoken vocab loads from [S15]; HF forum offline threads [S23, S24]; vLLM #1405 needed `TRANSFORMERS_OFFLINE` too [S6] |
| Python wheel, CUDA and native-build gaps | 4 | H1 D3 | flash-attn source builds are slow, and its setup tries to fetch prebuilt wheels from GitHub [S21]; HPC doc on the cost of building flash-attn [S22]; vLLM precompiled-wheel variables [S9]; Open WebUI wheelhouse steps (`pip download` on a machine with matching OS and Python, then install with `--no-index`) [S5] |
| Moving bundles, containers and caches | 3 | D2 V1 | NIM pre-stages with `download-to-cache` and `create-model-store`, then the cache is copied over [S18]; keep cache symlinks intact [S3]; every registry and mirror has to be pre-staged [S27] |
| Updates (apps and models) | 7 | H1 D3 V3 | Ollama desktop downloads updates on its own [S16]; Ollama #4498 [S17]; Open WebUI auto-update flags and version check [S3]; the `hf` CLI checks PyPI for updates [S1]; vendor claims about update cadence [S27, S28, S31] |
| Transfer approval and review | 4 | G1 V3 | Canadian Cyber Centre primer: low-to-high transfers go through a cross-domain solution (CDS), for example a software patch [S25]; scan-then-transfer flow [S26]; each new dependency needs a media transfer request plus a security review [S29]; updates are batched [S28] |
| Integrity checks on multi-GB files | 1 (weak) | D1 | tiktoken checks a content hash only if the caller passes `expected_hash` [S13] |
| Model format conversion | 0 | none | No evidence found. **INFERRED:** NIM's hardware-specific model profiles are chosen before transfer, which hints at this problem [S18] |
| License tracking | 0 | none | No public practitioner evidence found |

**INFERRED:** The top four rows are all about bundle completeness. In each case a tool quietly expected to download a file, wheel or cache entry that was never included in the bundle.

## 2. Key evidence in detail

- **VERIFIED:** huggingface_hub reads its environment variables once, at import time. With `HF_HUB_OFFLINE=1` it makes no Hub calls and raises an error if a file is not cached. Without that setting, `hf_hub_download` checks freshness even for cached files and waits up to `HF_HUB_ETAG_TIMEOUT` (10 s by default) before falling back to the cache. [S1]
  - **INFERRED:** On a network that silently drops traffic, every unflagged lookup can stall for about 10 s. Users see that as a "hang," not an error.
- **VERIFIED:** In vLLM #1405, a user loading a locally cloned model with `--download-dir` still saw Hub calls. The workarounds were absolute local paths and `TRANSFORMERS_OFFLINE=1` (9 upvotes). In Oct 2024 a Docker user on 0.6.2 still hit an offline-mode error when using a Hub model ID. [S6]
- **VERIFIED:** LiteLLM's proxy downloads `model_prices_and_context_window.json` from GitHub at startup. [S10] Issue #25062 (Apr 2026) reports that the offline fallback copy bundled with the package can be missing from PyInstaller builds and slim Docker images. The issue went stale and was closed as "not planned" in Jul 2026. It points to a local-only mode, `LITELLM_LOCAL_MODEL_COST_MAP=True` (#1434). [S11]
- **VERIFIED:** tiktoken downloads its BPE vocabulary files on a cache miss. The cache location comes from `TIKTOKEN_CACHE_DIR` or `DATA_GYM_CACHE_DIR` and defaults to the system temp folder. The cache key is a SHA-1 hash of the URL. [S13]
  - **INFERRED:** Because the default cache is in the temp folder, a vocabulary file copied in ahead of time can be wiped by a temp cleanup, which brings back the download.
- **VERIFIED:** In Open WebUI, `OFFLINE_MODE=true` sets `HF_HUB_OFFLINE=1` and turns off version checks and model auto-updates. Setting `WHISPER_MODEL_AUTO_UPDATE=false` on its own does not stop a download, because Open WebUI retries with downloads enabled. The guide is a community contribution and is not supported by the core team. [S3]
- **VERIFIED as a third-party claim; not confirmed in vLLM docs:** A blog says `HF_HUB_OFFLINE` covers only huggingface_hub. It also says vLLM's `/docs` page loads Swagger assets from a CDN unless `--enable-offline-docs` is set, and it recommends testing with `docker run --network none`. [S32]
- **VERIFIED:** Ollama on macOS and Windows downloads updates automatically. On Linux you update by re-running the install script. `OLLAMA_NO_CLOUD=1` turns off cloud models and web search. The FAQ documents no way to turn off auto-update. [S16] Issue #4498, "Add option to disable Autoupdate," was opened in May 2024, closed, reopened in Dec 2025, and is still open with about 20 comments. Users cite security, metered connections, surprise downloads of 600 MB to 2 GB, and regular connections to ollama.com. Their workarounds are firewall rules and blocking the updates folder. [S17]

## 3. Network-dependency and telemetry inventory

| Tool | Default outbound behavior | How to turn it off | Status |
|---|---|---|---|
| huggingface_hub (used by transformers, datasets, gradio) | Usage telemetry through `send_telemetry` | `HF_HUB_DISABLE_TELEMETRY=1` or `DO_NOT_TRACK=1` | VERIFIED [S1] |
| huggingface_hub | Freshness check on each download call | `HF_HUB_OFFLINE=1`, set before import | VERIFIED [S1] |
| `hf` CLI | Checks PyPI for a new version at most once every 24 h | `HF_HUB_DISABLE_UPDATE_CHECK=1` | VERIFIED [S1] |
| Gradio | Analytics on (`GRADIO_ANALYTICS_ENABLED` defaults to True) | Set it to False | VERIFIED [S2] |
| vLLM | Anonymous usage stats (hardware, model architecture, config) | `VLLM_NO_USAGE_STATS=1`, `DO_NOT_TRACK=1`, or the file `~/.config/vllm/do_not_track` | VERIFIED [S8]. The endpoint is not named in the primary docs; a blog names stats.vllm.ai [S32] |
| vLLM | Swagger `/docs` assets from a CDN | `--enable-offline-docs` | Third-party claim only [S32] |
| Open WebUI | Version check; downloads embedding, reranker and Whisper models on its own | `OFFLINE_MODE=true`, `ENABLE_VERSION_UPDATE_CHECK=false`, `*_AUTO_UPDATE=false`, `HF_HUB_OFFLINE=1` | VERIFIED [S3] |
| Chroma (a vector DB option for Open WebUI) | Anonymous telemetry to PostHog | `ANONYMIZED_TELEMETRY=False` | VERIFIED [S20]. Open WebUI's default is UNKNOWN |
| LiteLLM proxy | Downloads the cost map from GitHub at startup | Local cost-map setting (#1434) | VERIFIED [S10, S11] |
| LiteLLM proxy | Telemetry off by default when self-hosted. Docs: "No data or telemetry is stored on LiteLLM Servers when you self-host." | Not needed | VERIFIED [S12] |
| Ollama | Desktop auto-update; cloud models and web search; ollama.com key for private pulls | `OLLAMA_NO_CLOUD=1`; no documented switch for auto-update | VERIFIED [S16, S17] |
| tiktoken (pulled in by many stacks) | Downloads vocabulary on a cache miss | Pre-fill `TIKTOKEN_CACHE_DIR` | VERIFIED [S13] |

**INFERRED:** No single switch turns all of this off. Each tool has its own variable, and several are read only at import or at startup. Watching for outbound traffic with networking denied (`--network none`) would catch more than a checklist of flags.

## 4. Hobbyist vs. enterprise and government

- **Hobbyist or individual sources:** Ollama #4498, vLLM #1405, the OpenAI tiktoken thread, the flash-attn TIL post and the HF forum threads. Their concerns are privacy, metered bandwidth, convenience and unexplained calls home. VERIFIED from the thread contents.
- **Enterprise or government sources:** NIM air-gap docs [S18], the Canadian Cyber Centre primer ITSB-120 [S25], OPSWAT CDS docs [S26], a defense vendor's blog [S29], and vendor guides [S27, S28, S31]. Their concerns are pre-staging everything, CDS and media-transfer review, update cadence and accreditation. VERIFIED as source types.
- **INFERRED:** People working in classified environments rarely post failure reports in public, so their pain is under-represented on GitHub and Reddit. The vendor material points in a direction but is shaped by marketing and gives no numbers.

## 5. How long transfers and approvals take

- **UNKNOWN:** I found no GAO, DoD or other primary figure for low-to-high transfer times or per-artifact approval times.
- **VERIFIED as vendor claims only:**
  - Updates arrive on signed physical media every one to three months. [S27]
  - Updates ship monthly or quarterly, with a faster path for emergency patches. [S28]
  - Each new dependency needs a media transfer request and a security review, which teams have to plan into their sprints. [S29]
  - A true air gap adds weeks of delay to every change, and moving model weights is the slowest part of a first delivery. [S30]
- **INFERRED:** If one missing file means one more transfer cycle, a single overlooked dependency could delay a deployment by weeks, or by a quarter, at the claimed cadences. Interviews need to confirm this.

## 6. Gaps and search limitations

- **Reddit (r/LocalLLaMA, r/sysadmin):** The search tool returned no Reddit threads, even with a `site:` filter. UNKNOWN.
- **GitHub issues:** Web search did not surface Ollama's offline-install issues, TGI's offline-mode issues or llama.cpp issues, so none were reviewed. vLLM issue #4906 appeared in results but was not read.
- **Uncovered categories:** No evidence was gathered on license tracking, model format conversion, or verifying weight checksums.

## Implications by wedge

- **A, offline deployment and upgrades (strongest support):** Six of the nine categories are about what goes into a transferable bundle and whether it really runs without a network. NIM shows that a pre-stage-then-transfer workflow exists, but only for NIM; the open stacks leave it to each user. **INFERRED:** The product would build the bundle on the connected side and run it with all networking denied, recording every attempted connection and every missing file before transfer. It would then emit a hashed manifest.
- **B, access control:** This evidence set holds almost no access-control pain. **UNKNOWN:** It needs its own research.
- **C, operations:** Auto-updates, version checks and update cadence keep coming up as irritants. **INFERRED:** Most of that operations pain comes down to "every update is another offline bundle," which runs on Wedge A's machinery.
- **D, evidence:** Chat tests do not prove isolation [S3], hashes are optional [S13], and CDS and media reviewers need to know what is in a bundle [S25, S29]. **INFERRED:** Egress logs, hashes and dependency inventories fall out of A as a byproduct and set it apart, but demand for D on its own has not been measured.
- **E, private inference:** Runtimes are plentiful (Ollama, vLLM, TGI, NIM). The pain is not a missing runtime but runtimes and their dependencies that do not run cleanly offline. **INFERRED:** The product should wrap existing runtimes rather than build a new one.

## Sources (accessed 2026-10-28)

The note "excerpt" means the source was read through a search-result excerpt only. All other sources were fetched.

- S1 https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables
- S2 https://www.gradio.app/guides/environment-variables
- S3 https://docs.openwebui.com/tutorials/maintenance/offline-mode
- S4 https://docs.openwebui.com/troubleshooting/startup (excerpt)
- S5 https://docs.openwebui.com/ecosystem/computer/install/air-gapped (excerpt)
- S6 https://github.com/vllm-project/vllm/discussions/1405
- S7 https://discuss.vllm.ai/t/setting-up-vllm-in-an-airgapped-environment/916 (excerpt; answers appear bot-generated)
- S8 https://docs.vllm.ai/en/latest/usage/usage_stats.html
- S9 https://docs.vllm.ai/en/v0.9.2/getting_started/installation/gpu.html (excerpt)
- S10 https://docs.litellm.ai/docs/proxy/model_cost_map
- S11 https://github.com/BerriAI/litellm/issues/25062
- S12 https://docs.litellm.ai/docs/data_security
- S13 https://github.com/openai/tiktoken/blob/main/tiktoken/load.py
- S14 https://community.openai.com/t/newconnectionerror-keeps-coming-up-over-a-tiktoken-file/670052 (excerpt)
- S15 https://huggingface.co/microsoft/Phi-3-small-8k-instruct/commit/71140198d3f643b6c90697e242e537051091c819 (excerpt)
- S16 https://docs.ollama.com/faq
- S17 https://github.com/ollama/ollama/issues/4498
- S18 https://docs.nvidia.com/nim/large-language-models/latest/deployment/air-gap-deployment.html (excerpt)
- S19 https://docs.nvidia.com/aiperf/tutorials/configuration/using-local-tokenizers-without-hugging-face (excerpt)
- S20 https://docs.trychroma.com/telemetry (excerpt)
- S21 https://til.simonwillison.net/python/installing-flash-attention (excerpt)
- S22 https://docs.mila.quebec/examples/frameworks/flash_attn_setup/ (excerpt)
- S23 https://discuss.huggingface.co/t/huggingface-offline-error/89170 (excerpt)
- S24 https://discuss.huggingface.co/t/how-to-use-peft-base-merged-models-in-offline-mode/78343 (excerpt)
- S25 https://www.cyber.gc.ca/en/guidance/cross-domain-security-primer-itsb-120 (excerpt)
- S26 https://www.opswat.com/docs/supply-chain/configuration/cross-domain-transfer (excerpt)
- S27 https://www.truefoundry.com/blog/air-gapped-ai-deploying-enterprise-llms-in-highly-regulated-industries (excerpt)
- S28 https://vdf.ai/blog/air-gapped-ai-deployments-restricted-networks/ (excerpt)
- S29 https://corvusintell.com/blog/secure-cloud/air-gapped-deployment-defense/ (excerpt)
- S30 https://vibeengines.com/handbook/air-gapped-and-regulated-deployment (excerpt)
- S31 https://www.shakudo.io/resources/air-gapped-llm-deployment (excerpt)
- S32 https://particula.tech/blog/vllm-air-gapped-offline-deployment (excerpt)
- S33 https://context7.com/guides/air-gapped-ai-coding (excerpt)
