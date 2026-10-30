"""Known hidden network behaviour in AI serving stacks, and how to turn it off.

Each rule maps what a preflight observes (a host name, the Python package that
made a call, or a line of output) to the library responsible and its documented
offline setting. `confidence` is "documented" when the behaviour and the switch
come from the project's own docs or source as cited in docs/research/02 and 06,
and "inferred" when the host name or message is our best reading but was not
confirmed in a primary source. This table is meant to grow with every preflight
run on a real stack.
"""

from __future__ import annotations

import re
from typing import Any

RULES: list[dict[str, Any]] = [
    {
        "id": "huggingface-hub",
        "library": "huggingface_hub / transformers / datasets",
        "hosts": ["huggingface.co", "*.huggingface.co", "*.hf.co"],
        "packages": ["huggingface_hub", "transformers", "datasets", "diffusers", "sentence_transformers"],
        "patterns": [r"OfflineModeIsEnabled", r"couldn't connect to 'https://huggingface\.co'", r"LocalEntryNotFoundError"],
        "issue": "Hub lookups at load time: file freshness checks (up to HF_HUB_ETAG_TIMEOUT, 10 s, per call), downloads and telemetry.",
        "fix": "Set HF_HUB_OFFLINE=1 before the process starts (it is read at import time), plus HF_HUB_DISABLE_TELEMETRY=1. "
               "Load models from local paths, not Hub ids, and ship every file the model needs in HF_HUB_CACHE. "
               "For older transformers also set TRANSFORMERS_OFFLINE=1. For llama.cpp, use -m with a local GGUF and --offline instead of -hf.",
        "source": "huggingface_hub environment variables; vLLM discussion #1405 (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "hf-cli-update-check",
        "library": "huggingface_hub CLI",
        "hosts": ["pypi.org"],
        "packages": ["huggingface_hub"],
        "patterns": [],
        "issue": "The hf CLI checks PyPI for a newer version at most once a day.",
        "fix": "Set HF_HUB_DISABLE_UPDATE_CHECK=1.",
        "source": "huggingface_hub environment variables (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "tiktoken-vocab",
        "library": "tiktoken",
        "hosts": ["openaipublic.blob.core.windows.net"],
        "packages": ["tiktoken", "tiktoken_ext"],
        "patterns": [r"\.tiktoken"],
        "issue": "BPE vocabulary files are downloaded on a cache miss; the default cache is the system temp directory, which cleanup can empty.",
        "fix": "Ship the encoding files in the bundle and set TIKTOKEN_CACHE_DIR to a persistent directory that holds them.",
        "source": "tiktoken/load.py (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "litellm-cost-map",
        "library": "LiteLLM",
        "hosts": ["raw.githubusercontent.com"],
        "packages": ["litellm"],
        "patterns": [r"model_prices_and_context_window"],
        "issue": "The proxy downloads its model cost map from GitHub at startup.",
        "fix": "Set LITELLM_LOCAL_MODEL_COST_MAP=True (or LITELLM_OFFLINE_MODE=true) so the bundled copy is used.",
        "source": "LiteLLM model_cost_map docs and issue #25062 (docs/research/02, 06)",
        "confidence": "documented",
    },
    {
        "id": "vllm-usage-stats",
        "library": "vLLM",
        "hosts": ["stats.vllm.ai"],
        "packages": ["vllm"],
        "patterns": [],
        "issue": "Anonymous usage statistics (hardware, model architecture, configuration) are sent by default.",
        "fix": "Set VLLM_NO_USAGE_STATS=1 or DO_NOT_TRACK=1 (or create ~/.config/vllm/do_not_track). Also set HF_HUB_OFFLINE=1 when loading from Hub ids.",
        "source": "vLLM usage stats docs and vllm/envs.py (docs/research/02, 06)",
        "confidence": "documented",
    },
    {
        "id": "gradio-analytics",
        "library": "Gradio",
        "hosts": ["api.gradio.app"],
        "packages": ["gradio", "gradio_client"],
        "patterns": [],
        "issue": "Usage analytics are on by default.",
        "fix": "Set GRADIO_ANALYTICS_ENABLED=False.",
        "source": "Gradio environment variables guide (docs/research/06); host name not confirmed in a primary source",
        "confidence": "inferred",
    },
    {
        "id": "chroma-telemetry",
        "library": "Chroma",
        "hosts": ["*.posthog.com"],
        "packages": ["chromadb", "posthog"],
        "patterns": [],
        "issue": "Anonymous telemetry is sent to PostHog.",
        "fix": "Set ANONYMIZED_TELEMETRY=False.",
        "source": "Chroma telemetry docs (docs/research/06); host name not confirmed in a primary source",
        "confidence": "inferred",
    },
    {
        "id": "ollama-cloud",
        "library": "Ollama",
        "hosts": ["ollama.com", "*.ollama.com", "registry.ollama.ai"],
        "packages": ["ollama"],
        "patterns": [],
        "issue": "Cloud models, web search, model pulls and desktop auto-update reach ollama.com.",
        "fix": "Set OLLAMA_NO_CLOUD=1, import models from local GGUF files with a Modelfile, and block the desktop updater (there is no documented switch).",
        "source": "Ollama FAQ and issue #4498 (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "open-webui-aux-models",
        "library": "Open WebUI",
        "hosts": [],
        "packages": ["open_webui"],
        "patterns": [r"No embedding model is loaded"],
        "issue": "Embedding, reranker and Whisper models are downloaded on first use.",
        "fix": "Set OFFLINE_MODE=true and *_AUTO_UPDATE=false, ship those models and point Open WebUI at them.",
        "source": "Open WebUI offline-mode guide (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "runtime-package-install",
        "library": "pip / package installers",
        "hosts": ["files.pythonhosted.org", "pypi.org"],
        "packages": ["pip", "setuptools"],
        "patterns": [r"Looking in indexes", r"Collecting \S+"],
        "issue": "Something installs or checks Python packages at run time.",
        "fix": "Install every wheel ahead of time from a reviewed wheelhouse (pip download on a matching OS/Python, then pip install --no-index --find-links).",
        "source": "Open WebUI air-gapped wheelhouse steps (docs/research/06)",
        "confidence": "documented",
    },
    {
        "id": "github-release-assets",
        "library": "build scripts (for example flash-attn)",
        "hosts": ["github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"],
        "packages": [],
        "patterns": [],
        "issue": "A prebuilt wheel or release asset is fetched from GitHub at install or run time.",
        "fix": "Build or download the artifact on the connected side, ship it inside the bundle, and point the tool at the local copy.",
        "source": "flash-attn install notes (docs/research/06)",
        "confidence": "documented",
    },
]

_COMPILED = [(rule, [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]) for rule in RULES]


def _host_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().rstrip("."), pattern.lower()
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) or host == pattern[2:]
    return host == pattern


def match(hosts: set[str] | list[str] = (), packages: set[str] | list[str] = (),
          lines: list[str] = ()) -> list[dict[str, Any]]:
    """Rules triggered by the observed hosts, Python packages and output lines.

    A rule with known hosts needs a host or output match; the package that made
    the call then only adds evidence. Rules without hosts (behaviour seen only
    in output or attributable only to a package) can trigger on the package.
    """
    findings = []
    for rule, patterns in _COMPILED:
        matched: list[str] = []
        evidence: list[str] = []
        hit_hosts = sorted({h for h in hosts for p in rule["hosts"] if _host_matches(h, p)})
        if hit_hosts:
            matched.append("host")
            evidence += hit_hosts
        hit_pkgs = sorted({p for p in packages if p in rule["packages"]})
        if hit_pkgs:
            matched.append("package")
            evidence += hit_pkgs
        hit_lines = [ln for ln in lines if any(p.search(ln) for p in patterns)]
        if hit_lines:
            matched.append("output")
            evidence += hit_lines[:2]
        if matched == ["package"] and rule["hosts"]:
            continue
        if matched:
            findings.append({
                "rule": rule["id"], "library": rule["library"], "issue": rule["issue"], "fix": rule["fix"],
                "source": rule["source"], "confidence": rule["confidence"], "matched_on": matched, "evidence": evidence,
            })
    return findings
