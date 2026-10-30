# Offline delivery landscape: software and AI models into air-gapped networks

Prepared 2026-10-28 for the wedge A-E decision. Tags: **[V]** VERIFIED in the cited source ("ex" = read through a search-engine excerpt of that page, not a full fetch), **[I]** INFERRED from verified facts, **[U]** UNKNOWN. Numbers refer to Sources.

## 1. Bottom line

- The generic movers (Zarf, Hauler, Replicated, Artifactory Release Bundles) handle container images, Helm charts and files well. None of the docs reviewed mention model formats, pickle risk, model licenses or model cards [V 1,5,8 by absence], so weights travel as opaque blobs [I].
- Model awareness exists only in fragments: Hugging Face proxies in repository managers on the connected side (JFrog, Nexus) and runtime-specific offline caches on the serving side (NVIDIA NIM, Ollama, Red Hat ModelCars). We found no product covering select, scan, sign, transfer, verify and serve for open-weight models end to end [I].
- Most receiving-side paths assume Kubernetes (Zarf/UDS, Replicated Embedded Cluster, OpenShift AI) [V 1,8,16], usually with a registry inside the enclave [V 8,16; I for Zarf]. The non-Kubernetes paths are Hauler (single binary with embedded registry and fileserver) [V 6], NIM via `docker save`/`load` [V 20], and Ollama as a native service [V 22]; these share no lifecycle tooling [I].
- The market is churning: Defense Unicorns' LeapfrogAI repo now returns 404 [V 24], and JFrog froze Release Lifecycle Management on 31 Jul 2026, with end of life planned for 31 Jan 2028 [V 12].

## 2. Comparison

| Tool | Packages | Disconnected-side prerequisites | Model-aware? | Signing / offline verification | License / price |
|---|---|---|---|---|---|
| Zarf | Images, Helm charts, git repos (bundled Gitea) in one compressed file [V 1] | Existing K8s via kubeconfig, or Zarf installs K3s offline [V 1] | No AI/ML features in README [V 1] | cosign sign/verify, key file or KMS (`--signing-key`); automatic SBOMs, `--sbom-out` [V 1,2] | Apache-2.0 [V 1] |
| Hauler | Images, charts, files as OCI artifacts in one "haul", chunkable for media [V 5,6] | Single binary; embedded registry and fileserver, or copy into existing registry [V 6]; no K8s needed [I] | No [V 5 by absence] | cosign checks signatures, attestations, SBOMs before save and after load; key or keyless identity [V 5,6] | Apache-2.0; maintained by Rancher Government [V 5] |
| Replicated Embedded Cluster | Vendor's app + k0s cluster + OpenEBS + in-cluster registry [V 8] | Host passing preflights; installs its own K8s; EC v3 in Beta [V 8] | No [I] | Not in docs read [U] | Commercial; no public price found [U] |
| JFrog Artifactory | HF local/remote/virtual repos; Release Bundle v2 exported as .zip and imported [V 9,10 ex] | A second Artifactory inside the enclave; import is admin-only [V 10 ex] | Partly: HF repo layout, Xray license scanning of models [V 9 ex] | Signed bundles; signing key must be propagated to trusted keys before export [V 10 ex] | SaaS Pro $150/mo list; self-managed from $27k/yr (Pro X) or $51k/yr (Enterprise X); air-gap export needs Enterprise+ (quote only) [V 11 ex, 13] |
| Sonatype Nexus | HF proxy for models and datasets, Pro and Community Edition [V 14] | Needs an upstream; only proxy repos described [V 14], so not an offline store by itself [I] | Limited; Xet not yet supported [V 14] | Not described [U] | Community free; Pro price not checked [U] |
| OpenShift AI | Operator images mirrored to a private registry with oc-mirror; models as ModelCar OCI images (`oci://`) [V 16,17,18,19 ex] | OpenShift + mirror registry; model registry needs S3 storage and MySQL [V 16 ex] | Yes, for Red Hat's validated catalog (min vLLM/RHOAI versions, GPU/vRAM) [V 18 ex] | Not reviewed [U] | Subscription; price [U] |
| NVIDIA NIM | Container + model cache or model store (`download-to-cache`, `create-model-store`) [V 20] | Docker host (`docker load`) or K8s with mirrored images incl. GPU Operator [V 20] | NIM-specific: profiles vary by tensor-parallel size and backend and must match hardware [V 20] | Not on page [U] | Licensing not stated on page [U] |
| Ollama | GGUF (incl. split) or safetensors dir via Modelfile `FROM` + `ollama create` [V 21] | Ollama service; `OLLAMA_MODELS` dir [V 22] | Format-aware; GGUF not re-quantized on import [V 21] | None documented [U] | Not checked [U] |
| HF Hub offline | Local cache (`HF_HUB_CACHE`) [V 23] | Complete cache; `HF_HUB_OFFLINE=1` set before import [V 23] | n/a | None | n/a |
| UDS / LeapfrogAI | UDS Core is one Zarf package deployed with UDS CLI [V 28 ex] | K8s (via Zarf) [I] | LeapfrogAI was the AI layer; repo now 404 [V 24] | Inherits Zarf [I] | UDS Core v1.16.0, 27 Oct 2026 [V 29] |
| Iron Bank | Hardened container images + Body of Evidence on registry1.dso.mil [V 31,32 ex] | Access to or mirror of registry1 [I] | No weights process found [U] | Body of Evidence; images carry no ATO or CtF [V 31 ex] | Consumer cost [U] |

## 3. Details that matter

**Zarf.** Defense Unicorns contributed Zarf to OpenSSF in June 2024 [V 4 ex]; its current OpenSSF stage is unconfirmed [U]. The repo is active; latest release v0.88.0 (15 Oct 2026), still pre-1.0 [V 3]. `--max-package-size` splits packages into parts for small media; `--differential` includes only resources changed against a reference package [V 2]. Behavior with single 50-100+ GB weight files is not documented in the pages read [U].

**Hauler.** v2.1.2 (13 Oct 2026) [V 7]. Needs scratch disk about the size of the store or haul [V 5]. It is the closest thing to a non-K8s path, but it stops once content sits in a registry or fileserver; install, configuration and runtime health are out of scope [I].

**JFrog.** RLM is feature-frozen since 31 Jul 2026, with EOL planned for 31 Jan 2028 and migration to AppTrust [V 12]; the Release Bundle v2 air-gap pages carry the same notice [V 10 ex]. With Distribution 2.28.1+, exports can carry attached evidence [V 10 ex]. Docs disagree on whether HF datasets are supported [V 9 ex]. The pricing table is internally inconsistent: ML model repos appear from Pro, Curation from Enterprise X, Release Distribution only at Enterprise+ [V 13, low confidence].

**Sonatype.** Clients set `HF_ENDPOINT` to Nexus. Sonatype suggests ~120 s timeouts, reports slow downloads from S3/Azure Blob stores, and notes some HF files fail strict content-type validation [V 15 ex]. Bearer tokens for gated models need 3.95+ [V 14]. IQ Server's "Hugging Face Model Analysis" capability was not checked [U].

**OpenShift AI.** Because Hugging Face links need internet, Red Hat directs disconnected users to modelcar image paths in a mirrored registry, e.g. `registry.redhat.io/rhelai1/modelcar-granite-3-1-8b-instruct:1.5` [V 18 ex]. Model delivery becomes image mirroring [I]. A Red Hat blog points to a separate helper repo listing images beyond the operator [V 17 ex], a sign the mirror list is hard to get right [I].

**NVIDIA NIM.** The NGC key is used only on the connected host; on the target, mount a model store (`NIM_MODEL_PATH`) or the cache at `/opt/nim/.cache` with `NIM_MODEL_PROFILE` [V 20]. Cache creator and consumer must be the same image type. A model-free NIM given an `ngc://` URI needs network on first start, and a strict offline start fails if that manifest was never cached [V 20]. The `latest` air-gap URL rendered empty, so the 2.0.12 page was used.

**Ollama.** The import and FAQ pages do not cover offline use, copying the models directory, or its layout [V 21,22 by absence], so copying `~/.ollama/models` is undocumented and has no integrity check [I].

**Hugging Face offline failure modes.**
- A file missing from cache raises an error, and `HfApi` calls raise `OfflineModeIsEnabled` [V 23].
- Variables are read at import time, so setting `HF_HUB_OFFLINE` later does nothing [V 23].
- The cache relies on symlinks; Linux-created links may not resolve on Windows or shared drives, and disabling symlinks duplicates large files [V 23].
- Xet downloads land in a cache-wide `blobs/` store symlinked into repo folders [V 23], so copying one model folder alone can leave dangling links [I].
- The `hf` CLI checks PyPI for updates unless `HF_HUB_DISABLE_UPDATE_CHECK=1` [V 23].
- Failures around `trust_remote_code` were not verified in this pass [U].

**LeapfrogAI and UDS.** `defenseunicorns/leapfrogai` and `leapfrogai-sdk` return "Not Found" from the GitHub API on 28 Oct 2026 [V 24]. A search-index copy of a repo issue page showed an archive banner dated 15 Feb 2025, but the page could not be reopened [I, 25]. Iron Bank's LeapfrogAI vLLM project is archived, and a Repo1 ticket says Defense Unicorns will no longer produce or support the Kong image [V 26,27 ex]. UDS docs still list LeapfrogAI in the ecosystem [V 30 ex]. UDS Core itself shipped v1.16.0 on 27 Oct 2026 [V 29].

**Iron Bank.** Onboarding is a hardening manifest, a GitLab CI pipeline and review by the Container Hardening Team. Direct upload of external images is not supported, and parts of hardening are manual [V 31,32 ex]. Its evidence supports, but does not replace, a program's own ATO [V 31,33 ex].

## 4. What is still hard for one GPU server or a small non-Kubernetes footprint

1. **Kubernetes tax.** Zarf/UDS, Replicated and OpenShift AI land on K8s [V 1,8,16], with a registry inside the enclave [V 8,16; I for Zarf]; NIM's chart path adds mirrored images and the GPU Operator [V 20]. On one GPU box that means running K3s/k0s and a registry to serve a single model [I]. Hauler avoids K8s but ends at artifact availability [I].
2. **Size and staging.** Splitting for media exists [V 2,6], but staging needs scratch space near the archive size [V 5], so a 100+ GB model can need a multiple of its size in free disk [I]. No tool reviewed offers chunk-level deltas for a new weight revision; Zarf's differential works per resource [V 2; I].
3. **No model-aware gate before transfer.** Movers do not check pickle versus safetensors/GGUF, record license and model card, or confirm the target runtime supports the architecture [I]. Those checks sit in connected-side repo managers at higher tiers [V 9,13].
4. **Runtime-coupled caches fail late.** NIM ties caches to profile and image type [V 20], HF fails on any missing file [V 23], and Ollama needs a Modelfile import [V 21]. A mismatch surfaces inside the enclave and costs another transfer cycle [I].
5. **Verifying a whole release offline.** cosign exists in Zarf and Hauler [V 1,5], but no tool reviewed signs model + runtime image + config as one release verifiable with only a CLI on the target [I]. Whether keyless verification works fully offline was not checked [U]. JFrog needs an Artifactory inside plus pre-propagated keys [V 10 ex].
6. **Evidence is container-centric.** Iron Bank supplies evidence for containers, not ATOs [V 31 ex]; no equivalent for model weights was found [U].
7. **Cost and fit.** Artifactory air-gap export needs Enterprise+ [V 11 ex]. Replicated serves ISVs shipping their own apps [V 8], not enclaves importing arbitrary open-weight models [I]. OpenShift AI needs OpenShift [V 16 ex].
8. **Durability.** LeapfrogAI is gone from GitHub [V 24], JFrog RLM is sunsetting [V 12], and Zarf is pre-1.0 [V 3]; buyers with long accreditation cycles will weigh vendor durability [I].

## 5. Implications by wedge

- **A (offline deployment and upgrades):** the clearest whitespace. Build a non-K8s, model-aware offline release (weights + runtime image + config + manifest) with pre-transfer checks, an offline dry-run on the connected side, chunked media and on-target verification. It should emit and consume OCI and interoperate with Zarf/Hauler rather than replace them [I].
- **B (access control):** delivery tools do not address model access [I]; it matters once a stack runs inside and could read A's approved-model manifest [I].
- **C (operations):** K8s estates already have UDS or OpenShift tooling [V 28,16 ex]; the single-box gap is real, but ops without delivery is a weaker entry [I].
- **D (evidence):** today's evidence is container-centric (Zarf SBOMs and cosign, Iron Bank, JFrog evidence at higher tiers) [V 1,31,10 ex]; model-specific evidence is missing and falls out of A naturally [I].
- **E (private inference):** crowded with vendor-backed runtimes (NIM, OpenShift AI with vLLM, Ollama) [V 18,20,21]; better as a target of A than as the wedge [I].

## 6. Open questions

- How does Zarf behave with single 50-100+ GB files (compression time, memory, registry push)?
- Does air-gapped NIM in production require NVIDIA AI Enterprise?
- Was LeapfrogAI deleted or made private, and does Defense Unicorns ship a successor?
- Does JFrog AppTrust keep an air-gap export path after RLM's end of life?
- What do enclave transfer processes (cross-domain solutions, media scanning) allow for .safetensors/.gguf files, and at what sizes?
- Replicated pricing, and GPU support in Embedded Cluster.

## Sources (accessed 2026-10-28)

1. https://github.com/zarf-dev/zarf
2. https://docs.zarf.dev/commands/zarf_package_create/
3. https://api.github.com/repos/zarf-dev/zarf/releases/latest
4. https://www.businesswire.com/news/home/20240626960909/en/Defense-Unicorns-Announces-Contribution-of-Zarf-to-OpenSSF
5. https://github.com/hauler-dev/hauler
6. https://docs.hauler.dev/docs/intro
7. https://api.github.com/repos/hauler-dev/hauler/releases/latest
8. https://docs.replicated.com/vendor/embedded-overview
9. https://docs.jfrog.com/artifactory/docs/hugging-face-repositories
10. https://docs.jfrog.com/governance/docs/distribute-release-bundle-v2-versions-in-an-air-gap-environment
11. https://docs.jfrog.com/governance/reference/triggerairgapexport
12. https://docs.jfrog.com/releases/docs/release-lifecycle-management-deprecation-end-of-life
13. https://jfrog.com/pricing/
14. https://help.sonatype.com/en/hugging-face-repositories.html
15. https://help.sonatype.com/en/configure-hugging-face-with-nexus.html and https://help.sonatype.com/en/create-a-hugging-face-repository.html
16. https://docs.redhat.com/en/documentation/red_hat_openshift_ai_self-managed/3.5/html/installing_and_uninstalling_openshift_ai_self-managed_in_a_disconnected_environment/deploying-openshift-ai-in-a-disconnected-environment_install
17. https://www.redhat.com/en/blog/deploying-red-hat-openshift-operators-disconnected-environment
18. https://docs.redhat.com/en/documentation/red_hat_ai/3/html-single/validated_models
19. https://developers.redhat.com/articles/2025/01/30/build-and-deploy-modelcar-container-openshift-ai
20. https://docs.nvidia.com/nim/large-language-models/2.0.12/deployment/air-gap-deployment.html (https://docs.nvidia.com/nim/large-language-models/latest/deploy-air-gap.html returned empty content)
21. https://docs.ollama.com/import
22. https://docs.ollama.com/faq
23. https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables
24. https://api.github.com/repos/defenseunicorns/leapfrogai and https://api.github.com/repos/defenseunicorns/leapfrogai-sdk (both "Not Found"); https://github.com/defenseunicorns/leapfrogai (HTTP 404)
25. https://github.com/defenseunicorns/leapfrogai/issues/976 (search-index copy only; live page HTTP 404)
26. https://repo1.dso.mil/dsop/opensource/defenseunicorns/leapfrogai/vllm
27. https://repo1.dso.mil/dsop/opensource/defenseunicorns/leapfrogai/supabase/kong/-/work_items/7
28. https://github.com/defenseunicorns/uds-core
29. https://api.github.com/repos/defenseunicorns/uds-core/releases/latest
30. https://uds.defenseunicorns.com/docs/what-is-uds
31. https://docs-ironbank.dso.mil/overview/
32. https://docs-ironbank.dso.mil/quickstart/verification/
33. https://docs-ironbank.dso.mil/faq/
