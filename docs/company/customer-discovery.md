# Customer discovery plan

*Owner: founder. Written 2026-10-28; decision **2026-12-09**. Status: 0 calls held; no customers, pilots or revenue. Follows [02-decision-revision](../strategy/02-decision-revision.md), which overrides [01](../strategy/01-wedge-decision.md). Labels: VERIFIED (source given), INFERRED, UNKNOWN. Customer claims are hypotheses until tested; thresholds are ours.*

## 1. Hypotheses

Under test: the 02 wedge, offline readiness for AI deliveries. `ferry preflight` is VERIFIED on macOS only; pack/sign/verify, `ferry rehearse` and the receiving side are v1 scope, in progress.

| ID | Hypothesis | Favours vendor-side ICP (primary) | Favours receiving-side ICP (alternative) |
|---|---|---|---|
| H1 Pain | Deliveries fail after transfer: caused outside, found inside (INFERRED, research/06) | 5+ of 10 vendor calls give a qualifying incident (§6) | 3+ of 5 receiving calls do, at a higher rate |
| H2 Cost | A miss costs a transfer cycle, median 3+ business days; only vendor blogs claim "weeks" (UNKNOWN, 06) | Vendor pays: fixed-price work, travel, engineer days | Site pays: schedule, reviewer time |
| H4 Substitutes | Few run a network-denied smoke test; those who do missed their last incident | Vendor tests missed it | Only site import catches misses |
| H6 Admission | New executables take months to admit; stock `openssl`/`sha256sum` checks are accepted (INFERRED, 02) | Slow or refused: a connected-side pilot wins | A tool admitted within 90 days in the last 12 months; demand for import, gating, audit |
| H7 Buyer | A delivery head approves a per-shipment fee without procurement | 3+ vendor budget owners state a price | A receiving budget owner states a price and a recently used path |

**Neutral scope hypotheses:** **H3** misses sit in Python and container stacks (Hub calls, tokenizers, wheels), not self-contained GGUF + llama.cpp (02, point 1). **H5** serving is vLLM, SGLang or NIM on CUDA (INFERRED). **H8** targets are mostly non-Kubernetes, and weights travel as files, not OCI artifacts (UNKNOWN; 02, points 5, 7).

**Substitutes (checked 2026-10-28):** Replicated CMX's `airgap` policy blocks egress while its network reports still capture source command, PID, destination IP, port and DNS names (VERIFIED [R1]). `airgap` runs only on VMs and VM-based clusters; cloud-based distributions do not support it (VERIFIED [R11]). CMX GPU types are T4-class, on EKS, GKE and AKS cloud clusters only (VERIFIED [R2, R3]), so no CMX run combines a GPU with egress blocked (INFERRED; research/07 §1.1). CMX is sold standalone at $500 a month plus cluster costs (VERIFIED [R12]). `docker run --network none` leaves only loopback (VERIFIED [R4]). INFERRED: CMX reports destinations that our macOS log redacts for non-Python processes; our untested edge is full-size weights on the vendor's own GPU host, attribution with a fix, and a stock-verifiable manifest.

**ICP choice (2026-12-09):** the receiving side becomes primary only if it beats the vendor side on two of: qualifying-incident rate (with 3+ of 5), a budget owner with a price, and a new-tool admission path used in the last 12 months.

## 2. Screening criteria

**Vendor-side, all of:**
1. Personally built, shipped or debugged an AI model-plus-serving delivery to a customer site since 2025-11-01.
2. Site **D** (genuinely disconnected: no route out; updates by reviewed media or one-way transfer) or **R** (restricted: egress only via an internal mirror or allowlist). At most 3 of 10 vendor calls may be R-only: an R-site miss is a change request, not a media cycle (01).
3. Customer-operated, not a provider-run classified region (AWS Top Secret, Azure Government Top Secret, Google Distributed Cloud air-gapped; VERIFIED [R10]), IL5 commercial cloud or on-prem with egress.
4. Deployment, field or forward-deployed engineer, or the Head of Delivery or VP Eng who owns delivery, at an AI vendor or integrator.

**Receiving-side:** ISSM/ISSO, data transfer agent or enclave platform/HPC lead at a national lab, FFRDC, prime or integrator whose enclave imported (or tried to) AI models or software in the last 12 months.

**Both:** can speak in unclassified terms. No hobbyists or second-hand accounts; log competitors separately.

## 3. Call mix, sourcing and OPSEC

**Mix:** 10 vendor-side calls across 7+ organizations (6+ engineers, 3+ delivery heads; same-organization pairs are ideal). 5 receiving-side calls across 2+ organization types (1+ ISSM/ISSO, 1+ data transfer agent, 2+ platform leads).

**Sourcing** (channels only): `#zarf` on Kubernetes Slack (VERIFIED [R5]; it skews to Kubernetes, so cap it at 4 calls); public offline-failure threads such as vLLM #1405, LiteLLM #25062 and Ollama #4498 [R6-R8] (mostly hobbyists, 06; screen hard); vendor job postings that mention air-gapped delivery, then warm intros; two referrals per call. The ask (draft; nothing sent): 30 minutes on their latest disconnected delivery, unclassified, no pitch.

**OPSEC:**
- Open with: "Nothing classified, CUI, export-controlled or under customer NDA, please. I want what broke, not where."
- Record month or quarter, site type and component only. Never site, customer, program, network or system names, locations, hostnames, IPs, enclave architecture, findings or people.
- Don't ask for the DAAG or site procedures; DCSA distributes the DAAG through NISP eMASS, not publicly (VERIFIED via excerpt [R9]).
- If sensitive detail starts, stop the speaker and write nothing.
- No recording by default; consented recordings stay outside the repo and are deleted after coding.

## 4. Interview scripts

Incident first; no pitch until the close. Don't read the component codes aloud; code what they describe (§5). If the last delivery went fine, go back up to three, then move on.

### 4a. Vendor-side (40 min; delivery heads answer across deliveries)
1. Tell me about your last delivery or update of an AI model or application into a customer site with no internet. Roughly which month?
2. What went into it, and how did it travel?
3. Did anything not work the first time?
4. How did you find out? Who noticed, and how long after the media arrived?
5. What turned out to be the cause? (If unsure: which part of the stack?)
6. What did the fix take: how many more transfers, how many days until it ran inside?
7. Who paid, in hours, travel, schedule or contract terms?
8. What, if anything, do you run before shipping to check it works offline, and when did you last run it? Would it have caught this? Why? (Follow-up: have the full weights ever gone to a third-party test environment, and did a contract, CUI or export rule stop that? This tests research/07's R1.)
9. How do you serve the model (runtime, accelerator, containers, Kubernetes)? What OS hardening or crypto policy does the target enforce, and has it broken anything?
10. When did a customer last admit a new tool or executable from you? What did it take, and who said yes? (Follow-up only: would they admit a new binary now?)
11. What's the largest tooling purchase your team approved without procurement? Who would sign a paid pilot for delivery tooling?
12. Close (§8); ask for two referrals.

### 4b. Receiving-side (35 min)
1. Tell me about the last time an AI model or AI software came into your enclave from outside. Roughly when?
2. In general terms, what steps did it go through before it ran?
3. Did anything go wrong or take longer than expected? At which step was it found? What was the item?
4. How many days and transfer requests until a corrected package ran?
5. What did the reviewer need to approve the files, and what did the vendor provide?
6. How do you check integrity on arrival, and with which tools?
7. When did you last admit a new executable (not data)? How long did it take? Who approved?
8. Who decides which models users may run, and how is that enforced?
9. Who approved your last enclave software purchase, via which path? Largest purchase without formal procurement? Who would approve a pilot?
10. Close: show a sample manifest verified with stock OpenSSL; ask what the reviewer would still need, and for vendor intros.

### 4c. Questions not to ask

Each has a past-behaviour replacement in 4a-4b.

- "Would you use or buy a tool that ...?" Hypothetical; politeness predicts nothing.
- "Is offline failure a big problem?" Leading; invites a pleasing pain rating.
- "Was it tiktoken, the Hub, a wheel ...?" Primes our rule base and inflates H3.
- "How long was the re-transfer?" before one is mentioned. Presumes one happened.
- "How much would you pay?" A hypothetical anchor; past purchases are evidence.
- "Wouldn't `--network none` or CMX miss this?" Hands them our argument.
- "Would your ISSM approve Ferry?" Speculation on someone else's behalf.
- Site, customer, program or system specifics. OPSEC; notes become unstorable.

## 5. Per-call note template

One file per call (`docs/company/calls/V-01.md`, `R-01.md`) with role titles and organization types only; organization names need permission. Contact details stay in the founder's contact store outside the repo, keyed by call ID.

```markdown
# V-01 | 2026-11-__ | recording: none
Role title: | Org type, size band: | Org name (with permission):
Screen: site D/R, month __ | customer-operated Y/N | qualifies Y/N | withheld anything Y/N (never what)

## Incidents (last 12 months, first-hand)
1. Month, D/R, stack, code, item, found how/when, extra transfers, days to fix inside, who paid/cost, current test would catch Y/N/U

## Practice
Pre-ship test (none / --network none / CMX airgap / netns script / other), last run __
Serving: runtime, accelerator, containers, Kubernetes (which) | Weights as: files / HF cache / OCI / Zarf / Hauler
Target: FIPS mode Y/N/U, signature algorithm, arrival check tools | Last executable admitted: month, days, approver role

## Buying and next step
Budget owner role, confirmed Y/N | Largest no-procurement purchase $__, item | Pilot 1 price they could approve $__, approver role
Concierge offered/accepted/declined, date | Own-bundle demo date, 45-day clock end | Commitment: none / LOI / paid pilot $__ | Referrals (count)

## Coding
Qualifying incident Y/N | Codes | Disconfirming evidence | Paraphrase (verbatim only with permission)
```

**Codes:** MS model server; APP application; AUX auxiliary model, tokenizer or vocabulary; WHL wheels or packages; DRV driver or CUDA; FIPS FIPS mode or crypto policy; WGT weights or config incomplete; IMG container image or registry; OTH. Add NET when the item made a network call.

## 6. Synthesis method

- **Qualifying incident:** first-hand; month or quarter within 12 months of the call; the item named at component level or finer ("the embedding model's tokenizer", not "a dependency"); a cost in days, transfers, hours, travel or money. Second-hand stories are logged, never counted.
- **Ledger:** one row per incident in `docs/company/discovery-ledger.csv`. An event told twice counts once, under the more detailed call. Code within 24 hours, before looking at the tally.
- **"Current test would catch" = Y** only if it ran the same launch command with the real weights and the failure would have shown.
- **Tally after calls 5, 10 and 15:** every §7 metric per segment, plus the component mix and concierge findings new to the team.
- **Weighting:** incidents, money spent and tests actually run count. Opinions and intentions count zero.
- **Bias checks:** log every disconfirming answer; after call 8, audit the notes against §4c; compare the component mix with public evidence (06) and explain divergence.

## 7. Kill and re-scope criteria (applied 2026-12-09)

| ID | Condition | Action |
|---|---|---|
| K1 | Fewer than 5 of 15 give a dated incident naming the missing item and a cost | Kill this wedge; rescore A-E |
| K2 | Median days to fix inside: 2 business days or less | Re-scope to restricted-network CI hygiene at a lower price, or kill |
| K3 | 5+ of 15 already run a network-denied smoke test that would have caught their last qualifying incident | If 3+ of them name a gap it leaves (GPU path, full-size weights, attribution, manifest), re-scope to that; otherwise kill |
| K4 | 8+ of 15 serve via vLLM, SGLang or NIM on CUDA | Support that path on a Linux CUDA host before any demo counts toward K7 |
| K5 | 10+ of 15 deliver to Kubernetes (Zarf/UDS, OpenShift, Embedded Cluster) or provider clouds | Re-scope as a Zarf/Hauler extension with OCI/cosign outputs |
| K6 | Fewer than 3 named budget owners (budget role confirmed) state a price they could approve without procurement | Vendor pricing fails: switch to the receiving side if the §1 ICP rule favours it; otherwise kill |
| K7 | No LOI or small paid pilot within 45 days of a demo on the prospect's own bundle, or fewer than 3 concierge acceptances by 2026-12-09 | Kill. Demos held by 2026-12-09 get a final check on 2027-01-23; later demos run their own 45-day clock |
| K8 | Under half of qualifying incidents carry NET, AUX, WHL or WGT (DRV or FIPS dominate) | Re-scope toward target-environment rehearsal (driver, FIPS mode) |

**Preconditions and parking** (gtm.md and roadmap.md cite these as P1, P2 and A1): **P1:** if 5+ ship weights as OCI artifacts (ModelPack, KitOps, `docker model`) or Zarf packages, OCI/cosign output must precede pilot 1. **P2:** if 3+ require FIPS mode or an algorithm such as P-256, P-256 signing must precede pilot 1 (signatures are Ed25519 only today). **A1:** if 4+ of 5 receiving calls say a new executable takes over 6 months or is impossible, phase 2 stays parked and stock-tool verification is mandatory.

**Timeline:** recruit from 2026-10-29; calls 2026-11-02 to 2026-12-04, skipping 2026-11-25 to 11-27; tallies after calls 5 and 10; synthesis 2026-12-07; decision 2026-12-09.

## 8. Call to action: concierge preflight

Offer at the close of every qualifying vendor call: "If it's useful, I can join you for an hour while you run `ferry preflight` on your exact launch command, on your own machine. The report stays with you, and I don't need your model, logs or customer details. A clean result is a useful answer too."

- **Where:** their connected-side build or staging host, never an enclave or a system holding CUI or classified data. macOS works today (VERIFIED). Linux isolation is implemented but untested: test it on a Linux host first, or call it a joint first test and don't score tool failures against their stack.
- **What they get:** pass/fail; the in-sandbox egress probe; blocked attempts (process, PID, port); Python DNS lookups and connects with host and calling module; network-failure output lines; a documented offline fix wherever one of the 11 rules in `ferry/offline_rules.py` matches (Hugging Face Hub and its CLI, tiktoken, LiteLLM cost map, vLLM usage stats, Gradio, Chroma, Ollama, Open WebUI auxiliary models, pip/PyPI, GitHub assets; the Gradio and Chroma host names are labelled inferred). By default a blocked DNS lookup that the Python hook cannot attribute is a warning, not a failure; use `--strict` for any run they will rely on. Ferry has no telemetry; its only outbound attempts, a connect to never-routed 192.0.2.1 and one DNS lookup of example.com, are meant to fail (ferry/sandbox.py; docs/network-dependencies.md).
- **The founder records** (coded, with permission): attempts found, attributed, fix available, new to the team Y/N. The run tests H3 and H4 and is the own-bundle demo that starts K7's clock (subject to K4).
- **Next ask**, if it found something worth catching on every shipment: pilot 1 on their next real shipment, connected side only (preflight, pack and sign, review sheet, far-side check with `openssl` and `sha256sum`), for a fixed fee per shipment (pricing.md §4.1). Make this ask only once pack/sign/verify pass their tests (roadmap.md 1.2; gtm.md §8), and say they are v1 scope, not proven. Ask who signs and what price they could approve without procurement.

## Sources (accessed 2026-10-28)

- R1 https://docs.replicated.com/vendor/testing-network-policy
- R2 https://docs.replicated.com/vendor/testing-supported-clusters
- R3 https://docs.replicated.com/vendor/testing-about and https://docs.replicated.com/vendor/testing-vm-about
- R4 https://docs.docker.com/engine/network/drivers/none/
- R5 https://github.com/zarf-dev/zarf
- R6 https://github.com/vllm-project/vllm/discussions/1405
- R7 https://github.com/BerriAI/litellm/issues/25062
- R8 https://github.com/ollama/ollama/issues/4498
- R9 https://www.dcsa.mil/Portals/128/Documents/CTP/tools/250930%20VOI%20Newsletter.pdf (search excerpt; direct fetch returned 403)
- R10 https://aws.amazon.com/blogs/publicsector/amazon-bedrock-launches-with-claude-3-5-sonnet-in-the-aws-top-secret-cloud, https://devblogs.microsoft.com/azuregov/unlocking-new-possibilities/, https://www.infoq.com/news/2025/04/google-gemini-gdc-preview
- R11 https://docs.replicated.com/vendor/testing-how-to (air-gap section: cloud-based distributions do not support the `airgap` policy)
- R12 https://www.replicated.com/pricing (CMX $500/month plus cluster costs; no base plan purchase required)
- Memo citations: URLs are in docs/research/04, 05 and 06.
