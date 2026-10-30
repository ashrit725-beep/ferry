# Go-to-market: founder-led sales for offline readiness

*Owner: founder. Written 2026-10-28. Status: 0 conversations, 0 pilots, 0 customers, $0 revenue. Follows [02-decision-revision](../strategy/02-decision-revision.md), which overrides 01. Companions: [customer-discovery](customer-discovery.md) (screening, interview scripts, OPSEC, kill criteria K1-K8), [target-list](target-list.md) (who to call), [pilot](pilot.md) (pilot 1 scope, criteria S1-S7, exits E1-E4), [pricing](pricing.md) (all prices), [metrics](metrics.md) and [roadmap](roadmap.md). P1, P2 and A1 are the three rules in customer-discovery §7 "Preconditions and parking", labelled there; pilot.md and pricing.md cite them by content. P1: 5+ of 15 ship weights as OCI artifacts or Zarf packages. P2: 3+ require FIPS mode or an algorithm such as P-256. A1: 4+ of 5 receiving calls say a new executable takes over 6 months. This file covers who to sell to, where to find them, what to say, what to show and when to ask. Labels: VERIFIED (URL or a local check on the build Mac), INFERRED, UNKNOWN. Anything untested is a hypothesis. §3 was cross-checked against target-list on 2026-10-28.*

## 1. Problem statement and positioning

> Teams that deliver AI stacks into customer-operated disconnected networks find missing files and hidden network calls only after the media has been reviewed and carried inside, and each miss costs another transfer cycle or a site visit. Ferry runs the exact launch command with egress denied before the media is written, shows each blocked call with the process or Python library that made it and the documented fix, and ships a manifest the far side checks with stock tools. The goal: no failed transfer, no second trip.

| Claim in the statement | Status |
|---|---|
| "Offline" stacks still reach for the network | VERIFIED in public sources: Hub freshness checks unless `HF_HUB_OFFLINE` is set, LiteLLM's cost map fetched from GitHub at startup, tiktoken vocabulary downloads on a cache miss, vLLM discussion #1405 (opened Oct 2023, still active in 2026) (research/06) |
| Misses are found inside, after transfer, and each one costs a cycle | INFERRED (research/06). Cadence and "weeks of delay" are vendor-blog claims; frequency and cost are UNKNOWN, and discovery measures them (H1, H2) |
| Exact launch command, egress denied, process or library named, fix given | VERIFIED on the build Mac (macOS, Apple Silicon); the library is named for Python code only; fixes exist where one of the 11 rules matches; Linux UNTESTED |
| Manifest checked with stock tools | Signature step VERIFIED (Ed25519 over the exact manifest bytes, `openssl pkeyutl -verify -rawin`, OpenSSL 3+); `ferry pack/sign/verify` IN PROGRESS |
| "No failed transfer, no second trip" | A goal, not a measured outcome (hypothesis). Preflight sees only code paths that run on the connected host; driver, FIPS-mode and hardware differences inside are beyond it (pilot.md §10). Measured per shipment at +30/+60/+90 days (metrics.md §4) |

**Positioning rules.**
- Lead with delivery reliability: on-time go-live, no re-transfer, no site trip, a report the engineer attaches to the transfer request.
- Compliance comes up only when a receiving-side person raises it, and then in evidence language: "produces evidence that can support SI-7(15) and CM-14 reviews", never "meets" or "compliant".
- Against substitutes (detail in pricing.md §2): `docker run --network none` shows that something failed, not which library or which setting (INFERRED). Replicated CMX's `airgap` policy blocks egress and reports source command, PID, destination IP, port and DNS names (VERIFIED, https://docs.replicated.com/vendor/testing-network-policy), with GPUs only as T4-class cloud nodes (VERIFIED, https://docs.replicated.com/vendor/testing-supported-clusters), where `airgap` is not supported (VERIFIED, https://docs.replicated.com/vendor/testing-how-to). So CMX cannot run a GPU launch with egress blocked (INFERRED, research/07 §1.1). It costs $500 a month plus cluster costs (VERIFIED, https://www.replicated.com/pricing). Our untested edge: full-size weights on the vendor's own host with nothing uploaded, the calling library plus its fix, and a stock-verifiable manifest. Concede that CMX names destinations our macOS kernel evidence cannot: macOS redacts them, so only Python calls and output lines carry host names.

## 2. Buyer, champion and influencers

| Role | Side | Owns | Cares about | Must see |
|---|---|---|---|---|
| **Buyer:** Head of Delivery or VP Engineering (also Head of Field or Customer Engineering) at an AI vendor or integrator, 10-200 staff | Vendor | Delivery schedule; tooling budget | Go-live dates; engineer-days, travel and fixed-price exposure lost to misses | Their own last miss, costed in their numbers; a fee they can approve without procurement (pricing.md §4.1; K6) |
| **Champion:** deployment, field or forward-deployed engineer who builds the bundle and takes the failure call | Vendor | The launch command and the media | Catching the miss before media is written; no new infrastructure | The preflight finding something on their real command, on their machine |
| ISSM / ISSO | Receiving | SSP and CM plans (32 CFR 117.18; research/04); admission of new software (INFERRED) | No new executable without review; integrity evidence | That pilot 1 puts nothing inside the enclave; a manifest checkable with `openssl` and `sha256sum` |
| Data transfer agent or transfer reviewer | Receiving | Transfer requests, scans, file-type checks (rules not public; research/04) | Knowing exactly what is on the media | The review sheet: every file with type, size and SHA-256 |
| Enclave platform or HPC lead | Receiving | The install and the runtime | First-time-right installs; fewer vendor visits | A rehearsal or preflight report for the exact runtime build |

Receiving-side people do not buy pilot 1. They can block it (admission), pull for it (by asking vendors for evidence), or become the alternative ICP (customer-discovery §1). The receiving-side gateway, audit log and console are phase 2 (pilot.md §11). Show them only when a receiving-side person asks, and say they are v1 scope, not proven.

## 3. Where to reach them

**Who.** [target-list](target-list.md) is the outreach list. It has 38 organizations, each backed by a verified public page: 28 vendors, 1 integrator, 3 primes, 3 labs or FFRDCs and 3 operators. Each carries an A-C priority, and the list gives a suggested first-call order. Nobody on it has been contacted. Reach receiving-side targets through their vendors where target-list names a warm path: EdgeRunner AI to Army AI2C, Protopia AI to the USAF 309th SWEG, Atomic Canyon to PG&E Diablo Canyon. Defense Unicorns, Palantir, Scale AI, Replicated, NVIDIA and Red Hat are partner or competitor conversations, not prospects.

**Channels.** target-list's channel table is the master list. Cross-checked on 2026-10-28, three of its entries match our own checks: `#zarf` (Zarf README badge), KubeCon NA and SC26 (dates below). Who is in each channel is INFERRED until calls confirm it. Sourcing quotas follow customer-discovery §3 (for example, at most 4 calls from `#zarf`). Contact details never go in the repo.

| Channel (source) | Use in the sales motion |
|---|---|
| sbir.gov award search: the keyword "air-gapped" returned 33 awards (target-list) | Cold email §4a, citing the award abstract as the public source. SBIR firms are small by program rules (INFERRED) |
| Tradewinds Solutions Marketplace, "Awardables" (target-list) | Same; Awardable status is the vendor's own claim |
| `#zarf`, Zarf meetups, Hauler GitHub Discussions (target-list) | Community question §4b; answers also inform K5 |
| OpenSSF `#wg-ai-ml-security` and `#sig-model-signing` (target-list) | Standards conversations for roadmap 2.5 and 3.2 (OMS), not buyers |
| Public failure threads: vLLM #1405 and the vLLM forum's air-gap thread, LiteLLM #25062, Ollama #4498 (research/06; target-list) | Post a fix or finding that helps the thread; never cold-message commenters |
| KubeCon NA, 9-12 Nov 2026, Salt Lake City; SC26, 15-20 Nov 2026, Chicago (https://sc26.supercomputing.org/); ANS Winter Conference, 15-18 Nov 2026, Phoenix (target-list) | Meet targets contacted before the event (none contacted as of 2026-10-28). KubeCon for partners and standards, SC26 for receiving-side calls, ANS for the nuclear rows |
| Referrals: two asked for on every call (customer-discovery §3) | Likely the best channel if H1 holds (INFERRED) |

Added for this plan (verified 2026-10-28, not in target-list):

| Channel | Verified by | Who is there (INFERRED) | Use |
|---|---|---|---|
| vLLM user forum, discuss.vllm.ai (the vLLM Slack is for development coordination) | vLLM README, https://github.com/vllm-project/vllm | Teams serving vLLM, some offline | Reply to offline-mode threads with a reproducible finding; no pitch |
| llama.cpp GitHub Discussions (Q&A, Show and tell) | https://github.com/ggml-org/llama.cpp/discussions | Self-hosters, some vendors | Share a preflight write-up once a rule covers llama.cpp's own `-hf` messages (§5, beat 2b) |
| LiteLLM community Discord and Slack | LiteLLM README, https://github.com/BerriAI/litellm | Gateway operators, some self-hosted enterprise | Ask how air-gapped installs handle the cost map |
| Hugging Face forums, offline-mode threads | research/06 (S23, S24) | Mixed | Same as the failure threads |
| Replicated Community forum (readable without sign-in; categories include "Supporting your customers" and "Packaging an application") | https://community.replicated.com/ | ISV engineers shipping into customer sites, some air-gapped | Read for air-gap delivery pain and for where CMX stops |
| AI vendors' job postings that mention air-gapped delivery | customer-discovery §3 (no posting verified here) | Organizations, not people: a sign that they ship into disconnected sites | Qualify the organization, then ask for a warm intro to delivery leadership |

Not verified yet, so no time spent on them: DoDIIS 2027 and S4x27 (target-list); Platform One and Iron Bank channels, and r/LocalLLaMA (research/05); the 2027 date of the NCMS annual seminar (held each June). AFCEA TechNet Cyber 2027 (10-13 May, Baltimore) and SOF Week 2027 (3-6 May, Tampa) are confirmed only by a listing or a search excerpt (target-list).

## 4. Outreach drafts

### 4a. Cold email to a Head of Delivery

**DRAFT - DO NOT SEND WITHOUT FOUNDER REVIEW**

> Subject: catching offline failures before the media is written
>
> Hi [first name],
>
> [Organization] delivers [product] into customer sites without internet access ([public source from target-list: SBIR abstract, docs page or release]). I'm building a tool for one step of that. Before the media is written, it runs your exact launch command with the network blocked, lists each connection attempt with the process that made it (for Python code, the library too), and gives the documented offline fix where one is known. It works on macOS today; the Linux version is written but not yet tested on a Linux host.
>
> Public issue trackers show "offline" stacks still reaching out: vLLM calling the Hugging Face Hub with HF_HUB_OFFLINE=1 set (discussion #1405), LiteLLM fetching its cost map from GitHub at startup, tiktoken downloading vocabulary files on a cache miss.
>
> We have no customers yet, and I'm trying to learn how often this hits delivery teams and what a miss costs. Could you, or the engineer who builds your offline bundles, spare 30 minutes in the next two weeks? Unclassified only; I don't need customer or site names.
>
> [Founder name], Ferry (working name)

### 4b. Message for a community channel (`#zarf`, vLLM forum)

**DRAFT - DO NOT SEND WITHOUT FOUNDER REVIEW.** Read the channel's rules first; post once; no follow-up DMs.

> Question for people who deliver LLM stacks into disconnected sites: how do you find the hidden network calls (Hub freshness checks, cost-map downloads, tokenizer fetches, telemetry) before the bundle crosses? I'm building a tool for this, so I'm biased. It runs the launch command with egress denied and maps each attempt to the process (for Python, the library) and, where a rule exists, its documented offline setting. macOS only so far; Linux is untested. What does your pre-transfer check look like today, and what got past it last time?

### 4c. Follow-up after a call

**DRAFT - DO NOT SEND WITHOUT FOUNDER REVIEW**

> Thanks for the time today. What I heard: [their words: the last miss, how it was found, what it cost]. Please correct anything I got wrong.
>
> If it's useful, I can join you for an hour while you run `ferry preflight` on [the launch command], on your own build or staging machine. Nothing leaves it, and I don't need your model, logs or customer details. You keep the report: each blocked attempt, the process or library behind it and the documented fix where one is known. A clean result is a useful answer too. [If their host is Linux: "Linux support is implemented but we haven't tested it on a Linux host yet. Either we validate it first, or we treat your run as a joint first test."]
>
> It needs the exact command and environment, the full weights in place, and a URL that answers when the service is ready. Would [date A] or [date B] work? And whose view should I hear on the receiving side, a transfer reviewer or ISSM, about what they need to see?

## 5. 15-minute demo

Discovery comes first: no pitch or demo until the close (customer-discovery §4). Show only what ran on the build Mac. Call the leaky app a test double. Never present the gateway or console as proven.

**Prep, the day before, on the demo Mac:**
- `pip install -e .`, then `demo/fetch-model.sh` (pinned Qwen2.5-0.5B-Instruct Q4_K_M GGUF, Apache-2.0, SHA-256 checked). `llama-server --version` reported 0.7.0, build 11669, on 2026-10-28.
- `pytest tests/test_sandbox.py tests/test_preflight.py` passes, including `test_isolation_actually_blocks_egress`.
- Copy the test double's `APP` and `LEAKY_LIB` strings from `tests/test_preflight.py` into `demo/work/leaky/app.py` and `demo/work/leaky/site/fake_hub_client/__init__.py` (`demo/work/` is git-ignored). It looks up huggingface.co and connects only to an RFC 5737 address, so nothing connects to a third party; if isolation failed, only that DNS query would leave the Mac.
- `openssl version` must report OpenSSL 3 or later. macOS's `/usr/bin/openssl` is LibreSSL 3.3.6 and cannot load the Ed25519 key (local check, 2026-10-28).
- Until `ferry/cli.py` lands, type `python -m ferry.cli_offline preflight` wherever this says `ferry preflight` (same flags).
- Dry-run every command and keep the dry-run reports as a labelled backup. Beats 1, 2, 2b and the fallback of beat 3 were dry-run on 2026-10-28; their results are below.

| Time | Beat | Command, and what the dry run showed |
|---|---|---|
| 0:00-2:00 | Frame | "You described [their miss]. Here is the check that would have run before the media was written." If they have no miss to describe, show beat 1 only and move to qualification |
| 2:00-6:00 | 1. Leaky app fails, with attribution and fix | `ferry preflight --ready-url http://127.0.0.1:8081/health --env PYTHONPATH=demo/work/leaky/site --md demo/work/leaky.md -- python demo/work/leaky/app.py 8081 leaky`. Result: FAIL; isolation `sandbox-exec`, egress blocked inside the sandbox: yes; Python hook `fake_hub_client getaddrinfo huggingface.co:443` and `__main__ connect 198.51.100.7:443`, each with file and line; kernel denial `Python(pid) remote:*:443`; finding "huggingface_hub / transformers / datasets [documented]" with the fix (`HF_HUB_OFFLINE=1` before start, local paths, ship the cache). Open the Markdown report: the engineer attaches this to the transfer request |
| 6:00-9:00 | 2. Real model passes | `ferry preflight --ready-url http://127.0.0.1:8080/health --request-url http://127.0.0.1:8080/v1/chat/completions --request-json demo/work/chat.json --md demo/work/llama.md -- llama-server -m .cache/upstream/qwen2.5-0.5b-instruct-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf --host 127.0.0.1 --port 8080 --offline --no-webui -c 1024`, where `chat.json` holds one user message and `max_tokens` 8. Result: PASS, ready in about 1 s, smoke request HTTP 200 (in the report), token counts recorded, completion text never stored, 0 attempts. Say: a pass is evidence for this command on this machine, not for another host |
| optional | 2b. Same server, Hub reference | Replace `-m <file> --offline` with `-hf <repo>`, using a repo name that does not exist so nothing could download. Result: FAIL, from one output line ("failed to resolve commit"); the kernel also shows `llama-server(pid)` making a blocked DNS lookup, which on its own is only a warning unless `--strict` is set; **no fix**, because no rule covers llama.cpp's own Hub messages yet. Use it with engineers as the honest example of how the rule base grows (roadmap 1.3) |
| 9:00-12:00 | 3. Signed manifest, stock tools | If `ferry pack/sign/verify` pass their tests on the demo build and `ferry/cli.py` exists (it did not on 2026-10-28, and `ferry.cli_offline` has only preflight and rehearse): `ferry keygen`, `ferry pack demo/qwen2.5-0.5b-instruct.bundle.toml --key <key>` (flags per docs/design/v1-spec.md §10; check `--help`), then the reviewer steps in pilot.md §4.5: `sha256sum -c`, `tar -xf`, `openssl pkeyutl -verify -rawin -pubin -inkey publisher.pub.pem -in check/manifest.json -sigfile check/signatures/KEY_ID.sig`. Fallback (dry-run 2026-10-28): sign a manifest listing the Qwen file's size and SHA-256 with `ferry.crypto`, then verify it with the same `openssl` line ("Signature Verified Successfully"); `shasum -a 256` on the model matches the manifest digest. Say pack is v1 scope, in progress. Either way, change one field and verify again: "Signature Verification Failure", exit 1 |
| 12:00-15:00 | Offer and next step | Concierge preflight (§6) on their command, with two dates; any §7 questions still open; ask for two referrals |

For a receiving-side audience, swap beat 2 for the audit-log check: change one stored event in a scratch database and run `ferry.audit.verify_chain` (until `ferry audit verify` lands). In a 2026-10-28 dry run it returned `ok: false`, named the changed event's sequence number and reported "event content does not match its hash (modified)". Keep beat 3.

**Objections, answered honestly:**
- *"We already test with `--network none`."* "Would that check have caught your last miss?" Then the fact: it reports that something failed, not the library or the setting (INFERRED).
- *"CMX has an airgap mode."* Correct (VERIFIED), on VMs and VM-based clusters only; its GPU cloud clusters cannot use it (VERIFIED, research/07 §1.1). Ask whether they use it, and whether their weights and GPUs fit. Concede that it names destinations for every process, where our macOS kernel evidence shows ports only.
- *"Will it run on our Linux GPU host?"* The Linux path is implemented and untested. Ubuntu 24.04 restricts unprivileged user namespaces by default, and STIG-hardened RHEL disables them, so we validate first or run a declared joint first test (pilot.md §4.1; roadmap 1.1).
- *"vLLM? NIM? Containers?"* We wrap the launch command. The rule base has documented vLLM usage-stats and Hub entries, but nothing has been tested on CUDA. Containers most likely get output scanning only today (INFERRED, pilot.md §4.1).
- *"Our customer needs FIPS or P-256."* Signatures are Ed25519 today, so defer the pilot (pilot.md E3). P-256 moves up if P2 fires (roadmap 2.1).
- *"Is it open source? What does it cost?"* Licence terms are undecided (pilot.md §5). Price only at the pilot ask, after they name their own no-procurement limit (pricing.md §6).

## 6. Concierge preflight offer

The wording, venue and boundaries are fixed in customer-discovery §8. In short:
- **The offer:** one hour, at the close of every qualifying vendor call. The prospect runs `ferry preflight` on their exact launch command, on their own connected-side host, while the founder watches over their screen share. Never inside an enclave or on a system holding CUI or classified data.
- **What they keep:** the JSON and Markdown report, and a re-run after fixes.
- **What we record, with permission:** counts only. Attempts found, attempts attributed, fix available, new to the team (Y/N), and unmatched attempts (rule-base gaps). No copy of the report unless they offer one.
- **Price:** free. It is discovery and the demo on the prospect's own stack that starts K7's 45-day clock. It is never reported as a pilot (metrics.md §5).
- **Platform:** macOS today. Linux only after roadmap 1.1, or as a declared joint first test where tool failures are not scored against their stack.
- **It succeeds** when it finds an attempt the team did not know about, or when a clean result (a `--strict` pass with no warnings) is something they will attach to the transfer request.

## 7. Qualifying for a pilot

Screening (who counts as a call) is customer-discovery §2. Pilot eligibility is pilot.md §2. These questions decide whether to make the pilot ask, and each maps to a criterion.

| # | Question | Qualifies when | Maps to |
|---|---|---|---|
| 1 | When is your next delivery or update into a disconnected site? | Being prepared within 60 days | pilot.md §2 |
| 2 | What broke after transfer in the last 12 months, and how was it found? | A dated miss, the item named, a cost given | K1 |
| 3 | What did the fix take? | More than 2 business days, extra transfers or travel | K2 |
| 4 | What do you run before shipping, and would it have caught that? | No, or not for this kind of miss | K3 |
| 5 | Runtime, accelerator, containers, Kubernetes? | A path we can preflight on macOS now, or on Linux after roadmap 1.1; not Kubernetes-only | K4, K5, E2 |
| 6 | Build-host OS; does the target run FIPS mode or require a signature algorithm? | No FIPS or P-256 requirement for pilot 1 | P2, E3 |
| 7 | How do weights travel: files, HF cache, OCI artifact, Zarf, Hauler? | Files or HF cache | P1, E3 |
| 8 | What does the receiving reviewer ask for, and which tools check it? | Stock tools accepted | H6, A1 |
| 9 | Can you run a third-party CLI on the build host, and who approves it? | Yes, within 2 weeks | K7 |
| 10 | Who approves delivery tooling, and what is the largest purchase made without procurement? | A named budget owner and a limit at or above the pilot fee | K6, pricing.md §4.1 |

Disqualify for now: no customer-operated disconnected deliveries; provider-run classified clouds only; Kubernetes-only delivery (log it toward K5); no way to run third-party tools on the build host.

## 8. Pilot and the step after

**Pilot 1** is defined in pilot.md: connected side only, 10 business days, one real shipment, up to 3 launch commands, pack and sign, a reviewer packet, and stock-tool verification. Pricing is in pricing.md §4.1 ($5,000 fixed per shipment, a hypothesis; test range $2,500-$7,500). Offer it only after pack/sign/verify pass their tests, and say plainly that they are v1 scope. The pilot passes on S7, S1 and S5, with S4 holding (pilot.md §6).

**After a successful pilot** (pilot.md §13 has the full list):
1. Hold the readout with the engineer and the budget owner. Their baseline (B2, B3) against the pilot numbers is the sales case; keep the write-up internal unless they give written permission.
2. Ask for the next commitment in the same meeting: the next shipments at the pilot fee, or a subscription per delivering team ($24,000 a year, a hypothesis) with the pilot fee credited if signed within 90 days (pricing.md §4.1-4.2; pilot.md §13). Only cash received counts as revenue (metrics.md §5).
3. Track the real delivery at +30, +60 and +90 days: transfer cycles and days to running inside. This "no second trip" outcome comes only from the customer's written confirmation.
4. Ask for two introductions: a peer vendor, and the receiving-side reviewer or ISSM who checked the manifest. The second tests the review sheet and phase 2's admission path. No discount in exchange for a reference.
5. Turn every unmatched attempt from the pilot into a rule with a source and a regression test (roadmap 1.3). Re-rank the roadmap by what the pilot needed.

## 9. Calendar and cadence

| Date | Event |
|---|---|
| 2026-10-29 | Recruiting starts (customer-discovery §7) |
| 2026-11-02 | YC Winter 2027 deadline, 8pm PT (VERIFIED, https://www.ycombinator.com/apply); report numbers per metrics.md §6 |
| 2026-11-02 to 2026-12-04 | Discovery calls (none 2026-11-25 to 11-27); offer a concierge preflight at every qualifying close |
| 2026-11-09 to 11-12 | KubeCon NA (optional: partners and standards) |
| 2026-11-15 to 11-20 | SC26 (optional: receiving-side calls) |
| 2026-12-09 | Decision: continue, re-scope or kill (customer-discovery §7) |
| 2027-01-23 | Final K7 check for demos held by 2026-12-09 |

Weekly: count sends, replies, calls, concierge offers and acceptances, and pilot asks in the ledger (metrics.md §5). Response rates are UNKNOWN, so set outreach volume after the first week, from the pace needed for 15 calls by 2026-12-04.
