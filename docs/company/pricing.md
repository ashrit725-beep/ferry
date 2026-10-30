# Pricing hypothesis and cost model

*Owner: founder. Written 2026-10-28. Status: hypothesis only. No prospect has seen these prices. There are no customers, interviews, pilots or revenue, so nothing here is evidence of willingness to pay. USD, excluding tax. Labels: VERIFIED (URL or memo source), INFERRED, UNKNOWN. Companions: [pilot](pilot.md), [customer-discovery](customer-discovery.md).*

## 1. The hypothesis in brief

| Step | Unit | Price (hypothesis) | Test range | Main assumption |
|---|---|---|---|---|
| Pilot, "delivery hardening" | One shipment (pilot.md phase 1) | $5,000 fixed | $2,500-$7,500 | Fits the budget owner's no-procurement limit (UNKNOWN) and costs less than one miss |
| Repeat shipments | Per shipment, pilot scope minus onboarding | $5,000 | $3,000-$6,000 | Suits teams that ship 4 times a year or less |
| Subscription | Per delivering team, per year | $24,000 | $12,000-$36,000 | 5+ deliveries a year per team, each saving roughly 2-7 engineer-days or equivalent schedule cost |
| Receiving side (optional) | Per enclave, per year | $12,000 if the enclave owner pays; $3,000-$6,000 if the vendor passes it through | $6,000-$15,000 enclave-paid | Federal buyers can use the $15,000 micro-purchase threshold; admission, not price, is the real barrier |
| Services | Day rate, connected side only | $2,000 per day plus travel at cost | none yet | Kept under 20% of revenue |

The logic: price where the pain occurs (a shipment), convert to the unit that recurs (the delivering team), and sell the receiving side separately to whoever controls it (the enclave owner).

## 2. Substitutes and anchors

### 2.1 An engineer's time: the main competitor

- Median annual wage for software developers: $135,980 in May 2025 (VERIFIED [S1]).
- Wages and salaries are 70.0% of private-industry employer compensation cost, June 2026 (VERIFIED [S2]).
- Loaded cost: $135,980 / 0.70 ≈ $194,000 a year, ≈ $845 per working day (230 days), ≈ $106 per hour (INFERRED arithmetic). Senior or cleared delivery engineers probably cost more (UNKNOWN).

| Self-built equivalent | Effort (INFERRED) | Cost at $845 per day |
|---|---|---|
| Build a network-denied smoke test, manifest and hash list once | 3-10 engineer-days | $2,500-$8,500 |
| Run and triage it for each delivery | 0.5-2 days | $420-$1,690 per delivery |
| Keep the list of offline switches current (Hub, vLLM, LiteLLM, tiktoken, ...) | 2-4 days per quarter | $6,800-$13,500 a year |

What a script usually lacks (INFERRED): attribution of each call to the library that made it, with a documented fix; a signed manifest the far side checks with stock OpenSSL; a review sheet for the transfer reviewer; a rule base fed by many stacks.

### 2.2 `docker run --network none`

- It leaves the container only a loopback interface (VERIFIED [S3]).
- Docker Engine costs $0. Docker Desktop is free for organizations under 250 employees and under $10M revenue; otherwise $9-$24 per user per month, billed annually (VERIFIED [S4, S5]).
- What it lacks (INFERRED): which library called out and how to turn it off; coverage of stacks that are not containers; anything about the bundle. Failures surface only as errors in the logs.

### 2.3 Replicated Compatibility Matrix (CMX), `airgap` policy

- Blocks egress, and its network reports still capture source command, PID, destination IP and port, and DNS names (VERIFIED [S6]).
- VMs cost $0.096 an hour (2 vCPU, 8 GiB) to $1.536 an hour (32 vCPU, 128 GiB), plus $0.50 per VM start, billed per minute from credits (VERIFIED [S7]). A 4-hour run on an 8-vCPU VM is about $2.04 (INFERRED arithmetic).
- GPU instance types exist only on cloud clusters (EKS, GKE, AKS), T4-class, at $0.321-$6.528 an hour (VERIFIED [S7, S8, S9]). The `airgap` policy runs only on VMs and VM-based clusters; cloud-based distributions do not support it (VERIFIED [S12]). So no CMX run combines a GPU with egress blocked (INFERRED; research/07 §1.1).
- CMX is sold standalone: $500 a month plus cluster costs, with no base plan purchase required (VERIFIED [S13]; research/07 §1.1). That is about $6,000 a year plus credits, a quarter of the $24,000 subscription hypothesis (§4.2). Replicated's distribution plans ($2,000 a month and up; research/05 §5 [42]) are a separate product.
- INFERRED: a CMX run costs a few dollars on top of the monthly fee, so per-run credits cannot anchor our price, but the $500 monthly fee is a visible reference for a connected-side test tool. Any premium over it has to come from what CMX lacks: full-size weights on the vendor's own GPU host with nothing uploaded, library attribution with fixes, and a stock-verifiable signed manifest. CMX does report destinations better than our macOS evidence, because macOS redacts addresses.

### 2.4 Public price points buyers already pay (research/05 §5, VERIFIED there; CMX row VERIFIED [S13])

| Product | Price | Relevance |
|---|---|---|
| Replicated | Builders $2,000/month + $50 per license per month; Business $3,000/month + $200 per license per month [42] | What a vendor pays to distribute into customer sites. The per-license fee ($600-$2,400 per install per year) anchors per-site fees |
| Replicated CMX | $500/month plus cluster costs, sold without a base plan [S13] | The closest substitute for a network-denied test (research/07 §1.1). The $24,000 subscription is 4x its yearly fee |
| JFrog | Self-managed Pro X from $27,000/year; Enterprise X from $51,000/year; SaaS Pro $150/month [40] | Artifact management; air-gap export needs Enterprise+ (research/01) |
| NVIDIA AI Enterprise | $4,500 per GPU per year [41] | An enclave's inference stack: $9,000-$18,000 a year for 2-4 GPUs |
| LiteLLM Enterprise | Custom; lists air-gapped deployment, RBAC and audit logs [39] | Substitute for the receiving-side gateway |
| Memo 05 estimate | Between Replicated base fees ($24k-$36k a year) and JFrog self-managed ($27k-$51k a year) | INFERRED range for an AI air-gap packaging product |

### 2.5 Doing nothing

A miss costs an extra reviewed transfer cycle, engineer rework, reviewer time and possibly travel and schedule slip. No primary figure exists; only vendor blogs claim "weeks" (research/06 §5). The pilot baseline (pilot.md B2) measures it per prospect.

## 3. Value metric options

| Option | Tracks the pain? | Countable without telemetry? | Approvable without procurement? | Predictability | Payer fit | Main risk | Verdict |
|---|---|---|---|---|---|---|---|
| Per delivery (shipment) | Directly: each miss costs a cycle | Yes, by contract | Yes, if under the owner's limit | Low: 4-12 a year per team (vendor claims, research/06) | Vendor pays for its own pain | Hard to count once installed; batching; unclear unit | **Entry: pilot and low-cadence teams** |
| Per delivering team, annual | Indirectly: all deliveries plus prep time | Yes: a named team | Less likely: $24k may exceed card limits (UNKNOWN) | High | Vendor | Team boundaries; value unproven before a pilot | **Core recurring unit** |
| Per receiving enclave or site | For the enclave owner: gate, audit, evidence | Yes: installations | Federal buyers under $15,000; labs and primes UNKNOWN | Medium | Controller pays, or vendor passes it through | Admission can take months (customer-discovery §7, phase-2 parking rule) | **Phase 2 only, priced separately** |
| Support and services | Early, hands-on | Hours | Small statements of work | Low | Either | Drift into consultancy | **Included; day rate only for on-site** |
| Per GPU | No: the connected side has few GPUs | Needs counting | n/a | Medium | Enclave | Invites comparison with NVIDIA's full stack | Rejected for now |
| Per model or per GB | No; penalizes large models | Yes | n/a | Low | Vendor | Rewards splitting and skipping checks | Rejected |
| Per preflight run | Taxes the behaviour we want | Needs metering, which means telemetry | n/a | Low | Vendor | Breaks the no-telemetry rule | Rejected |
| Per seat | Weak: 1-3 engineers prepare a delivery (INFERRED) | Yes | Yes | Low | Vendor | Too little revenue per account | Rejected |

**No metering is possible.** Ferry makes no telemetry, update or licence calls (docs/network-dependencies.md). Entitlements are contractual (named team, enclave count) and self-reported once a year. If a licence file is ever added, it must verify offline and must never block a build or an enclave: warn only. LiteLLM's offline licence check, by contrast, treats any failure as no licence (VERIFIED, research/02 S25). A licence failure inside an enclave costs a transfer cycle, the very failure we sell against (INFERRED).

## 4. Recommended hypothesis and assumptions

### 4.1 Pilot, "delivery hardening": $5,000 fixed per shipment

- **Scope:** pilot.md phase 1: up to 3 launch commands, one bundle, review sheet, stock verification, readout.
- **Shipment:** one bundle version for one delivery. The same bundle sent to more sites within 30 days counts once (hypothesis).
- **Terms (proposed):** credited in full against a subscription signed within 90 days; not charged if pilot exit E1 applies (isolation cannot be validated on the prospect's platform).
- **Assumptions:**
  1. The fee fits the budget owner's no-procurement limit (UNKNOWN). Ask for the largest tooling purchase approved without procurement (the purchase question in customer-discovery §4a; K6).
  2. For federal buyers, $5,000 is under the $15,000 micro-purchase threshold (VERIFIED [S10]). Contractor-operated labs and primes set their own limits (UNKNOWN).
  3. $5,000 is about 5.9 engineer-days at $845. One avoided miss pays for it if the miss costs 6 or more engineer-days in labour, travel or schedule. H2's threshold (median 3+ business days per miss) does not cover that for a single engineer; the baseline has to show the rest (INFERRED).
  4. A paid pilot, not a free one, is deliberate: K7 tests buying, not interest.
  5. Founder time is 20-30 hours per pilot (about $2,100-$3,200 at $106 an hour), probably double for the first two (Linux validation, defects). Pilots 1-2 roughly break even on founder time (INFERRED).
- **Floor: $2,500,** about 3 engineer-days. Lower, the price signals "a script" and does not cover founder time (INFERRED).

### 4.2 Subscription per delivering team: $24,000 a year

- **Team:** the engineers who prepare deliveries for one product line: up to 10 named users, with unlimited connected-side hosts, preflights and bundles.
- **Includes:** connected-side tooling (preflight, pack/sign/verify, rehearse) and its upgrades; rule-base updates (monthly target, plus patterns from the customer's own runs); support by email and video in business hours with a next-business-day response. No 24x7 support and no remote access.
- **Anchors:** equal to Replicated Builders' base fee ($2,000 a month) and below JFrog self-managed Pro X ($27,000 a year) (VERIFIED, research/05 §5); inside memo 05's INFERRED range. It is also 4x CMX's standalone fee (about $6,000 a year, §2.3), so a pilot has to show value CMX cannot give before this price holds (INFERRED). LiteLLM Enterprise advertises a 1-hour response for Sev 0 issues (research/05 §5); a founder team cannot match that, which limits both price and segment (INFERRED).
- **Buyer break-even** at $845 per engineer-day (INFERRED arithmetic):

| Deliveries per year | Value needed per delivery | Engineer-days per delivery |
|---|---|---|
| 4 | $6,000 | 7.1 |
| 8 | $3,000 | 3.6 |
| 12 | $2,000 | 2.4 |

  On labour alone, the subscription pays back only for teams that ship often or whose misses cost several engineer-days. At low cadence it needs real schedule, travel or contract costs per miss. The price is defensible only once the pilot measures prep time (pilot.md criterion S4) and the baseline measures misses (pilot.md B2).
- **Tiers to test:** $12,000 (4 or fewer deliveries a year, one product line), $24,000, and $36,000 (several product lines or delivery teams).

### 4.3 Receiving side per enclave: $12,000 a year enclave-paid, or $3,000-$6,000 vendor pass-through

- **Enclave:** one disconnected installation (one host, or 1-4 GPU servers behind one gateway) running import, gateway, provenance check, audit, evidence and console.
- **Enclave-paid anchor:** NVIDIA AI Enterprise at $4,500 per GPU per year puts a 2-4 GPU enclave's inference stack at $9,000-$18,000 a year (VERIFIED, research/05 [41]). $12,000 stays under the $15,000 micro-purchase threshold (VERIFIED [S10]).
- **Vendor-paid anchor:** Replicated's per-license fee of $600-$2,400 per install per year (VERIFIED, research/05 [42]) suggests vendors expect per-site fees in the low thousands.
- **Assumptions:** the enclave owner controls admission and cares most about the importer, the digest gate and the record (02, reviewer point 4). Admission may take over 6 months (the phase-2 parking rule in customer-discovery §7), and no price offsets that. Phase 2 stays parked if that rule triggers.

### 4.4 Services

- **Included:** pilot onboarding, rule additions, release upgrades.
- **Day rate:** $2,000 per on-site day on the connected side, plus travel at cost (hypothesis; about 2.4x the BLS-median loaded engineer-day).
- **No work inside enclaves.** The product promises no vendor access (01 §4), and enclave-side or remote work would pull the company into the customer's security scope (research/05 §4, INFERRED).
- **Paid acceleration** of roadmap items (P-256, DSSE/in-toto, OCI/cosign) for a design partner only if the item is on the roadmap anyway (02). Avoid single-customer forks.

## 5. Cost model

Founder time is valued at the BLS-median loaded rate, $106 an hour, as an opportunity cost (INFERRED).

| Cost | Driver | Estimate | Label |
|---|---|---|---|
| Development before pilot 1 | Validate Linux isolation on real hosts (Ubuntu 24.04, RHEL 8 and 9, with and without user namespaces) and fix what fails | 3-10 founder-days | INFERRED |
| | Finish and test pack/sign/verify/import and rehearse | In progress; remaining effort unknown | UNKNOWN |
| | Container-aware preflight (hook inside the container, `--network none`) | 5-10 days | INFERRED |
| Development, if triggered | P-256 and DSSE/in-toto output (P-256 precondition, customer-discovery §7) | 10-15 days | INFERRED |
| | OCI/cosign output (OCI precondition, same section) | 10-20 days | INFERRED |
| Rule base | Track upstream releases (Hub, vLLM, LiteLLM, tiktoken, Ollama, ...) | About 0.5 day a week, ≈ $21,000 a year | INFERRED |
| Onboarding | Per pilot | 20-30 h ($2,100-$3,200); first two 40-60 h | INFERRED |
| Support | Per subscribed team | 4-8 h a month ($5,100-$10,200 a year) | INFERRED |
| | Per enclave (phase 2) | 1-2 h a month ($1,300-$2,500 a year); slower with no remote access | INFERRED |
| Infrastructure | Customer-hosted: no servers per customer | ≈ $0 marginal | By design |
| | CI: GitHub-hosted Linux at $0.006 a minute, Linux GPU at $0.052 a minute [S11]; for example 3,000 + 600 minutes a month | ≈ $50 a month | VERIFIED rates; INFERRED volume |
| | Release hosting, hardware-held signing keys, domain, email | Small | UNKNOWN |
| Sales | 15 discovery calls at about 2.5 h each (prep, call, coding) | About 38 h | INFERRED |
| | Per pilot sold: concierge preflight, follow-up, order form, security questions | 8-15 h | INFERRED |
| | Events and travel | Optional | UNKNOWN |
| Legal, insurance, accounting | Order form, evaluation licence, MSA template; cyber and technology E&O insurance, which enterprise buyers often ask for | Get quotes before pilot 1 | UNKNOWN |

**Unit contribution** (INFERRED arithmetic, not a forecast):
- Pilot: $5,000 minus 20-30 h ≈ $1,800-$2,900. Repeat shipment with about 10 h of support ≈ $3,900.
- Team subscription: $24,000 minus $5,100-$10,200 of support ≈ $13,800-$18,900 (58-79%).
- Enclave: $12,000 minus $1,300-$2,500 ≈ $9,500-$10,700.
- Funding one engineer at ≈ $194,000 a year loaded takes about 10-14 subscribed teams, or about 50 repeat shipments, before rule-base, development and sales time. How many delivering teams the ICP holds is UNKNOWN (01 §9); pricing depends on that answer.

## 6. Questions that validate or break the hypothesis

Ask about past behaviour, never hypotheticals (customer-discovery §4c). Name a price only at the pilot ask, after the prospect has stated its own no-procurement limit, and record the reaction in the call note's Buying section.

**Validating evidence:**
1. Among the last 3 deliveries, at least 1 miss that cost 3+ business days or travel (pilot B2; H2). Supports a per-shipment fee.
2. The team ships 5+ times a year (pilot B5). The subscription beats per-shipment pricing.
3. 3+ budget owners name a no-procurement limit of $5,000 or more (K6).
4. A paid pilot or LOI within 45 days of a demo on the prospect's own bundle (K7).
5. The reviewer says the packet replaced manual work, and gives the minutes saved (pilot criterion S5).
6. Pilot prep time (pilot criterion S4) beats pilot B3 by at least 1 engineer-day per delivery (hypothesis).
7. An enclave owner names a budget line and a purchase path used in the last 12 months (customer-discovery H7 and the purchase-path question in §4b).

**Breaking evidence:**
1. Misses are rare or cheap (K1 or K2). Per-shipment value collapses.
2. An existing `--network none` or CMX test would have caught the last incident (K3). The price drops to "hygiene", or the wedge is re-scoped.
3. Any new tool on build hosts needs security review or procurement whatever the price. The pilot stops being procurement-free, and the sales cycle length is UNKNOWN.
4. FIPS, P-256 or OCI/cosign are required before purchase (customer-discovery §7 preconditions). No revenue until they are built.
5. Buyers expect free open-source tooling and pay only for support. The model becomes a cheaper support subscription.
6. Teams ship twice a year or less. Only per-shipment pricing works, and revenue is lumpy.
7. The vendor will not pay for the receiving side and the enclave owner will not pay for vendor tooling. Two separate, smaller sales.
8. Kubernetes dominates (K5). The product is priced as a Zarf/Hauler extension, probably lower.

## Sources (accessed 2026-10-28)

- S1 https://www.bls.gov/ooh/computer-and-information-technology/software-developers.htm
- S2 https://www.bls.gov/news.release/ecec.nr0.htm (USDL-26-1494, June 2026 data)
- S3 https://docs.docker.com/engine/network/drivers/none/
- S4 https://www.docker.com/pricing/
- S5 https://docs.docker.com/subscription/desktop-license/
- S6 https://docs.replicated.com/vendor/testing-network-policy
- S7 https://docs.replicated.com/vendor/testing-pricing
- S8 https://docs.replicated.com/vendor/testing-vm-about ("GPU instance types are only supported on Cloud Clusters")
- S9 https://docs.replicated.com/vendor/testing-supported-clusters
- S10 https://www.acquisition.gov/far/2.101 (micro-purchase threshold $15,000), effective 2025-10-01 per https://www.pillsburylaw.com/en/news-and-insights/federal-acquisition-regulatory-council-inflation-thresholds.html
- S11 https://docs.github.com/en/billing/reference/actions-runner-pricing
- S12 https://docs.replicated.com/vendor/testing-how-to (air-gap section: "cloud-based distributions do not support the airgap network policy")
- S13 https://www.replicated.com/pricing (CMX: $500/month plus cluster costs; no base plan purchase required)
- Memo sources: research/05 §5 [39]-[42] (LiteLLM, JFrog, NVIDIA, Replicated pricing pages); research/02 S25 (LiteLLM licence check); research/06 S27-S30 (vendor cadence and delay claims).
