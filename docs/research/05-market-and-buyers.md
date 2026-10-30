# 05 - Market and Buyers: AI in Restricted and Disconnected Environments (2025-2026)

*Research date: 2026-10-28. Question: who needs AI inside restricted or air-gapped networks, who buys, and how.*
*Labels: **VERIFIED** = read in a cited source; **INFERRED** = analyst reasoning from verified facts; **UNKNOWN** = not confirmed. "Claim" = a figure reported by the vendor or agency about itself. Bracketed numbers point to Sources. Sources [1] and [39]-[44] were fetched directly; the rest were read through search-engine extracts of the cited pages. Check key numbers on the page before using them externally.*

## Summary

- YC's current Requests for Startups include "AI for the Air-Gapped Economy" by Brad Flora, under the Winter 2027 batch heading. **VERIFIED** [1]
- The best-documented demand is in national security. DOE/NNSA runs OpenAI reasoning models on LANL's Venado after moving it to a classified network [15][16]. Scale (Donovan) and Palantir (Apollo) both sell into classified and air-gapped networks [20][25]. **VERIFIED**
- Much "classified AI" runs in government regions that the cloud provider operates (AWS Top Secret, Azure Government Top Secret, Google Distributed Cloud air-gapped), not in air gaps the customer builds [9][11][13]. **VERIFIED** That leaves room for a small vendor in enclaves the customer operates (labs, plants, prime contractors, the tactical edge) and among the vendors that have to ship into them. **INFERRED**
- Commercial evidence is thinner: one named nuclear deployment (Diablo Canyon) [28]. This pass found no named hospital or bank running a fully disconnected LLM. **UNKNOWN**
- The rules for buying changed in 2026. SBIR/STTR came back through FY2031 after a 5.5-month lapse [32][33], and DoD suspended CMMC Phase 2 in July 2026 pending a review [35][36]. **VERIFIED**

## 1. YC Request for Startups

| Item | Finding | Status |
|---|---|---|
| Title / author | "AI for the Air-Gapped Economy", by Brad Flora | VERIFIED [1] |
| Batch / date | Listed under the Winter 2027 RFS heading. No date shown on the item (page footer says 2026). | VERIFIED [1]; exact publish date UNKNOWN |
| Argument (paraphrase) | The most valuable data sits with defense contractors, banks, hospitals and nuclear plants, and they cannot send it to outside AI APIs. They want AI that runs entirely inside their own facilities with no internet, and founders keep running into this requirement. YC wants companies that bring frontier AI into these settings: on-prem models, deployment tooling, security accreditation and hardware. Sales are slower and harder, but the budgets are the largest and the companies the most defensible. | VERIFIED [1] |
| Other Winter 2027 items | These include "Own Your Intelligence", "Vertical Foundation Models", "AI for City Hall" and "Data Center Supply Chain". | VERIFIED [1] |

YC names "deployment tooling" and "security accreditation" explicitly. Those map to wedges A and D. **INFERRED**

## 2. Who is deploying or seeking LLMs in restricted settings

| Organization / setting | What is public | Is the air gap run by the customer? | Status |
|---|---|---|---|
| LANL, LLNL, Sandia (DOE/NNSA) | Partnership announced Jan 2025. By Aug 2025, Venado (GH200) had moved to a classified network and was running OpenAI o-series models. The three labs share it for work such as plutonium aging and biothreat guardrails. | Yes: on-prem classified HPC | VERIFIED [15][16] |
| DoD enterprise (GenAI.mil) | Launched Dec 2025 with Gemini for Government for CUI/IL5. The Pentagon CTO cited 1.5M daily users in Apr 2026. ChatGPT integration is planned. | No: commercial cloud at IL5. Classified expansion UNKNOWN | VERIFIED (agency claim) [17][18][19] |
| Army XVIII Airborne Corps | Scale's Donovan was announced as the first LLM on a government classified network. | Classified network | VERIFIED (trade press) [21] |
| INDOPACOM / EUCOM | DIU awarded Scale the "Thunderforge" prime prototype (Mar 2025) for AI-assisted planning, with Anduril and Microsoft. | UNKNOWN | VERIFIED [22][23] |
| COCOMs, Joint Staff, OSD, Army | Ask Sage won a $10M first-year deal with CDAO and the Army (Jun 2025). The Army workspace extends to Secret workflows. | Mixed. IL6/TS status is the vendor's claim | VERIFIED (claim) [5][6] |
| IC and DoD, Top Secret | Google Distributed Cloud air-gapped is authorized for Secret and TS. Gemini on GDC was in preview in Apr 2025. | Google manages an appliance on the customer's premises | VERIFIED (secondary) [9][10] |
| IC and DoD, Top Secret | AWS Top Secret cloud: Bedrock is generally available there with Claude 3.5 Sonnet. Separately, Claude is offered at IL6 (Secret) through Palantir and AWS (Nov 2024). | Isolated region run by the provider | VERIFIED [11][12] |
| IC and DoD, Top Secret | Azure OpenAI (GPT-4o) authorized in Azure Government Top Secret under ICD 503 (Jan 2025). | Isolated cloud run by the provider | VERIFIED [13][14] |
| Nuclear: PG&E Diablo Canyon | Atomic Canyon's Neutron Enterprise was deployed on-site on NVIDIA hardware (Nov 2024) to search licensing documents. Its FERMI models were built with ORNL. | On-site. Whether fully disconnected is UNKNOWN | VERIFIED [28][29] |
| Hospitals | Found no named US health system running a disconnected LLM. One vendor case study describes an unnamed hospital. A radiology review says HIPAA and GDPR push hospitals to host models locally, but on-site GPUs are scarce. | n/a | UNKNOWN (weak evidence) [30][31] |
| Banks, defense primes, OT/ICS beyond nuclear | Not confirmed in this pass beyond YC's assertion. | n/a | UNKNOWN |

Two different markets share the "air-gapped" label. Hyperscalers own the classified clouds that the provider operates. Enclaves the customer operates (HPC centers, plants, labs at primes and integrators, the tactical edge) still need someone to move, verify and maintain models and software across the boundary. **INFERRED**

## 3. Vendors and funded companies

| Vendor | What it sells | Public funding or deal | Wedge overlap |
|---|---|---|---|
| Defense Unicorns | UDS, a runtime built for air gaps that packages and sustains mission apps; UDS Registry; UDS Army. Maintains the open-source Zarf. | $136M Series B (Jan 2026, led by Bain Capital Tech Opportunities) at a valuation above $1B. $35M Series A (2024). Claims 300% year-over-year growth in military adoption. [2][3][4] | A, C (direct) |
| Ask Sage, now BigBear.ai | Generative AI platform for government. Claims FedRAMP High, IL5, IL6 and TS. Deploys to cloud, on-prem and air-gapped sites. [5][7] | Acquired for $250M cash, closed Dec 31, 2025. Claims 100K+ users. [8] | B, E |
| Scale AI | Donovan runs on classified and air-gapped networks as Kubernetes containers; also Thunderforge. [20][22] | Only one outlet reports a $500M follow-on: UNKNOWN [24] | E |
| Palantir | AIP. Apollo deploys into networks Palantir cannot log into, including air-gapped ones [25]. An air-gapped offering with NVIDIA, built on Nemotron, was reported Jun 30, 2026 [26]. | Public company | A, C, E |
| EdgeRunner AI | AI agents that run on the device with no network, for soldiers and enterprises | $17.5M, including a $12M Series A led by Madrona (May 2025). AFRL CRADA. "Awardable" on Tradewinds. [27] | E (edge) |
| Atomic Canyon | AI search built for nuclear plants, run on-site [28] | Not checked | E (vertical) |
| Replicated / JFrog / LiteLLM / NVIDIA | Respectively: app distribution with air-gap installs; artifact and model registry; LLM gateway; licensed GPU inference stack | See section 5 | A / A,D / B / E |

Fetching the GitHub URL for Defense Unicorns' LeapfrogAI repository returned 404, so its status is UNKNOWN [44].

## 4. Procurement paths for a small vendor

- **SBIR/STTR.** Authority lapsed Oct 1, 2025. S. 3971, signed Apr 13, 2026, extends both programs through Sep 30, 2031. It adds a Phase II "strategic breakthrough" vehicle of up to $30M and replaces lifetime caps with annual limits on proposals. **VERIFIED** (law-firm summary; confirm on congress.gov) [32] AFWERX and SpaceWERX reopened solicitations after reauthorization. **VERIFIED** [33] The FY27 Release 1 dates come only from an aggregator: **UNKNOWN** until confirmed on DSIP.
- **Topics that name air-gapped AI.** One extended search found no 2026 DoD SBIR, AFWERX or DIU solicitation that explicitly asks for tooling to deploy LLMs into air gaps. **UNKNOWN** This may be a limit of the search; query DSIP for "air-gapped", "disconnected" and "DDIL".
- **Other routes peers have used.** EdgeRunner gained "Awardable" status on CDAO's Tradewinds marketplace and signed an AFRL CRADA [27]. DIU awards prime prototypes such as Thunderforge [22]. **VERIFIED** That such prototypes usually run on Other Transaction (OT) authority is **INFERRED**.
- **Partnering.** For classified sites, the realistic route for a solo founder is to subcontract to or integrate with the platform holders (Defense Unicorns, Palantir, primes). **INFERRED**
- **CMMC.** The DFARS rule took effect Nov 10, 2025, starting Phase 1 (self-assessments). Phase 2 (Level 2 third-party assessments) was due Nov 10, 2026. A DoD CIO memo suspended it on Jul 13, 2026, pending a 60-day review, and the RFI drew more than 1,100 responses. Phase 1, DFARS 252.204-7012 and NIST SP 800-171 Rev 2 still apply, and officials did not rule out ending the program. **VERIFIED** [34][35][36][37][38]
- **What CMMC means for a software seller (INFERRED).** Scope follows the systems that process, store or transmit FCI or CUI. If the customer installs and runs the software entirely inside its own enclave, with no vendor remote access, no telemetry and no support bundles that carry CUI, the vendor stays largely out of scope. A hosted control plane or remote support pulls it in. A COTS-only exemption is often cited but was not verified here (**UNKNOWN**). For now, the Phase 2 suspension weakens compliance as a reason for defense contractors to buy.

## 5. Public pricing anchors

| Product | Public price | Status |
|---|---|---|
| NVIDIA AI Enterprise (self-managed) | $4,500 per GPU for 1 year, support included; $13,500 for 3 years; $22,500 perpetual with 5 years of support; cloud $1 per GPU-hour. EDU/Inception: $1,125 per GPU-year. A 5-year subscription comes with H100, H200 NVL and A800 PCIe GPUs. | VERIFIED [41] |
| Replicated | Builders: $2,000/mo plus a per-license fee (the table says $50 per license per month). Business: $3,000/mo plus $200 per license per month. Enterprise: contact sales. Air-gap installs are checked for every tier, but the FAQ ties them to Enterprise, so the page contradicts itself. | VERIFIED [42] |
| JFrog | SaaS: Pro $150/mo; Enterprise X from $950/mo. Self-managed: Pro X from $27,000/yr (1 server); Enterprise X from $51,000/yr (3 servers); Enterprise+ custom. ML model registry and Hugging Face caching are in every tier. The pricing page does not mention air gaps. | VERIFIED [40] |
| LiteLLM Enterprise | No public price ("custom pricing"); 30-day self-hosted trial key. Lists air-gapped deployment, SSO/SCIM, RBAC and audit logs. Response time for Sev 0 issues: 1 hour. | VERIFIED [39] |
| Defense Unicorns UDS | No public price found | UNKNOWN |

Analyst estimate, not evidence: a packaging and upgrade product built for AI in air gaps, sold to software vendors or integrators, would plausibly price between Replicated's base fees (about $24k-36k/yr plus licenses) and JFrog self-managed ($27k-51k/yr). **INFERRED**

## 6. Where technical champions gather

- The Kubernetes Slack channel `#zarf`, plus Zarf community meetups linked from the repository. **VERIFIED** [43]
- DoDIIS Worldwide (DIA): Aug 9-12, 2026, at the Tampa Convention Center. It has already happened; the 2027 dates are **UNKNOWN**. **VERIFIED** [45][46]
- Not verified in this pass: the S4 ICS security conference (the search returned nothing), AFCEA TechNet Cyber, events co-located with KubeCon, Platform One and Iron Bank channels, and r/LocalLLaMA. **UNKNOWN**; confirm before spending time on them.

## 7. Candidate ICP segments (ranked)

| Rank | Segment | Pain evidence | Access for a solo founder | Budget | Evidence quality |
|---|---|---|---|---|---|
| 1 | AI software vendors and integrators that must ship models and apps into customers' disconnected sites | Medium. Replicated, JFrog and LiteLLM all sell air-gap or self-hosted installs. YC says founders keep hitting the need. | High. Commercial sale, no clearance, reachable via GitHub and Slack. | Medium (Replicated and JFrog anchors) | Medium, mostly INFERRED |
| 2 | AI and HPC teams at DOE national labs and FFRDCs | Strong. Three labs share the classified Venado deployment. | Medium. Friendly to open source; buy through lab subcontracts and CRADAs. | Medium to high | High (primary DOE sources) |
| 3 | Defense primes and mid-tier integrators (their own CUI or classified enclaves) | Medium. YC's claim plus NIST 800-171 obligations; no named example verified. | Medium to low. Security reviews, long cycles. | High | Low to medium |
| 4 | Government program platform teams on classified networks | Strong. Donovan, Ask Sage, Apollo and UDS all serve them. | Low. Clearances, ATOs, contract vehicles, entrenched incumbents. | High | High (vendor and trade press) |
| 5 | Nuclear and critical-infrastructure (OT) operators | Medium. Diablo Canyon runs generative AI on-site. | Medium to low. Conservative buyers; vertical vendors already present. | Medium | Medium (one named case) |
| 6 | Hospitals and banks | Weak in this pass | Medium | Medium | Low / UNKNOWN |

## 8. Implications for the wedge decision

- **A (offline deployment and upgrades).** The need is the best documented and willingness to pay is the clearest (Replicated, JFrog, UDS, Apollo). Generic Kubernetes packaging is contested by Zarf/UDS (open source, with a backer valued above $1B) and by Apollo. To differentiate, focus on payloads specific to AI: multi-GB weights, CUDA and driver compatibility, provenance, and delta updates across a transfer boundary. Sell to segment 1 first, ideally working with Zarf rather than against it. **INFERRED**
- **B (access control).** LiteLLM Enterprise already lists RBAC, SSO, audit logs and air-gapped deployment, and Ask Sage and AIP bundle the same. There is little evidence of a separate budget for it. **INFERRED**
- **C (operations).** The pain is real (Apollo and UDS exist to keep software running in disconnected sites), but the work leans on services and often needs on-site or cleared staff. It works better as expansion after A. **INFERRED**
- **D (evidence).** YC names accreditation. Signed manifests, SBOMs and transfer receipts for each install come naturally out of A. The CMMC Phase 2 suspension reduces the compliance pull in the near term. **INFERRED**
- **E (inference infrastructure).** The most crowded and capital-intensive wedge: three hyperscaler offerings at Top Secret, NVIDIA AI Enterprise, Palantir with NVIDIA, Scale, BigBear.ai/Ask Sage and EdgeRunner. Avoid it as the first wedge. **INFERRED**

## 9. Open questions

1. The exact publication date of the YC RFS item.
2. How CMMC treats COTS software installed inside a customer's enclave (32 CFR 170 / DFARS 252.204-7021), and what the DoD review concludes.
3. Whether LeapfrogAI was retired (repository 404), and whether Defense Unicorns would partner or compete on AI payloads.
4. Named banks, hospitals and defense primes that run fully disconnected LLMs.
5. Whether any FY27 DSIP topics cover deploying AI to disconnected sites.
6. Whether Scale's reported $500M follow-on and an expansion of GenAI.mil to classified networks are real.

## Sources (accessed 2026-10-28)

1. https://www.ycombinator.com/rfs
2. https://www.govconwire.com/articles/defense-unicorns-136m-series-b-1b-valuation
3. https://intelligencecommunitynews.com/defense-unicorns-reaches-1b-valuation-in-series-b-round/
4. https://www.lw.com/en/news/2026/01/latham-watkins-advises-defense-unicorn-series-b
5. https://intelligencecommunitynews.com/ask-sage-partners-with-dod-cdao-and-u-s-army/
6. https://www.asksage.ai/press-releases/ask-sage-announces-generative-ai-army-enterprise-offering-at-il5-in-collaboration-with-microsoft
7. https://www.carahsoft.com/ask-sage and https://aws.amazon.com/marketplace/pp/prodview-5ryopj245g6e6 (vendor listings)
8. https://www.businesswire.com/news/home/20251231482987/en/BigBear.ai-Finalizes-250M-Acquisition-of-Ask-Sage
9. https://www.infoq.com/news/2025/04/google-gemini-gdc-preview
10. https://www.wwt.com/article/partner-pov-or-google-public-sector-achieves-top-secret-and-secret-cloud-authorization
11. https://aws.amazon.com/blogs/publicsector/amazon-bedrock-launches-with-claude-3-5-sonnet-in-the-aws-top-secret-cloud
12. https://techcrunch.com/2024/11/07/anthropic-teams-up-with-palantir-and-aws-to-sell-its-ai-to-defense-customers
13. https://devblogs.microsoft.com/azuregov/unlocking-new-possibilities/
14. https://defensescoop.com/2025/01/16/openais-gpt-4o-gets-green-light-for-top-secret-use-in-microsofts-azure-cloud/
15. https://www.energy.gov/node/4852451
16. https://www.lanl.gov/media/news/0130-open-ai
17. https://www.defenseone.com/defense-systems/2026/04/pentagon-adds-googles-latest-model-genaimil-usage-soars/413126/
18. https://www.cdomagazine.tech/us-federal-news-bureau/us-department-of-war-launches-genai-mil-platform-with-first-frontier-ai-capability
19. https://www.executivegov.com/articles/openai-chatgpt-pentagon-genai-mil-july-launch
20. https://scale.com/donovan
21. https://intelligencecommunitynews.com/scale-ai-deploying-first-llm-on-a-government-classified-network/
22. https://www.executivegov.com/articles/scale-ai-diu-thunderforge-contract
23. https://scale.com/blog/thunderforge-ai-for-american-defense
24. https://startupfortune.com/scale-ais-500-million-pentagon-contract-reframes-who-gets-to-build-americas-national-security-ai-stack/ (single source, unconfirmed)
25. https://blog.palantir.com/deploying-across-security-domains-449c786d92c0
26. https://securitybrief.news/story/palantir-nvidia-launch-air-gapped-ai-for-agencies
27. https://www.businesswire.com/news/home/20250501050946/en/EdgeRunner-Raises-$17.5M-to-Develop-Air-Gapped-On-Device-AI-for-the-Warfighter
28. https://www.nasdaq.com/press-release/pge-launches-first-commercial-deployment-site-generative-ai-solution-nuclear-energy
29. https://www.utilitydive.com/news/generative-ai-deployment-at-diablo-canyon-is-a-first-for-us-nuclear-power-s/732953
30. https://arxiv.org/pdf/2509.16328
31. https://intechhouse.com/case-studies/production-ai-for-a-regulated-hospital-with-full-data-sovereignty (vendor case study)
32. https://www.crowell.com/en/insights/client-alerts/sbirsttr-programs-reauthorized-after-six-month-lapse
33. https://www.afrl.af.mil/News/Article-Display/Article/4473004/afwerx-spacewerx-open-new-sbirsttr-solicitations-following-reauthorization/
34. https://www.cooley.com/news/insight/2025/2025-09-25-dod-releases-long-awaited-final-rule-implementing-cybersecurity-maturity-model-certification-contract-clause
35. https://federalnewsnetwork.com/cybersecurity/2026/07/pentagon-suspends-cmmc-phase-two-requirements-launches-review-of-program/
36. https://www.washingtontechnology.com/contracts/2026/07/dod-suspends-cmmc-phase-2-launches-60-day-reform-review/414739/
37. https://www.lw.com/en/insights/what-defense-contractors-should-know-about-dod-suspension-of-cmmc-phase-2
38. https://dodcio.defense.gov/CMMC/
39. https://www.litellm.ai/enterprise
40. https://jfrog.com/pricing/
41. https://docs.nvidia.com/ai-enterprise/planning-resource/licensing-guide/latest/pricing.html
42. https://www.replicated.com/pricing
43. https://github.com/zarf-dev/zarf
44. https://github.com/defenseunicorns/leapfrogai (returned HTTP 404 on 2026-10-28)
45. https://www.govevents.com/event/23720/2026-dodiis-worldwide-conference
46. https://www.telos.com/event/dodiis-worldwide-2026/

Unreachable or failed: https://www.nvidia.com/en-us/data-center/products/ai-enterprise/buy/ (HTTP 404; the docs page [41] was used instead). The S4x26 search returned nothing, and banks and defense primes were not searched specifically.
