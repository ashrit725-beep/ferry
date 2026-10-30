# Security requirements and transfer procedures for AI in disconnected and classified environments

Research date 2026-10-28. **VERIFIED** = read in a primary or credible source (see Sources); **INFERRED** = our reasoning from verified facts; **UNKNOWN** = not confirmed.

## Bottom line

- **The transfer rules sit in CSA guidance that is not public.** 32 CFR 117.18 does not directly address data transfer (VERIFIED). DCSA replaced the DAAPM (v2.2, effective 31 Aug 2020) with the DAAG, which is distributed through NISP eMASS (VERIFIED via search excerpts; dcsa.mil returned HTTP 403 to direct fetches). AFT section numbers, Data Transfer Agent duties, file-type checks, scanning, records and two-person rules remain **UNKNOWN**.
- **Best citable hooks:** SP 800-53 SI-7(15), CM-14, SI-7(6), SR-4(3), AU-9 and AU-10(3) (VERIFIED, control text read).
- **CUI/CMMC rules say little about integrity:** SP 800-171r3 tailors out SI-7 and SR-11 as "NCO" (VERIFIED).
- **The AI security guidance converges** on signed and hashed artifacts, hashed release archives, two-person control of weights and signed provenance (VERIFIED via excerpts).
- **Timing:** CMMC Phase 2 starts 10 Nov 2026, 13 days from now (INFERRED from verified rule text).

## 1. DCSA guidance: DAAPM to DAAG

- DAAPM v2.2 took effect 31 Aug 2020 and superseded v2.0 and v2.1 (VERIFIED, excerpt of the dcsa.mil PDF).
- DCSA's NISP Cybersecurity Office (NCSO) released the DAAG to replace the DAAPM. It can be downloaded in NISP eMASS or requested by email (VERIFIED, excerpt of DCSA's September 2025 newsletter). CDSE toolkits list the DAAG as requiring an eMASS account (VERIFIED, excerpt).
- The claims "Version 1.1, 31 Aug 2025" and "existing ATOs remain valid" come only from a vendor blog (UNKNOWN).
- The AFT details we were asked for could not be read: section numbers, the DTA role, low-to-high and high-to-low steps, file-type verification, malware scanning, logs and two-person review. A third-party mirror also returned 403 (UNKNOWN).

## 2. NISPOM, 32 CFR 117.18 (VERIFIED from the Cornell LII copy; eCFR blocked automated access)

- (a)(2): CSA guidance draws on FISMA, SP 800-37 and CNSSI 1253.
- (b)(4) requires user-activity monitoring and protected, access-limited logs. (b)(6) requires change control that flags security-relevant changes that may need re-authorization.
- (c)(2): the ISSM certifies the SSP. The ISSM also maintains the SSPs, assessment reports, POA&Ms, CM plans, configuration checklists and interconnection agreements.
- (e)(2): absent contract terms, systems are categorized moderate confidentiality, low integrity, low availability. (e)(6): no classified processing before CSA authorization.
- 117.18 does not address media or data transfer directly. Under (f), CUI systems fall to contract terms.
- INFERRED: with low integrity as the default, SI-7 enhancements may not be selected unless an overlay or the AO adds them.

## 3. NIST SP 800-53 Rev. 5 (VERIFIED, 2020 PDF)

| Control | Requirement (paraphrase) |
|---|---|
| SI-7(6) | Cryptography detects unauthorized changes to software, firmware and information |
| SI-7(12) | Verify the integrity of org-defined user-installed software before it runs |
| SI-7(15) | Cryptographically authenticate org-defined components before installation |
| CM-14 | Block installation unless the component is signed with an org-approved certificate |
| SR-4, SR-4(3) | Maintain provenance of components and data; confirm components are genuine and unaltered |
| SR-11 | Anti-counterfeit procedures; report counterfeits |
| AU-9, AU-9(3) | Protect audit information and tools; cryptographic protection |
| AU-10, AU-10(3) | Irrefutable evidence of actions; reviewer and releaser credentials kept in the chain of custody |
| AC-3, AC-4, AC-5, AC-6 | Access and information-flow enforcement; separation of duties; least privilege |
| CM-7(5) | Deny all execution, permit by exception |
| IA-5, SC-7, SC-13, MP-5, MP-7 | Authenticators; managed interfaces; defined cryptographic uses; media transport and use |

Release 5.2.0 (27 Aug 2025) targets the integrity of updates and patches. It adds SA-15(13), SA-24 and SI-2(7) and revises SI-7(12) (VERIFIED from the NIST news page and an excerpt of the catalog page). The new wording is UNKNOWN.

## 4. SP 800-171r3 and CMMC

- r3 requirements that map (VERIFIED):
  - 03.01.03-07: information flow, separation of duties, least privilege.
  - 03.03.08: protect audit information; limit who can manage logging.
  - 03.04.01-12, notably 03.04.08 (allow by exception).
  - 03.08.05/07: media transport and use; no removable media without an identifiable owner.
  - 03.14.02: malicious code protection at system entry and exit points.
  - 03.17.01-03: supply chain.
  - SI-07, SI-07(01) and SR-11 are tailored out as NCO.
- The 32 CFR 170 final rule was published 15 Oct 2024 (VERIFIED).
- The DFARS final rule (FR 2025-17359) was published 10 Sep 2025 and took effect 10 Nov 2025. It adds clause 252.204-7021 and provision 252.204-7025. For three years, applying the clause is at program discretion. After that it is required wherever contractor systems handle FCI or CUI. COTS-only buys are excluded (VERIFIED).
- 32 CFR 170.3(e) (VERIFIED):
  - Phase 1 starts on the DFARS effective date, and each later phase starts one year after the previous one.
  - Phase 2 adds a Level 2 (C3PAO) assessment before award, which can be deferred to option periods.
  - Phase 4 is full implementation.
- Phases 2-4 therefore start 10 Nov 2026, 2027 and 2028 (INFERRED; matches law-firm summaries).
- Which SP 800-171 revision Level 2 uses: UNKNOWN this session (commonly reported as Rev. 2; check 32 CFR 170.14).

## 5. Government AI-security guidance

- **Deploying AI Systems Securely** (NSA-led joint CSI, 15 Apr 2024; VERIFIED via excerpts, PDF returned 403):
  - Confirm each artifact's origin and integrity with cryptography, signatures and checksums.
  - Archive hashed, encrypted copies of each release, with hashes and keys in a vault or HSM.
  - Apply two-person control and two-person integrity to weights.
- **AI Data Security** (NSA, CISA, FBI and partners, 22 May 2025; VERIFIED via excerpts):
  - Log the path data takes through the system.
  - Keep a signed, append-only provenance database.
  - Sign datasets and their revisions.
  - Encrypt to FIPS 140-3.
- **SP 800-218A** (July 2024; VERIFIED):
  - PS.1.1-1.3: protect code, models, weights, training data and configuration.
  - PS.2.1: provide integrity-verification information.
  - PS.3.1-3.2: archives and provenance.
- **DoD CIO AI Cybersecurity RM Tailoring Guide v2** (14 Jul 2025) is guidance, not a mandate (VERIFIED, excerpt). Its control-level content is UNKNOWN.
- **DoW AI Strategy** (Jan 2026) directs the CDAO to push the latest frontier models and keep updates flowing (VERIFIED, secondary source).
  - DefenseScoop reports (VERIFIED) that DoD signed classified-network AI agreements with eight firms in May 2026, and had moved about 90% of classified workloads off Anthropic by September.
  - We found no public SIPRNet/JWICS deployment memo (UNKNOWN).
- **OMB M-25-21** (3 Apr 2025) replaces M-24-10 and excludes AI used as a component of a national security system (VERIFIED). M-25-22 was not checked.

## 6. Mapping: what the product can evidence, and what it cannot

| Requirement | Evidence from the bundle verifier, policy gateway and audit log | Cannot provide |
|---|---|---|
| SI-7(15), CM-14, SI-7(6) | Checks signatures and hashes on images, packages, weights and configs against the customer trust store before install; fails closed; signed report | Choice of approved components and certificates; PKI governance; FIPS validation unless the module itself is validated |
| SI-7(12), 5.2.0 update controls | Integrity check at each upgrade; diff of versions and config | Any mapping until the 5.2.0 text is read |
| SR-4(3), PS.3.2 | Manifest of source, version, hash and upstream attestations; custody hops | Truth of upstream claims; supplier vetting |
| SR-11 | Detection of altered artifacts and an incident record | Anti-counterfeit program; hardware |
| CM-7(5), 03.04.08 | Allowlist enforcement for models and packages | Deciding what is authorized |
| CM-3, 117.18(b)(6) | Change record for each install; flags new models, capabilities and configs | CCB approval; re-authorization decision |
| AC-3, AC-6, 03.01.05-07 | Deterministic model entitlements per user, app and workload; deny by default | Clearance, need-to-know, provisioning |
| AC-5, 03.01.04, NSA two-person control | Enforced split of packager, approver and installer; dual approval to import weights | Designating and training people |
| AC-4, 03.01.03 | Label-aware routing to models | Not a cross-domain solution |
| AU-9(3), AU-10(3), 03.03.08, 117.18(b)(4) | Hash-chained, signed logs; restricted log administration; signed releaser identity | Log review, retention, insider-threat program |
| IA-5 | Issuing, rotating and revoking keys and tokens | Identity proofing; HSM custody |
| MP-5, MP-7, 03.08.07, 03.14.02 | Records media ID and hash; re-verifies on arrival; captures site scanner results | Approved media, marking, transport, sanitization, scanning |
| DAAG AFT (UNKNOWN) | Configurable record for each transfer: files, types, hashes, scans, operator, approver | DTA appointment; the procedure itself; ISSM/AO approval |
| 117.18(c)(2), (e)(5)-(7) | Evidence exports for the SSP, checklists and continuous monitoring | Certifying the SSP; authorization |

## 7. Features do not equal compliance

- The CSA authorizes and the ISSM certifies (117.18). A product cannot be "DAAG-compliant", "authorized" or "CMMC certified". CMMC status attaches to the contractor's assessed systems (INFERRED).
- Key controls carry organization-defined assignments that the customer sets (VERIFIED).
- Say "produces evidence supporting SI-7(15)", never "meets SI-7(15)".

## 8. Implications by wedge (INFERRED)

- **A:** Has the strongest requirement pull (SI-7(15), CM-14, SR-4, AU-10(3)), plus DoW pressure to update models and churn among model vendors. Keep transfer records configurable until the DAAG text is known.
- **B:** Maps to AC-3/4/5/6 and AU-9. To stand out it needs model-level entitlements and deterministic audit.
- **C:** Maps to CM-3, 117.18(b)(6) and continuous monitoring. Services-heavy and specific to each site.
- **D:** ISSMs must maintain authorization documentation, so evidence matters. It is best produced as a by-product of A.
- **E:** Few controls are specific to inference, and M-25-21 excludes NSS. Little compliance pull.

## 9. Open questions

- What does the DAAG transfer text say about AFT/DTA, approved file types and tools, two-person review and retention?
- Does the DAAG move NISP systems to Rev. 5 controls?
- Which of SI-7, CM-14 and SR-4 does the CNSSI 1253 Classified Information Overlay select?
- What is the 5.2.0 text for SA-15(13), SA-24, SI-2(7) and SI-7(12)?
- Does CMMC Level 2 use Rev. 2 or Rev. 3?
- Do AOs treat model weights as software components under SI-7(15)/CM-14, or as information under SI-7(6)?
- What does the DoD CIO AI tailoring guide say at the control level?

## Sources (accessed 2026-10-28)

- DAAPM v2.2 (403): https://www.dcsa.mil/Portals/91/Documents/CTP/tools/DCSA%20Assessment%20and%20Authorization%20Process%20Manual%20Version%202.2.pdf
- DCSA newsletter Sept 2025 (403): https://www.dcsa.mil/Portals/128/Documents/CTP/tools/250930%20VOI%20Newsletter.pdf
- DAAPM v2.1 mirror (403): https://rmf.org/wp-content/uploads/2020/06/DCSA_Assessment_and_Authorization_2.1-FINAL.pdf
- SecureSTRUX blog: https://securestrux.com/resources/insights/daag-vs-daapm-and-the-transition-to-daag/
- CDSE toolkits: https://www.cdse.edu/Training/Toolkits/Information-System-Security-Manager-Toolkit/ ; https://www.cdse.edu/Training/Toolkits/Cybersecurity-Toolkit/
- 32 CFR 117.18: https://www.law.cornell.edu/cfr/text/32/117.18
- 32 CFR 170.3: https://www.law.cornell.edu/cfr/text/32/170.3
- CMMC program rule: https://www.federalregister.gov/documents/2024/10/15/2024-22905/cybersecurity-maturity-model-certification-cmmc-program
- DFARS CMMC rule: https://www.federalregister.gov/documents/full_text/xml/2025/09/10/2025-17359.xml
- Cooley summary: https://www.cooley.com/news/insight/2025/2025-09-25-dod-releases-long-awaited-final-rule-implementing-cybersecurity-maturity-model-certification-contract-clause
- SP 800-53r5: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
- SP 800-53 5.2.0: https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls ; https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- SP 800-171r3: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-171r3.pdf
- SP 800-218A: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf
- Deploying AI Systems Securely (403): https://media.defense.gov/2024/Apr/15/2003439257/-1/-1/0/CSI-DEPLOYING-AI-SYSTEMS-SECURELY.PDF
- AI Data Security (403): https://media.defense.gov/2025/May/22/2003720601/-1/-1/0/CSI_AI_DATA_SECURITY.PDF
- DoD CIO AI tailoring guide (403): https://dodcio.defense.gov/Portals/0/Documents/Library/AI-CybersecurityRMTailoringGuide.pdf
- DoW AI Strategy: https://media.defense.gov/2026/Jan/12/2003855671/-1/-1/0/artificial-intelligence-strategy-for-the-department-of-war.pdf
- Holland & Knight: https://www.hklaw.com/en/insights/publications/2026/02/department-of-wars-ai-first-agenda-a-new-era-for-defense-contractors
- DefenseScoop: https://defensescoop.com/2026/05/01/dod-expands-classified-ai-work-with-8-companies-excluding-anthropic/ ; https://defensescoop.com/2026/09/11/dod-poised-to-move-all-classified-ai-workloads-off-anthropic-by-october/
- OMB M-25-21: https://www.whitehouse.gov/wp-content/uploads/2025/02/M-25-21-Accelerating-Federal-Use-of-AI-through-Innovation-Governance-and-Public-Trust.pdf
