# Metrics: what we count, how, and what we never report

*Owner: founder. Written 2026-10-28. A number is reported only if a system recorded it or a counterparty confirmed it in writing, and only with its definition and date. Companions: [gtm](gtm.md), [customer-discovery](customer-discovery.md) (call notes, ledger, kill criteria), [pilot](pilot.md) (baseline B1-B6, criteria S1-S7), [pricing](pricing.md). Labels: VERIFIED, INFERRED, UNKNOWN.*

## 1. Current values (2026-10-28)

| Metric | Value |
|---|---|
| Conversations / qualified conversations | 0 / 0 |
| Concierge preflights offered / accepted / run | 0 / 0 / 0 |
| Pilots with a signed scope | 0 |
| Production deployments | 0 |
| Paying customers / revenue (cash received) | 0 / $0 |
| Preflight, rehearsal, verification and gateway activity in the evaluation, pilot or production class | 0 |
| Internal test activity | Exists (automated tests; founder runs and dry runs on the build Mac). Excluded from every reported number |
| Rule base | 11 rules in `ferry/offline_rules.py` (9 "documented", 2 "inferred"); 0 derived from evaluation, pilot or production runs |

## 2. Principles

1. **No telemetry, ever, for metrics' sake.** Ferry makes no telemetry, update or licence calls (docs/network-dependencies.md). Numbers from a prospect's or customer's machine exist only as reports or exports they choose to share, or as the counts they allow us to record (gtm.md §6, pilot.md §9).
2. **Every number carries its activity class** (§3). Classes are never summed.
3. **A count needs a record:** a report file, a database row, a call note, a signed document or a bank receipt. Memory and stated intent count zero.
4. **Zero is reported as zero**, with the date.
5. **No metric may require content.** Prompts, completions and credentials are never stored (`ferry.audit.sanitize`; the preflight smoke request keeps status, latency and token counts only).

## 3. Activity classes: test, pilot, production

| Class | Definition | Ferry label |
|---|---|---|
| internal | Run by us: test suite, demos, test doubles, our own models, dry runs | `test` |
| evaluation | A prospect's real launch command or bundle before a signed pilot scope (concierge preflight) | `test` |
| pilot | Work under a signed pilot scope, on the shipment it names (pilot.md) | `pilot` |
| production | The customer's own deliveries (vendor side) or real workloads (receiving side) after the pilot, confirmed by the customer in writing | `production` |

Where the label lives:
- **Gateway:** every app (principal) has `environment` in {`test`, `pilot`, `production`}, default `test` (`principals` table, ferry/db.py). Each `gateway.chat.completions` audit event copies the calling app's environment into `details.environment` (ferry/gateway/openai_api.py). An app counts as production only if the customer created or relabelled it `production` on their own installation and confirmed that in writing.
- **Preflight and rehearsal reports** carry no label (report version 1). Until a label field exists (roadmap 1.4), the class comes from the run ledger: who ran it, on whose command, under which agreement. An unlabelled report is internal.
- **Verifications and imports** carry no label. They take the class of the installation, recorded in the ledger.

## 4. Product metrics: observable system behaviour only

| Area | Metric | Source field | Code path |
|---|---|---|---|
| Preflight | Runs, pass, fail | Report `verdict` | VERIFIED (macOS) |
| | Valid run | `isolation.egress_blocked == true`. A run without a blocked probe (no sandbox, or `--allow-no-isolation`) is invalid: never counted as a pass, reported separately | VERIFIED |
| | Pass with warnings | `verdict == "pass"` with `warnings`: attempts accepted via `--allow-attempts`, or blocked DNS lookups the Python hook cannot attribute (warnings unless `--strict`). Never reported as a clean pass; a clean pass has no warnings | VERIFIED |
| | Attempts per run | `network_attempts` (kernel denials; DNS entries explained by local lookups excluded) and `python_network_calls` (host, port, package) | VERIFIED |
| | Findings per run | `findings[]` by `rule`, `confidence`, `matched_on` | VERIFIED |
| | Unmatched attempts (rule-base gaps) | Attempts or `output_indicators` with no finding. Example: the internal 2026-10-28 dry run of `llama-server -hf` | VERIFIED |
| | Attribution share (pilot.md S2) | Distinct attempts with a named process or Python `package`, and the share of those with a finding | VERIFIED fields |
| | Fix closure | A failing report followed by a passing report for the same command (matched by command hash once roadmap 1.4 lands) | VERIFIED fields |
| | Readiness and smoke request | `process.ready.seconds`; `process.request.ok`, `status`, `latency_ms`, token counts | VERIFIED |
| Bundles | Verifications accepted / rejected | Verification report `verdict`; stored in `verifications` (mode `verify` or `import`) when a data dir is used. Standalone `verify` stores nothing, so count saved reports | IN PROGRESS |
| | Rejection reason codes | `checks[].id` with status `fail`: `archive.*`, `manifest.*`, `signatures.*`, `inventory.*`, `artifact.*`, `policy.*`, `compat.*` (docs/design/v1-spec.md §4), plus `policy.rollback` and `policy.version_reuse` (v1-additions A1) | IN PROGRESS |
| | Imports | `bundles` rows; `bundle.import` audit events by outcome | IN PROGRESS |
| Gateway | Requests allowed, denied, errors | `audit_events` with `action = 'gateway.chat.completions'`, by `outcome` (`success`, `denied`, `rejected`, `unauthenticated`, `unavailable`, `error`) and `details.status_code`, per `details.environment` | IN PROGRESS |
| | Denied before inference | `denied` events by `details.decisive_rule` | IN PROGRESS |
| | Latency | `details.latency_ms`: p50 and p95 per environment and model | IN PROGRESS |
| | Provenance | `details.provenance`, `details.artifact_digest` | IN PROGRESS |
| | Audit integrity | `verify_chain` result. Numbers from an installation whose chain fails are invalid until explained | VERIFIED (chain check) |
| Rehearsal | Runs, pass, fail | Report `verdict`, `verification_verdict`, `isolation.egress_blocked`; per model `ok`, `load_seconds`, `latency_ms`, `served_file_matches_import`; runtime build | IN PROGRESS |

Queries for a `ferry.db` or an export the customer shares. They ran against the real schema on SQLite 3.50.4, 2026-10-28:

```sql
-- Gateway outcomes per environment
SELECT json_extract(details, '$.environment') AS env, outcome, COUNT(*) AS n
FROM audit_events WHERE action = 'gateway.chat.completions'
GROUP BY env, outcome ORDER BY env, outcome;

-- Latency samples for one environment (compute p50/p95 outside SQLite)
SELECT json_extract(details, '$.latency_ms') AS ms FROM audit_events
WHERE action = 'gateway.chat.completions' AND outcome = 'success'
  AND json_extract(details, '$.environment') = 'pilot' ORDER BY ms;

-- Rejected verifications by failing check
SELECT json_extract(c.value, '$.id') AS check_id, COUNT(*) AS n
FROM verifications v, json_each(v.report, '$.checks') c
WHERE v.verdict = 'rejected' AND json_extract(c.value, '$.status') = 'fail'
GROUP BY check_id ORDER BY n DESC;
```

**Attested measures are kept apart from product metrics.** Ferry cannot observe them, so they are reported as "attested by [role]":
- pilot.md S3 (findings the engineer judges irrelevant);
- S5 and S6 (the reviewer's stock-tool check, its duration, and the tamper test);
- S4 (preparation time against baseline B3);
- the shipment outcome below.

**The outcome that matters is not system-observed.** For each pilot or production shipment: did it run inside on the first transfer, with no missing file and no network failure? Measure transfer cycles and days to running inside at +30, +60 and +90 days, against the baseline B2 (pilot.md §13). Report it as "n of m shipments, customer-confirmed", never as a rate before m reaches 5.

## 5. Company funnel

| Stage | Counts when (all conditions) | Does not count | Record |
|---|---|---|---|
| Conversation | A live call or meeting of 15+ minutes with someone in a target role (vendor-side buyer or champion; receiving-side ISSM/ISSO, transfer agent or platform lead), about their own delivery or import work | Email threads, chat or forum replies, event chats under 15 minutes, friends, advisors, investors; competitors (logged separately) | Call note `docs/company/calls/V-xx.md` or `R-xx.md` |
| Qualified conversation | Passes the screen in customer-discovery §2, and either gives a qualifying incident (customer-discovery §6) or has a delivery (vendor side) or import (receiving side) due within 60 days | Interest without both | "qualifies Y" in the call note; incident row in `discovery-ledger.csv` |
| Concierge preflight run | `ferry preflight` executed on the prospect's real launch command (not a demo or test double), `egress_blocked == true`, report delivered to them | Our demos; a public model they suggested instead of their stack; runs without proven isolation | Ledger entry with date, verdict and the counts they allowed |
| Pilot (signed scope) | pilot.md's order form (scope, criteria, dates, fee, data handling) signed or accepted in writing by someone authorized. A waived fee is flagged "unpaid" | Verbal yes, "let's try it", an LOI without scope, concierge runs | Signed form, stored outside the repo; ledger entry |
| Production deployment | After the pilot, Ferry is part of the customer's own delivery workflow for a shipment to a real site (vendor side), or an enclave serves real workloads through apps labelled `production` (receiving side), confirmed in writing | Pilot shipments, staging installs, our own installs | Customer confirmation; optional evidence report or audit export they choose to share |
| Paying customer | Organization that has paid at least one invoice | Signed but unpaid, LOIs, free pilots, credits, refunded payments | Invoice and bank receipt |

Tracked but not stages: concierge offers, acceptances and declines (K7 needs 3+ acceptances by 2026-12-09); LOIs; referrals received; days between stages; and disqualification reasons coded as no-disconnected-delivery, provider-cloud-only, kubernetes-only, no-incident, fix-under-2-days, current-test-catches-it, cannot-run-tools or other.

Ratios between stages are reported only once the earlier stage has 10 or more entries; below that, counts only. Revenue is cash received, by month. Bookings (signed, unpaid) are reported separately. "ARR" is used only for signed recurring contracts, labelled contracted ARR.

## 6. Reporting to YC and investors

YC Winter 2027 applications close 2026-11-02 at 8pm PT, with decisions by 2026-12-11 (VERIFIED, https://www.ycombinator.com/apply). The form itself (apply.ycombinator.com) was not read, so its questions are not quoted here. Calls start 2026-11-02, so the application can include at most calls held that day; expect zeros.

**Report:**
- Funnel counts per §5, with the date and the definitions, zeros included. Template: "As of [date]: [N] discovery conversations ([M] qualified), 0 concierge runs, 0 pilots, 0 customers, $0 revenue."
- Users: "no users outside the founding team" until a concierge run happens. After that: "[k] organizations ran Ferry on their own launch command (unpaid evaluation)".
- Technical status, sorted by label. VERIFIED on macOS: preflight with an in-sandbox egress probe, kernel denial collection, Python attribution, an 11-rule base of offline fixes (9 documented, 2 inferred), and a real llama.cpp model passing. Also VERIFIED: Ed25519 manifest signatures checkable with stock OpenSSL, and an audit chain that detects modified events. IN PROGRESS: pack/sign/verify/import, rehearse, the receiving side. UNTESTED: Linux. NOT BUILT: vLLM-, NIM- or container-specific support beyond wrapping the launch command, Kubernetes, P-256/OMS/cosign.
- Problem evidence with its labels: public failure reports VERIFIED; cost and frequency UNKNOWN; the kill criteria and the 2026-12-09 decision date.

**Never report:**
- Test traffic as usage: gateway requests from `test` apps, our own preflights, rehearsals, CI runs, demos or dry runs.
- Concierge runs as pilots or customers; unpaid pilots as customers; LOIs, verbal commitments or "in talks with" as revenue, bookings or pipeline value.
- Contacts that fail §5 as conversations: emails, DMs, community replies, booth chats.
- Findings from test doubles as findings in the wild, or the rule base as "built from real runs" while that count is 0.
- Organization names or logos without written permission, or anything shared under the OPSEC rules (customer-discovery §3).
- Unverified market sizes, or other companies' valuations and funding presented as our market.
- Compliance or certification claims (FIPS, CMMC, "ATO-ready", "compliant"). Only "produces evidence that can support ...".
- Platform claims beyond the evidence: Linux, vLLM on CUDA, containers, Kubernetes.
- Growth percentages without the absolute numbers.

## 7. Cadence

- After every call: note and ledger row within 24 hours (customer-discovery §6).
- Weekly: refresh §1 from the ledger and check each number against its record.
- After every concierge run or pilot session: ledger entry with class, verdict and permitted counts.
- Before any external use (YC, investors, website, outreach): a second person checks every number against its record and definition.
- Names, emails, contracts and invoices stay outside the repo. The repo holds counts, role titles and organization types.
