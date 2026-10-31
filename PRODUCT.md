# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Two audiences carry equal weight (confirmed 2026-10-29):

- **Enclave operators**: infrastructure and security engineers who run the disconnected side of Ferry. They import verified bundles, start inference runtimes on the imported files, register backends and routes, issue API keys to applications, edit and activate the access policy, and watch the gateway. They work inside a disconnected network on ordinary office laptops with integrated graphics, in modern browsers (Chrome, Edge, Firefox or Safari, current versions), often in windowless rooms. They use the console with the `ferry` command line beside it and expect parity between the two.
- **Auditors and transfer reviewers**: people who must trust the record. They sign in with the read-only `auditor` role to inspect verification results, the hash-chained audit log and the evidence report, and they compare what the console shows with what stock tools (OpenSSL, shasum) say about a bundle. Their job is to answer "what crossed the boundary, who allowed it, and can I prove it" without taking Ferry's word for it.

Publishers on the connected side (the people who pack, sign and rehearse bundles) use the command line and the generated review sheet; they are not console users.

## Product Purpose

Ferry is offline readiness for AI deliveries into disconnected networks. Before an AI stack is written to transfer media it runs the stack's exact launch command with network access blocked, names every hidden network call and the library behind it, and packs the model into a deterministic, signed bundle a reviewer can check with stock tools. On the receiving side it imports verified bundles and serves them through a default-deny, OpenAI-compatible gateway that confirms the backend is running the exact imported file, enforces API keys and policy, and keeps a hash-chained audit log and an evidence report.

The console is the receiving side's window onto all of that. Success for the console: an operator completes an import, route, key or policy change without the command line and without doubt about the current state; an auditor can reconstruct what happened and verify it, quickly, from the console alone.

Status: version 0.1.0, a working pre-customer prototype (2026-10-28). No customer has used it yet.

## Positioning

Generic air-gap movers treat model weights as opaque blobs and mostly assume Kubernetes. Ferry's mechanism, which a neighbouring product cannot truthfully copy: the preflight proves egress is blocked and attributes every hidden call to the library that made it; the bundle is verified fail-closed (signatures before parsing, content-based format checks, pickle and executable rejection, rollback protection) and is checkable without Ferry; the gateway proves provenance by confirming the served file is the imported file. The console therefore shows evidence, never claims.

## Operating Context

- Disconnected networks (air-gapped enclaves). The console is served by Ferry itself under a strict Content-Security-Policy: nothing is fetched from another origin, no inline script or style, fonts ship as files, and the build is checked for external URLs. No telemetry, analytics or update checks exist.
- Workflow on the receiving side: trust a publisher key (fingerprint check), verify and import a bundle (long-running jobs with progress), start a runtime on the imported file, add a backend and a route with provenance, create apps and issue one-time API keys, validate and activate a policy, explain why a request would be allowed or denied, read and filter the audit log, verify the chain, export the audit log and the evidence report (Markdown and JSON) for the transfer file.
- Roles: `admin` (full) and `auditor` (read-only; admin-only controls hidden and rejected server-side).
- Real data only: everything on screen comes from the admin API; a local demo with a real 0.5 GB model exists for development (gateway at 127.0.0.1:8750, demo workspace under demo/work/).
- Rituals around the product: transfer review meetings where the review sheet, the OpenSSL check and the evidence report are read line by line; incident reviews that start from the audit chain.

## Capabilities and Constraints

- Pages that must all survive the redesign with the same hash routes, actions and gating (confirmed): Login; Overview; Bundles (inbox with Verify/Import and live job progress, verification history); Bundle detail (checks, signers, artifacts); Verification detail; Models (imported models, routes with provenance badges, backends with health and Check, add backend/route); Access (apps and keys with one-time key display; policy editor with Validate/Activate and version history; Explain tool); Audit (filterable, searchable event table, event detail with hash and prev_hash, Verify chain, Export); Evidence (rendered report, Markdown/JSON download, network inventory, effective config); Not found.
- Stack: React 19, TypeScript, Vite; Tailwind v4 and shadcn (base-ui) are being adopted for the redesign; every npm package is pinned exactly, scripts are not run on install, and shipped code is reviewed for network behaviour in docs/network-dependencies.md.
- Browser floor (confirmed): current Chrome, Edge, Firefox and Safari; integrated graphics, so ambient effects must stay cheap and must degrade under prefers-reduced-motion.
- Terminology the product owns: bundle, bundle id (sha256:…), manifest, publisher and reviewer signatures, trust store, import, store file, provenance, backend, route, app, API key, policy version, audit chain, head hash, evidence report, rehearsal, preflight.
- Undecided (recorded, not invented): a licence for the repository; whether a light theme is required (not pinned on 2026-10-29).

## Brand Commitments

- The name **Ferry** and the existing Ferry mark (the glyph in web/src/components/Icons.tsx) stay.
- Voice: concise, factual, specific; controls name their action; errors name the problem and the recovery; no marketing language inside the console.

## Evidence on Hand

- Real demo data: one imported bundle (Qwen2.5-0.5B-Instruct, 491 MB GGUF), one route with verified provenance, two apps, three API keys, an active policy, an intact audit chain, an evidence report (demo/work/<timestamp>/evidence.md).
- The test suite (1,300+ tests), the security review (docs/security-review.md) and the limitations list (docs/limitations.md).
- Absent, never to be fabricated: customers, testimonials, benchmarks against competitors, pricing, certifications.

## Product Principles

1. Fail closed and say so: a refusal is shown with the exact check that failed and what to do next.
2. Evidence over claims: show the hash, the signer, the file, the chain; never a green tick without the thing it rests on.
3. Nothing hidden: what the console does, the command line can do, and the audit log records both.
4. Operate under constraint: dense, fast, keyboard-operable, readable on a plain laptop inside a windowless room.
5. One language for state: pass, fail, warning, pending and info look the same on every page.

## Accessibility & Inclusion

WCAG 2.2 AA is binding (confirmed): contrast, keyboard operability, visible focus, no information carried by colour alone, and motion that respects prefers-reduced-motion.
