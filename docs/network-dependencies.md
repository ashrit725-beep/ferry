# Network dependency inventory

Every network interaction of Ferry and of the components it is designed to run
with. "Verified" means observed on the build machine (macOS 26.5.1, Apple M3 Pro)
on 2026-10-28 (the console: 2026-10-30) or enforced by an automated test;
everything else is labelled. Running locally is not the same as being
air-gapped; this inventory is what lets you check the difference.

## Ferry on the disconnected side (gateway, console, importer)

| Direction | Destination | Purpose | When | Control |
|---|---|---|---|---|
| Inbound | `server.host:server.port` (default `127.0.0.1:8750`) | OpenAI-compatible API, admin API, console | While `ferry serve` runs | `[server]` in ferry.toml. Plain HTTP unless `tls_cert_file`/`tls_key_file` are set |
| Outbound | Each configured backend `base_url` | Inference requests and health checks | Per request; health every `health_interval_s` | Admins add backends. Addresses must resolve to loopback/private ranges unless `allow_public_backends = true` in ferry.toml. Link-local (e.g. 169.254.169.254) is always refused. Proxy environment variables are ignored; redirects are not followed |
| DNS | Backend host names | Resolving names for the egress check | When a backend is saved and before upstream requests (cached 30 s) | Use IP literals to avoid DNS entirely |
| None | Telemetry, crash reporting, update checks, licence checks, CDNs, remote fonts, time sync | Not implemented | Never | Nothing to disable |

`ferry import`, `ferry verify`, `ferry audit`, `ferry evidence` and the other
local commands make no network connections.

## Ferry on the connected side

| Command | Network behaviour |
|---|---|
| `ferry keygen`, `pack`, `sign`, `inspect`, `verify` | None |
| `ferry rehearse` | Starts llama-server inside a network sandbox and talks to it over loopback. From inside the sandbox it attempts one TCP connection to `192.0.2.1:443` (RFC 5737 TEST-NET-1, never routed on the internet) and one DNS lookup of `example.com`; both are expected to fail, which is the evidence that egress was blocked. **Verified** on macOS: both denied, loopback served a real completion (tests/test_sandbox.py) |
| `demo/fetch-model.sh` | Operator step, not part of Ferry: `curl` from huggingface.co at a pinned revision, then a SHA-256 check against the published digest |

## Python runtime dependencies

Direct: fastapi, uvicorn, httpx, cryptography, pydantic. None of them make
network connections on import. Ferry's HTTP client is used only for backends.

| Package (version installed here) | Network behaviour | Status |
|---|---|---|
| fastapi 0.162.0, starlette 1.10.0 | None. FastAPI's own `/docs` page loads assets from a CDN, so Ferry disables `/docs`, `/redoc` and `/openapi.json` | Docs routes disabled in `create_app` (checked by tests) |
| opentelemetry-api 1.45.1 (required by fastapi 0.162) | API only. Without an OpenTelemetry SDK and exporter it records and sends nothing | **Verified** dependency chain (`pip show`). `ferry doctor` warns if an SDK or exporter package is installed |
| uvicorn 0.54.0, h11, click | Listener only | |
| httpx 0.28.1, httpcore, anyio, idna, certifi | Outbound only when Ferry calls a backend. Created with `trust_env=False` | certifi is a CA bundle file; no network |
| cryptography 50.0.2, cffi, pycparser | None | |
| pydantic 2.14.1, pydantic-core, typing-extensions, annotated-types, annotated-doc, typing-inspection | None | |

Build-time only: setuptools (wheel build), pytest (tests).

## Console (web/)

Built on the connected side with npm (`cd web && npm ci && npm run build`) and
committed to `ferry/static/`, which Ferry serves itself. The stack is React 19
and TypeScript bundled by Vite 8, Tailwind CSS v4, shadcn components on Base UI
primitives, motion, lucide icons, Sonner toasts and the cmdk command palette.
Fonts are Archivo Variable (`@fontsource-variable/archivo`) and Azeret Mono
(`@fontsource/azeret-mono`): latin and latin-ext woff2 files only, copied into
`ferry/static/assets/`. IBM Plex and Geist are no longer installed. The page
fetches nothing from another origin: no CDN, no remote fonts, no analytics, no
update checks. The only request it makes is to Ferry itself.

How the build is kept offline:

- Every package is pinned to an exact version. `web/.npmrc` sets
  `ignore-scripts=true` (no install script runs) and `save-exact=true`, and
  `package-lock.json` resolves from `registry.npmjs.org` only, with sha512
  integrity (checked by `web/tests/test_static_build.py`).
- Ferry serves the console under `default-src 'self'; script-src 'self';
  style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'`.
  The HTML has no inline script, no `<style>` element and no `style=""`
  attribute; fonts are files (`assetsInlineLimit: 0`), never `data:` URIs.
- The `offlineGuard` plugin in `web/vite.config.ts` fails the build on any
  `http://` or `https://` string left in a built file once the rewrites in the
  last table below are applied, on any CSS `url()` that is not same-origin or
  `data:image/`, and on any `@import` in the built CSS.
  `web/scripts/check-dist.mjs` and the tests check the written files again and
  also refuse source maps, service workers, `eval` and `new Function`;
  `grep -ri 'https\?://' ferry/static` prints nothing.
- Sonner (toasts) injects its stylesheet as a `<style>` element when its module
  loads, which `style-src 'self'` refuses. The `cspSafeSonner` plugin in
  `web/vite.config.ts` strips that `__insertCSS(...)` call at build time, so the
  CSP sees no inline styles; the same rules ship in the built CSS file
  (`sonner/dist/styles.css`, imported by `src/index.css`). The build fails if the
  call is not found, so a Sonner upgrade cannot bring the injection back
  unnoticed, and a test checks that the toast rules are in the CSS and not in
  the JS. Base UI is mounted in its `CSPProvider` with `disableStyleElements`
  for the same reason.

**Verified** on the build machine on 2026-10-30:

- None of the 52 packages in the production closure (the `package-lock.json`
  entries not marked `dev`) contains `fetch(`, `XMLHttpRequest`, `WebSocket`,
  `sendBeacon`, `new Image(`, `importScripts`, `eval(`, `new Function`,
  `document.cookie` or `localStorage` in a `.js`, `.mjs`, `.cjs` or `.css`
  file. The only hosts those files name are documentation, issue-tracker,
  specification and attribution sites (react.dev, github.com,
  developer.mozilla.org, floating-ui.com, base-ui.com, motion.dev and the
  like), in comments and in warning or error text, plus XML namespace names.
- The built JS contains one `fetch(`, in the API client (`web/src/api.ts`,
  same-origin, credentials `same-origin`, redirects refused), and no
  `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `localStorage`,
  `sessionStorage`, `indexedDB`, `eval`, `new Function` or service-worker
  reference.
- A probe build listed what is bundled: 44 of the 52 packages contribute code
  (9 direct, 35 transitive). The other 8 are the two font packages (CSS and
  woff2 files), the type declarations (`@types/react`, `@types/react-dom`,
  `csstype`) and three packages whose code does not reach the bundle
  (`@babel/runtime`, `reselect`, `detect-node-es`).
- `tsc --noEmit` and the Vite build ran with all network access denied
  (`sandbox-exec` with `(deny network*)`, under which a loopback `connect()`
  fails with EPERM instead of ECONNREFUSED). The build, driven through Vite's
  API with the project's `vite.config.ts` and written to a scratch directory,
  produced the 9 files of `ferry/static` with the same SHA-256 as the shipped
  build.

Direct dependencies (`web/package.json`; 11 runtime, 9 build-time). "Browser"
means the code is in the JS or CSS served to the browser; "Build" means it runs
under Node on the connected side and ships nothing but generated files.

| Package (version installed here) | Runs | Network behaviour | URL strings (those the build guard rewrites are marked) |
|---|---|---|---|
| react 19.3.1 | Browser | None | None in the bundle |
| react-dom 19.3.1 | Browser | None | `https://react.dev/errors/` in production error text (rewritten); `http://www.w3.org/…` namespace names passed to `createElementNS` (rewritten) |
| @base-ui/react 1.9.0 | Browser | None | None of its own. Its helper @base-ui/utils builds `https://base-ui.com/production-error` into production error text (rewritten). Documentation links in its source comments are stripped by the minifier |
| cmdk 1.1.1 | Browser | None | None |
| sonner 2.0.8 | Browser | None. Its runtime `<style>` injection is stripped at build time (above) | `http://www.w3.org/2000/svg` on its built-in icons (rewritten) |
| motion 14.8.0 | Browser | None. Animates elements already on the page | `https://motion.dev/troubleshooting/` is appended to its warning and error text (rewritten). It is absent from the current bundle; the rule stays so an upgrade cannot break the build |
| lucide-react 1.64.0 | Browser | None. Icons are inline SVG | `http://www.w3.org/2000/svg`, the default `xmlns` of each icon (rewritten) |
| class-variance-authority 0.7.1 | Browser | None | Apache licence URL in a header comment, stripped by the minifier |
| cn 0.5.0 | Browser | None | None |
| @fontsource-variable/archivo 5.3.0 | Browser (CSS and woff2 files copied by Vite) | None. Font files only, referenced by same-origin path | None |
| @fontsource/azeret-mono 5.3.0 | Browser (CSS and woff2 files copied by Vite) | None. Font files only, referenced by same-origin path | None |
| vite 8.3.5 | Build | None while building (**verified**, above). `npm run dev` and `vite preview`, started by hand, listen on 127.0.0.1 only (ports 5173 and 4173) and proxy `/api`, `/v1` and `/healthz` to `127.0.0.1:8750` | None ships |
| @vitejs/plugin-react 6.1.2 | Build | None | None ships |
| typescript 7.0.2 | Build | None. `tsc --noEmit` only type-checks | None ships |
| tailwindcss 4.3.3 | Build | None. Compiles the utility CSS; its `@import` handling skips `http(s)://` and `data:` URLs instead of fetching them | `https://tailwindcss.com` in the licence banner at the top of the built CSS (rewritten) |
| @tailwindcss/vite 4.3.3 | Build | None | None ships |
| tw-animate-css 1.4.0 | Build (static CSS imported by `src/index.css`) | None | None ships |
| shadcn 4.23.0 | Build (CLI; only its static `shadcn/tailwind.css` is imported) | The CLI contacts the shadcn registry only when an engineer runs `shadcn add` or `init` to vendor component sources. The build never runs it | Registry and documentation URLs inside the CLI; none ships |
| @types/react 19.3.0 | Build (declaration files) | None | None ships |
| @types/react-dom 19.3.0 | Build (declaration files) | None | None ships |

Transitive packages that contribute code to the bundle (35; none contains the
patterns scanned for above):

| Pulled in by | Packages (version installed here) |
|---|---|
| @base-ui/react | @base-ui/utils 0.5.0, @floating-ui/react-dom 2.1.9, @floating-ui/dom 1.8.0, @floating-ui/core 1.8.0, @floating-ui/utils 0.2.12, use-sync-external-store 1.7.0 |
| cmdk | @radix-ui/{primitive 1.2.0, react-compose-refs 1.1.5, react-context 1.3.0, react-dialog 1.3.1, react-dismissable-layer 1.2.1, react-focus-guards 1.2.0, react-focus-scope 1.3.1, react-id 1.1.4, react-portal 1.2.0, react-presence 1.1.11, react-primitive 2.2.0, react-slot 1.5.0, react-use-callback-ref 1.1.5, react-use-controllable-state 1.3.0, react-use-effect-event 0.0.5, react-use-layout-effect 1.1.4}, aria-hidden 1.2.6, react-remove-scroll 2.7.2, react-remove-scroll-bar 2.3.8, react-style-singleton 2.2.3, use-callback-ref 1.3.3, use-sidecar 1.1.3, get-nonce 1.0.1 |
| motion | framer-motion 14.8.0, motion-dom 14.8.0, motion-utils 14.7.0, tslib 2.8.1 |
| class-variance-authority | clsx 2.1.1 |
| react-dom | scheduler 0.28.0 |

All shipped code is MIT, ISC (lucide-react), Apache-2.0 (class-variance-authority)
or 0BSD (tslib); the two font packages are SIL OFL 1.1.

URL-shaped strings the build guard rewrites (`NEUTRALISE` in
`web/vite.config.ts`). They are message text, XML identifiers or a comment, and
nothing requests them. These are the only ones the bundle contains; any other
URL string fails the build.

| String | Where it comes from | Why it is harmless | Rewritten to |
|---|---|---|---|
| `https://react.dev/errors/` (2 in the JS) | react-dom | Hint appended to production error messages | `react.dev/errors/` (scheme dropped) |
| `https://base-ui.com/production-error` (1) | @base-ui/utils | Passed to `new URL()` to name the page in a production error message | `https:\/\/base-ui.com/production-error`: inside a JS string `\/` is `/`, so the value is unchanged at runtime, and it is never requested |
| `http://www.w3.org/2000/svg`, `…/1999/xlink`, `…/1998/Math/MathML`, `…/XML/1998/namespace` (24) | react-dom (`createElementNS`), lucide-react and sonner (`xmlns` on SVG icons) | XML namespace names are identifiers, not addresses | `http:\/\/www.w3.org/…`, the same value at runtime |
| `https://tailwindcss.com` (1, in the CSS) | Tailwind's licence banner comment | A comment | `tailwindcss.com` |
| `https://motion.dev/troubleshooting/` (0 today) | motion-utils warning and error text | Hint appended to messages | `motion.dev/troubleshooting/` (scheme dropped) |

Limits of this review: the shipped code was scanned for network APIs and every
URL string in the built files was listed (the table above is that list). The
315 further packages that `npm ci` installs for the build only (Tailwind's
compiler and its native binaries `@tailwindcss/oxide` and `lightningcss`, Vite,
TypeScript, and the shadcn CLI with its own dependencies) were not read line by
line; the evidence for them is that the type check and the build ran with
network access denied and wrote the same bytes. The review is a snapshot of the
pinned versions. After any dependency change, repeat it: the build guard fails
on a new URL string, but it cannot see a new `fetch(`.

## Inference runtimes (installed by the operator)

| Runtime | Network behaviour | What Ferry does about it | Source |
|---|---|---|---|
| llama.cpp `llama-server` | Can download models (`-hf`, model URLs). `--offline` "forces use of cache, prevents network access" | `ferry runtime llamacpp` and `ferry rehearse` always pass `--offline --no-webui`, bind 127.0.0.1 and set `--api-key-file` | `llama-server --help` (0.7.0, b11669). **Verified**: served a completion inside the sandbox with egress and DNS denied |
| Ollama | No server-side auth. Desktop builds auto-update. `OLLAMA_NO_CLOUD=1` disables cloud models and web search | Put the gateway in front; bind Ollama to loopback; set `OLLAMA_NO_CLOUD=1` | docs/research/02, 06 |
| vLLM | Usage statistics unless `VLLM_NO_USAGE_STATS=1` or `DO_NOT_TRACK=1`; Hugging Face Hub calls unless `HF_HUB_OFFLINE=1` (set before start) | Documented here; Ferry cannot change vLLM's behaviour | docs/research/02, 06 |

## How to check a host yourself

1. `ferry doctor` lists configured listeners and backends, flags proxy
   variables, public backend addresses, telemetry-capable packages and external
   URLs in the console build. `ferry doctor --probe-network` (opt-in) tries one
   TCP connection to a public address and reports whether the host is actually
   isolated.
2. `ferry rehearse` runs the model with egress blocked and reports the probe.
3. Run the whole stack under an OS sandbox (`sandbox-exec` on macOS,
   `unshare --net` on Linux) the same way the rehearsal does.
