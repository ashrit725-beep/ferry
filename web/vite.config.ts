import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin, type ProxyOptions } from 'vite';

/**
 * The console is served inside disconnected networks, so the build must contain
 * nothing a browser could fetch from another origin. Bundled React code carries
 * a few URL-shaped strings that are never fetched: the error-decoder hint in
 * production error messages and XML namespace names, which are identifiers,
 * not addresses. They are neutralised so that `grep -r http ferry/static`
 * stays empty, and any other remote reference fails the build instead of
 * shipping. scripts/check-dist.mjs re-checks the written files.
 */
const NEUTRALISE: ReadonlyArray<readonly [RegExp, string]> = [
  // Message text only: keep the hint, drop the scheme.
  [/https:\/\/react\.dev\/errors\//g, 'react.dev/errors/'],
  // Message text only: motion-utils formatErrorMessage appends this hint to
  // its warnings and invariant errors. Keep the hint, drop the scheme.
  [/https:\/\/motion\.dev\/troubleshooting\//g, 'motion.dev/troubleshooting/'],
  // Inside a JS string literal `\/` is the same character as `/`, so the
  // namespace values react-dom passes to createElementNS are unchanged.
  [/http:\/\/www\.w3\.org\//g, 'http:\\/\\/www.w3.org/'],
  // Tailwind's preserved license banner comment at the top of the built CSS.
  [/https:\/\/tailwindcss\.com/g, 'tailwindcss.com'],
  // Message text only: @base-ui/utils formatErrorMessage passes this through
  // new URL() to name the page in a production error message, so dropping the
  // scheme would replace that message with a TypeError. Escaped like the
  // namespace above: the string is unchanged at runtime and never fetched.
  [/https:\/\/base-ui\.com\/production-error/g, 'https:\\/\\/base-ui.com/production-error'],
];

const SCHEME_URL = /https?:\/\//i;

/** True for url() references the CSP allows: same-origin paths and data: images. */
function isLocalRef(ref: string): boolean {
  if (ref.startsWith('//')) return false;
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref)) return ref.startsWith('data:image/');
  return true;
}

function context(text: string, index: number): string {
  return text.slice(Math.max(0, index - 40), index + 60).replace(/\s+/g, ' ');
}

function offlineGuard(): Plugin {
  return {
    name: 'ferry-offline-guard',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const problems: string[] = [];
      for (const file of Object.values(bundle)) {
        let text: string;
        if (file.type === 'chunk') {
          for (const [pattern, replacement] of NEUTRALISE) {
            file.code = file.code.replace(pattern, replacement);
          }
          text = file.code;
        } else if (file.fileName.endsWith('.css') && typeof file.source === 'string') {
          for (const [pattern, replacement] of NEUTRALISE) {
            file.source = file.source.replace(pattern, replacement);
          }
          text = file.source;
        } else {
          text = typeof file.source === 'string' ? file.source : new TextDecoder('latin1').decode(file.source);
        }
        const match = SCHEME_URL.exec(text);
        if (match) problems.push(`${file.fileName}: ...${context(text, match.index)}...`);
        if (file.fileName.endsWith('.css')) {
          for (const m of text.matchAll(/url\(\s*["']?([^"')\s]+)/g)) {
            const ref = m[1] ?? '';
            if (!isLocalRef(ref)) problems.push(`${file.fileName}: non-local url(${ref.slice(0, 80)})`);
          }
          if (/@import\b/.test(text)) problems.push(`${file.fileName}: @import is not allowed in built CSS`);
        }
      }
      if (problems.length > 0) {
        this.error(`remote references in the console build (it must work offline):\n  ${problems.join('\n  ')}`);
      }
    },
  };
}

/**
 * Sonner calls `__insertCSS("...")` when its module loads, which appends a
 * <style> element. The gateway's `style-src 'self'` refuses it, so every page
 * load would log two CSP violations (the empty element, then its text). The
 * same stylesheet is imported from `sonner/dist/styles.css` in index.css and
 * ships in the bundle's CSS file, so the call is removed here. The build fails
 * if the call is no longer found, so a Sonner upgrade cannot quietly bring the
 * injection back.
 */
const SONNER_INSERT_CSS = /__insertCSS\("(?:[^"\\]|\\.)*"\);?/;

function cspSafeSonner(): Plugin {
  return {
    name: 'ferry-csp-safe-sonner',
    apply: 'build',
    transform(code, id) {
      if (!/[\\/]node_modules[\\/]sonner[\\/]dist[\\/]index\.mjs$/.test(id)) return null;
      if (!SONNER_INSERT_CSS.test(code)) {
        this.error("sonner no longer calls __insertCSS(\"...\"): check how it injects its stylesheet; style-src 'self' refuses <style> elements");
      }
      return { code: code.replace(SONNER_INSERT_CSS, ''), map: null };
    },
  };
}

// changeOrigin stays false so the backend sees the browser's Host header and
// its Origin check (spec section 6) passes for requests made through the proxy.
const backend: ProxyOptions = { target: 'http://127.0.0.1:8750', changeOrigin: false };
const proxy = { '/api': backend, '/v1': backend, '/healthz': backend };

export default defineConfig({
  base: '/',
  plugins: [tailwindcss(), react(), cspSafeSonner(), offlineGuard()],
  // Resolved from this file's URL so the alias needs no node typings in tsconfig.
  resolve: { alias: { '@': decodeURIComponent(new URL('./src', import.meta.url).pathname) } },
  build: {
    outDir: '../ferry/static',
    emptyOutDir: true,
    assetsDir: 'assets',
    // Fonts must stay files: font-src 'self' does not allow data: URIs.
    assetsInlineLimit: 0,
    sourcemap: false,
    target: 'es2022',
    modulePreload: { polyfill: false },
    chunkSizeWarningLimit: 700,
  },
  server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  preview: { host: '127.0.0.1', port: 4173, strictPort: true, proxy },
});
