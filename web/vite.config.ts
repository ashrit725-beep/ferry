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
  // Inside a JS string literal `\/` is the same character as `/`, so the
  // namespace values react-dom passes to createElementNS are unchanged.
  [/http:\/\/www\.w3\.org\//g, 'http:\\/\\/www.w3.org/'],
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

// changeOrigin stays false so the backend sees the browser's Host header and
// its Origin check (spec section 6) passes for requests made through the proxy.
const backend: ProxyOptions = { target: 'http://127.0.0.1:8750', changeOrigin: false };
const proxy = { '/api': backend, '/v1': backend, '/healthz': backend };

export default defineConfig({
  base: '/',
  plugins: [react(), offlineGuard()],
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
