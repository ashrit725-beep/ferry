#!/usr/bin/env node
/**
 * Checks the built console in ../ferry/static before it is committed:
 *
 * - offline: no http:// or https:// anywhere in text assets, CSS url() only to
 *   files that exist next to it, no @import, no source maps;
 * - CSP (default-src 'self'; script-src 'self'; style-src 'self'; font-src
 *   'self'; img-src 'self' data:): index.html has no inline script or style,
 *   no style="" or on*="" attributes, only same-origin references, and fonts
 *   are files rather than data: URIs; scripts do not need eval;
 * - no service worker.
 *
 * Prints every file with its raw and gzip size. Exits 1 on any problem.
 * Usage: node scripts/check-dist.mjs [dist-dir]
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { dirname, extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(process.argv[2] ?? join(here, '..', '..', 'ferry', 'static'));
const TEXT = new Set(['.html', '.js', '.mjs', '.css', '.json', '.svg', '.txt', '.md', '.map', '.webmanifest']);
const problems = [];

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

function rel(file) {
  return relative(dist, file).split(sep).join('/');
}

function snippet(text, index) {
  return text.slice(Math.max(0, index - 40), index + 60).replace(/\s+/g, ' ');
}

/** A reference the CSP allows and that resolves to a file in the build. */
function checkLocalRef(ref, fromFile, what) {
  if (ref.startsWith('data:')) {
    if (!ref.startsWith('data:image/') && ref !== 'data:,') problems.push(`${rel(fromFile)}: ${what} uses a non-image data: URI`);
    return;
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(ref) || ref.startsWith('//')) {
    problems.push(`${rel(fromFile)}: ${what} points off-origin: ${ref.slice(0, 80)}`);
    return;
  }
  const path = ref.split(/[?#]/)[0];
  const target = path.startsWith('/') ? join(dist, path) : resolve(dirname(fromFile), path);
  if (!target.startsWith(dist + sep) || !existsSync(target)) {
    problems.push(`${rel(fromFile)}: ${what} refers to a missing file: ${ref}`);
  }
}

if (!existsSync(join(dist, 'index.html'))) {
  console.error(`check-dist: ${dist}/index.html does not exist; run the build first`);
  process.exit(1);
}

const files = walk(dist).sort();

for (const file of files) {
  const ext = extname(file).toLowerCase();
  if (ext === '.map') problems.push(`${rel(file)}: source maps must not ship`);
  if (!TEXT.has(ext)) continue;
  const text = readFileSync(file, 'utf8');
  const scheme = /https?:\/\//i.exec(text);
  if (scheme) problems.push(`${rel(file)}: contains a URL scheme: ...${snippet(text, scheme.index)}...`);
  if (/sourceMappingURL/.test(text)) problems.push(`${rel(file)}: references a source map`);
  if (/serviceWorker\s*\.\s*register|navigator\s*\.\s*serviceWorker/.test(text)) problems.push(`${rel(file)}: registers a service worker`);
  if (ext === '.js' && /(^|[^.\w$])eval\s*\(|new\s+Function\s*\(/.test(text)) {
    problems.push(`${rel(file)}: uses eval or new Function, which script-src 'self' forbids`);
  }
  if (ext === '.css') {
    if (/@import\b/.test(text)) problems.push(`${rel(file)}: @import is not allowed`);
    for (const m of text.matchAll(/url\(\s*(["']?)([^"')]+)\1\s*\)/g)) {
      const ref = m[2].trim();
      if (/^data:(font|application)\//i.test(ref)) problems.push(`${rel(file)}: font embedded as data: URI (font-src 'self' forbids it)`);
      else checkLocalRef(ref, file, 'url()');
    }
  }
}

const html = readFileSync(join(dist, 'index.html'), 'utf8');
for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  const attrs = m[1] ?? '';
  if ((m[2] ?? '').trim()) problems.push('index.html: inline <script> content');
  const src = /\ssrc=["']([^"']+)["']/i.exec(attrs);
  if (!src) problems.push('index.html: <script> without src');
  else checkLocalRef(src[1], join(dist, 'index.html'), '<script src>');
}
if (/<style\b/i.test(html)) problems.push('index.html: inline <style> element');
if (/\sstyle\s*=/i.test(html)) problems.push('index.html: style="" attribute');
if (/\son[a-z]+\s*=/i.test(html)) problems.push('index.html: inline event handler attribute');
for (const m of html.matchAll(/<(?:link|img|source|iframe|object|embed)\b[^>]*\s(?:href|src)=["']([^"']+)["']/gi)) {
  checkLocalRef(m[1], join(dist, 'index.html'), 'reference');
}
if (!files.some((f) => f.endsWith('.woff2'))) problems.push('no .woff2 font files in the build (fonts must be bundled)');

let raw = 0;
let gz = 0;
const rows = files.map((file) => {
  const bytes = readFileSync(file);
  const zipped = gzipSync(bytes, { level: 9 }).length;
  raw += bytes.length;
  gz += zipped;
  return [rel(file), bytes.length, zipped];
});
const kb = (n) => `${(n / 1024).toFixed(1)} KiB`.padStart(11);
console.log(`console build in ${dist}`);
for (const [name, size, zipped] of rows) console.log(`  ${kb(size)} ${kb(zipped)} gzip  ${name}`);
console.log(`  ${kb(raw)} ${kb(gz)} gzip  total (${rows.length} files)`);

if (problems.length) {
  console.error(`\ncheck-dist: ${problems.length} problem(s):\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log('check-dist: ok (offline, CSP-compatible, no source maps)');
