/**
 * JSON for display and for the policy editor. Text is only ever parsed with
 * JSON.parse and printed with JSON.stringify; nothing is evaluated, and
 * highlighting works on the printed text, so markup never comes from data.
 */

export type JsonTokenKind = 'key' | 'string' | 'number' | 'literal' | 'punct';

export interface JsonToken {
  kind: JsonTokenKind;
  text: string;
}

export function prettyJson(value: unknown, indent = 2): string {
  if (value === undefined) return '';
  return JSON.stringify(value, null, indent) ?? '';
}

// A string (optionally followed by ':' when it is a key), a number, or a literal.
const TOKEN = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b/g;

export function jsonTokens(value: unknown, indent = 2): JsonToken[] {
  const text = prettyJson(value, indent);
  const out: JsonToken[] = [];
  let last = 0;
  for (const m of text.matchAll(TOKEN)) {
    const index = m.index;
    if (index > last) out.push({ kind: 'punct', text: text.slice(last, index) });
    if (m[1] !== undefined) {
      if (m[2] !== undefined) {
        out.push({ kind: 'key', text: m[1] });
        out.push({ kind: 'punct', text: m[2] });
      } else {
        out.push({ kind: 'string', text: m[1] });
      }
    } else if (m[3] !== undefined) {
      out.push({ kind: 'number', text: m[3] });
    } else if (m[4] !== undefined) {
      out.push({ kind: 'literal', text: m[4] });
    }
    last = index + m[0].length;
  }
  if (last < text.length) out.push({ kind: 'punct', text: text.slice(last) });
  return out;
}

export type JsonParseResult =
  | { ok: true; value: unknown }
  | { ok: false; message: string; line: number | null; column: number | null };

/** 1-based line and column of a 0-based offset. */
export function lineColumn(text: string, offset: number): { line: number; column: number } {
  const p = Math.max(0, Math.min(offset, text.length));
  const before = text.slice(0, p);
  const line = before.split('\n').length;
  return { line, column: p - before.lastIndexOf('\n') };
}

/** 0-based offset of a 1-based line and column, clamped to the text. */
export function offsetOf(text: string, line: number, column: number): number {
  let offset = 0;
  for (let l = 1; l < line; l += 1) {
    const next = text.indexOf('\n', offset);
    if (next === -1) return text.length;
    offset = next + 1;
  }
  return Math.min(offset + Math.max(0, column - 1), text.length);
}

// Engines word their messages differently: V8 gives "position N" and sometimes
// "(line L column C)", Firefox "at line L column C of the JSON data".
function locate(message: string, text: string): { line: number | null; column: number | null } {
  const lc = /line (\d+) column (\d+)/i.exec(message);
  if (lc) return { line: Number(lc[1]), column: Number(lc[2]) };
  const pos = /position (\d+)/i.exec(message);
  if (pos) return lineColumn(text, Number(pos[1]));
  return { line: null, column: null };
}

function tidy(message: string): string {
  return (
    message
      .replace(/^JSON\.parse:\s*/i, '')
      .replace(/^JSON Parse error:\s*/i, '')
      .replace(/\s*\(line \d+ column \d+\)/i, '')
      .replace(/\s+at line \d+ column \d+ of the JSON data/i, '')
      .replace(/\s+in JSON at position \d+/i, '')
      .trim() || 'not valid JSON'
  );
}

export function parseJson(text: string): JsonParseResult {
  if (!text.trim()) return { ok: false, message: 'the document is empty', line: null, column: null };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (err) {
    const raw = err instanceof Error ? err.message : String(err);
    return { ok: false, message: tidy(raw), ...locate(raw, text) };
  }
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    // Object.fromEntries defines own properties, so a "__proto__" key stays a plain key.
    return Object.fromEntries(Object.keys(obj).sort().map((k) => [k, sortKeys(obj[k])]));
  }
  return value;
}

/** Key-sorted, whitespace-free JSON: equal for documents that differ only in layout or key order. */
export function canonicalText(value: unknown): string {
  return JSON.stringify(sortKeys(value)) ?? '';
}

/** True when two texts are the same JSON document (or, if either does not parse, the same text). */
export function sameDocument(a: string, b: string): boolean {
  if (a === b) return true;
  const pa = parseJson(a);
  const pb = parseJson(b);
  return pa.ok && pb.ok && canonicalText(pa.value) === canonicalText(pb.value);
}
