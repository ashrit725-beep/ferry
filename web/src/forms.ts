/**
 * Small, testable pieces of form handling. The server stays the authority on
 * what is valid; these only catch input that cannot be sent at all.
 */

export type Scheme = 'http' | 'https';
export const SCHEMES: readonly Scheme[] = ['http', 'https'];

// The backend form takes the scheme from a select and the address from a text
// field and joins them here, so the console bundle never carries a literal URL.
const SEPARATOR = '://';

/** Splits a pasted base URL into scheme and address; an unsupported scheme is left in the address. */
export function splitBaseUrl(value: string): { scheme: Scheme | null; address: string } {
  const v = value.trim();
  const i = v.indexOf(SEPARATOR);
  if (i === -1) return { scheme: null, address: v };
  const scheme = v.slice(0, i).toLowerCase();
  if (scheme === 'http' || scheme === 'https') return { scheme, address: v.slice(i + SEPARATOR.length) };
  return { scheme: null, address: v };
}

/** Base URL to send. An address that already carries a scheme is sent unchanged for the server to judge. */
export function joinBaseUrl(scheme: Scheme, address: string): string {
  const a = address.trim();
  return a.includes(SEPARATOR) ? a : `${scheme}${SEPARATOR}${a}`;
}

export type NumberField = { ok: true; value: number | undefined } | { ok: false; error: string };

/** Parses an optional numeric field; empty means "not given". */
export function optionalNumber(text: string, opts: { integer?: boolean; min?: number } = {}): NumberField {
  const t = text.trim();
  if (!t) return { ok: true, value: undefined };
  const n = Number(t);
  if (!Number.isFinite(n)) return { ok: false, error: 'Enter a number.' };
  if (opts.integer && !Number.isInteger(n)) return { ok: false, error: 'Enter a whole number.' };
  if (opts.min !== undefined && n < opts.min) return { ok: false, error: `Enter ${opts.min} or more.` };
  return { ok: true, value: n };
}

/** Trimmed text, or undefined when empty, for optional string fields. */
export function optionalText(text: string): string | undefined {
  const t = text.trim();
  return t ? t : undefined;
}

/** Apps and rule ids share this grammar (spec sections 5 and 6). */
export const APP_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** Public model names (ferry.policy.MODEL_NAME). */
export const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** The documented empty policy: valid, and denies everything (spec section 5). */
export const EMPTY_POLICY = {
  schema: 'ferry.dev/access-policy/v1',
  description: '',
  rules: [] as unknown[],
};
