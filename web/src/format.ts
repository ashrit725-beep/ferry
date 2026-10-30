/**
 * Display formatting. Numbers use a fixed locale so columns line up the same
 * way for every operator; timestamps are shown relative with the exact UTC
 * time available alongside.
 */

const INT = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const COMPACT = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'] as const;
export const DASH = '—';

export function formatInt(n: number | null | undefined): string {
  return n === null || n === undefined || !Number.isFinite(n) ? DASH : INT.format(n);
}

export function formatCompact(n: number | null | undefined): string {
  return n === null || n === undefined || !Number.isFinite(n) ? DASH : COMPACT.format(n);
}

/** Binary units, matching what `ls -lh` and the CLI print. */
export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n) || n < 0) return DASH;
  if (n < 1024) return `${Math.round(n)} B`;
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${BYTE_UNITS[unit]}`;
}

export function formatPercent(part: number, total: number): string {
  if (!(total > 0)) return DASH;
  const pct = (part / total) * 100;
  if (pct > 0 && pct < 0.1) return '<0.1%';
  return `${pct >= 10 || Number.isInteger(pct) ? pct.toFixed(0) : pct.toFixed(1)}%`;
}

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return DASH;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

export function parseTime(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t);
}

/** "2026-10-28 02:00:00.000 UTC"; unparseable input is returned as given. */
export function exactUtc(iso: string | null | undefined): string {
  const d = parseTime(iso);
  if (!d) return iso ?? DASH;
  return d.toISOString().replace('T', ' ').replace('Z', ' UTC');
}

/** "just now", "4 min ago", "in 3 d"; older than 30 days falls back to the date. */
export function relativeTime(iso: string | null | undefined, now: number): string {
  const d = parseTime(iso);
  if (!d) return iso ?? DASH;
  const diff = (d.getTime() - now) / 1000;
  const abs = Math.abs(diff);
  const phrase = (value: number, unit: string): string => (diff < 0 ? `${value} ${unit} ago` : `in ${value} ${unit}`);
  if (abs < 10) return diff <= 0 ? 'just now' : 'in a few seconds';
  if (abs < 60) return phrase(Math.floor(abs), 's');
  if (abs < 3600) return phrase(Math.floor(abs / 60), 'min');
  if (abs < 86_400) return phrase(Math.floor(abs / 3600), 'h');
  if (abs < 86_400 * 30) return phrase(Math.floor(abs / 86_400), 'd');
  return d.toISOString().slice(0, 10);
}

/** True when an RFC 3339 timestamp lies in the past (unparseable values count as not past). */
export function isPast(iso: string | null | undefined, now: number): boolean {
  const d = parseTime(iso);
  return d !== null && d.getTime() <= now;
}

/** "sha256:74a4da8c9fdb…a7a9db"; values that are not hex digests are shortened the same way. */
export function shortDigest(value: string, head = 12, tail = 6): string {
  const m = /^([a-z0-9]+:)?([0-9a-f]+)$/i.exec(value);
  const prefix = m?.[1] ?? '';
  const body = m ? (m[2] ?? '') : value;
  if (body.length <= head + tail + 1) return value;
  return `${prefix}${body.slice(0, head)}…${body.slice(-tail)}`;
}

/** Signing key ids are shown by their first 16 hex digits, as the CLI does. */
export function shortKeyId(value: string): string {
  return value.length > 16 ? `${value.slice(0, 16)}…` : value;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${formatInt(n)} ${n === 1 ? one : many}`;
}

/** datetime-local input value (treated as UTC) to RFC 3339; empty or invalid input gives ''. */
export function utcInputToRfc3339(value: string): string {
  if (!value) return '';
  const withSeconds = /T\d{2}:\d{2}$/.test(value) ? `${value}:00` : value;
  const t = Date.parse(`${withSeconds}Z`);
  return Number.isNaN(t) ? '' : new Date(t).toISOString();
}

/** RFC 3339 to a datetime-local input value in UTC ("2026-10-28T02:00"). */
export function rfc3339ToUtcInput(iso: string): string {
  const d = parseTime(iso);
  return d ? d.toISOString().slice(0, 16) : '';
}
