/**
 * Maps status values from the API to a visual tone. The tone only ever adds
 * colour to a badge that already shows the value as text, so an unknown or
 * future value still reads correctly (it falls back to neutral).
 */

import type { ApiKeySummary, LastAuditVerify } from './api.ts';
import { isPast } from './format.ts';

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral';

export type StatusDomain =
  | 'verdict'
  | 'check'
  | 'signature'
  | 'artifact'
  | 'provenance'
  | 'backend'
  | 'job'
  | 'outcome'
  | 'severity'
  | 'trust'
  | 'key'
  | 'decision'
  | 'app'
  | 'availability'
  | 'chain';

const TONES: Record<StatusDomain, Readonly<Record<string, Tone>>> = {
  verdict: { accepted: 'ok', rejected: 'bad' },
  check: { pass: 'ok', fail: 'bad', warn: 'warn', skip: 'neutral' },
  signature: {
    valid: 'ok',
    invalid: 'bad',
    malformed: 'bad',
    revoked: 'bad',
    expired: 'warn',
    not_yet_valid: 'warn',
    untrusted: 'neutral',
  },
  artifact: { ok: 'ok', mismatch: 'bad', missing: 'bad', malformed: 'bad', rejected: 'bad', skipped: 'neutral' },
  provenance: { verified: 'ok', mismatch: 'bad', unverified: 'warn', not_pinned: 'warn', unknown: 'neutral' },
  backend: { up: 'ok', down: 'bad', loading: 'warn' },
  job: { queued: 'neutral', running: 'info', succeeded: 'ok', failed: 'bad' },
  outcome: {
    success: 'ok',
    accepted: 'ok',
    denied: 'warn',
    rejected: 'warn',
    unauthenticated: 'warn',
    unavailable: 'warn',
    failure: 'bad',
    error: 'bad',
  },
  severity: { error: 'bad', warning: 'warn', info: 'info' },
  trust: { active: 'ok', revoked: 'bad', expired: 'warn', not_yet_valid: 'warn' },
  key: { active: 'ok', expired: 'warn', revoked: 'neutral' },
  decision: { allow: 'ok', deny: 'bad' },
  app: { enabled: 'ok', disabled: 'neutral' },
  availability: { available: 'ok', unavailable: 'bad', disabled: 'neutral' },
  chain: { intact: 'ok', broken: 'bad' },
};

/** Values come from the server, so only own keys count ("constructor" is not a status). */
export function toneFor(domain: StatusDomain, value: string | null | undefined): Tone {
  if (!value) return 'neutral';
  const tones = TONES[domain];
  return Object.prototype.hasOwnProperty.call(tones, value) ? (tones[value] ?? 'neutral') : 'neutral';
}

/** "not_pinned" reads as "not pinned". */
export function statusLabel(value: string): string {
  return value.replace(/_/g, ' ');
}

export type KeyStatus = 'active' | 'revoked' | 'expired';

export function keyStatus(key: ApiKeySummary, now: number): KeyStatus {
  if (key.revoked_at) return 'revoked';
  if (key.expires_at && isPast(key.expires_at, now)) return 'expired';
  return 'active';
}

/** Severity order for sorting attention items: errors first. */
export function severityRank(severity: string): number {
  return severity === 'error' ? 0 : severity === 'warning' ? 1 : severity === 'info' ? 2 : 3;
}

/** Only the exact role "admin" unlocks admin controls; any other value is read-only. */
export function isAdminRole(role: string | null | undefined): boolean {
  return role === 'admin';
}

/**
 * A job is worth polling only while queued or running. Any other value,
 * including one this console does not know, ends polling instead of looping.
 */
export function isJobActive(state: string | null | undefined): boolean {
  return state === 'queued' || state === 'running';
}

/* ------------------------------------------------------------------ audit chain coverage */

/**
 * What the last recorded chain check says about the log as it stands now. A
 * check only vouches for the events it recomputed: anything appended after the
 * check's own audit.verify event is not covered until the chain is verified again.
 */
export type ChainCoverage =
  | { kind: 'never' }
  | { kind: 'failed'; last: LastAuditVerify }
  | { kind: 'current'; last: LastAuditVerify; checkedTo: number | null }
  | { kind: 'stale'; last: LastAuditVerify; checkedTo: number | null; since: number | null };

export function chainCoverage(audit: { head_seq: number; last_verify: LastAuditVerify | null }): ChainCoverage {
  const last = audit.last_verify;
  if (last === null) return { kind: 'never' };
  if (!last.ok) return { kind: 'failed', last };
  const checkedTo = last.head_seq ?? (last.seq !== null ? last.seq - 1 : null);
  // Without the check's own seq the coverage cannot be shown, so it is not claimed.
  if (last.seq === null) return { kind: 'stale', last, checkedTo, since: null };
  if (audit.head_seq <= last.seq) return { kind: 'current', last, checkedTo };
  // Counted from the last covered event, so the check's own record (not covered by it) is one of them.
  return { kind: 'stale', last, checkedTo, since: audit.head_seq - (checkedTo ?? last.seq) };
}
