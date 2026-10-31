import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import type { ApiKeySummary } from '../src/api.ts';
import { chainCoverage, isAdminRole, isJobActive, keyStatus, severityRank, statusLabel, toneFor } from '../src/status.ts';

const NOW = Date.parse('2026-10-28T12:00:00.000Z');

describe('toneFor', () => {
  test('every provenance state from spec section 7 has a tone', () => {
    assert.equal(toneFor('provenance', 'verified'), 'ok');
    assert.equal(toneFor('provenance', 'mismatch'), 'bad');
    assert.equal(toneFor('provenance', 'unverified'), 'warn');
    assert.equal(toneFor('provenance', 'not_pinned'), 'warn');
    assert.equal(toneFor('provenance', 'unknown'), 'neutral');
  });

  test('signature and check statuses', () => {
    assert.equal(toneFor('signature', 'valid'), 'ok');
    assert.equal(toneFor('signature', 'invalid'), 'bad');
    assert.equal(toneFor('signature', 'revoked'), 'bad');
    assert.equal(toneFor('signature', 'untrusted'), 'neutral');
    assert.equal(toneFor('check', 'fail'), 'bad');
    assert.equal(toneFor('check', 'warn'), 'warn');
    assert.equal(toneFor('check', 'skip'), 'neutral');
  });

  test('unknown, empty and inherited names fall back to neutral', () => {
    assert.equal(toneFor('verdict', 'maybe'), 'neutral');
    assert.equal(toneFor('backend', null), 'neutral');
    assert.equal(toneFor('backend', ''), 'neutral');
    assert.equal(toneFor('outcome', 'constructor'), 'neutral');
    assert.equal(toneFor('outcome', '__proto__'), 'neutral');
  });
});

describe('labels and ordering', () => {
  test('statusLabel', () => {
    assert.equal(statusLabel('not_pinned'), 'not pinned');
    assert.equal(statusLabel('not_yet_valid'), 'not yet valid');
  });

  test('severityRank puts errors first', () => {
    const sorted = ['info', 'other', 'error', 'warning'].sort((a, b) => severityRank(a) - severityRank(b));
    assert.deepEqual(sorted, ['error', 'warning', 'info', 'other']);
  });
});

describe('keyStatus', () => {
  const key = (over: Partial<ApiKeySummary>): ApiKeySummary => ({
    key_id: '0123456789ab',
    created_at: '2026-10-01T00:00:00.000Z',
    expires_at: null,
    revoked_at: null,
    last_used_at: null,
    ...over,
  });

  test('revoked wins over expired, expired over active', () => {
    assert.equal(keyStatus(key({}), NOW), 'active');
    assert.equal(keyStatus(key({ expires_at: '2026-10-27T00:00:00.000Z' }), NOW), 'expired');
    assert.equal(keyStatus(key({ expires_at: '2026-12-01T00:00:00.000Z' }), NOW), 'active');
    assert.equal(keyStatus(key({ revoked_at: '2026-10-02T00:00:00.000Z', expires_at: '2026-10-27T00:00:00.000Z' }), NOW), 'revoked');
  });
});

describe('roles and jobs', () => {
  test('only the exact role "admin" is an admin', () => {
    assert.equal(isAdminRole('admin'), true);
    for (const r of ['auditor', 'Admin', 'admin ', 'administrator', '', null, undefined]) assert.equal(isAdminRole(r), false, String(r));
  });

  test('only queued and running jobs are polled', () => {
    assert.equal(isJobActive('queued'), true);
    assert.equal(isJobActive('running'), true);
    for (const s of ['succeeded', 'failed', 'cancelled', '', null]) assert.equal(isJobActive(s), false, String(s));
  });
});

describe('chainCoverage', () => {
  const ok = { ok: true, verified_at: '2026-10-29T18:00:00Z', problem: null, head_seq: 74, seq: 75 };
  test('a check with nothing appended after it is current', () => {
    assert.deepEqual(chainCoverage({ head_seq: 75, last_verify: ok }), { kind: 'current', last: ok, checkedTo: 74 });
  });
  test('events after the check are not covered by it', () => {
    assert.deepEqual(chainCoverage({ head_seq: 96, last_verify: ok }), { kind: 'stale', last: ok, checkedTo: 74, since: 22 });
  });
  test('a failed check stays failed and no check reads never', () => {
    const bad = { ...ok, ok: false, problem: 'hash mismatch at #2' };
    assert.equal(chainCoverage({ head_seq: 75, last_verify: bad }).kind, 'failed');
    assert.equal(chainCoverage({ head_seq: 9, last_verify: null }).kind, 'never');
  });
  test('a record without its own seq never claims coverage', () => {
    const old = { ...ok, head_seq: null, seq: null };
    assert.deepEqual(chainCoverage({ head_seq: 75, last_verify: old }), { kind: 'stale', last: old, checkedTo: null, since: null });
  });
});
