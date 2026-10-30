import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  DASH,
  exactUtc,
  formatBytes,
  formatInt,
  formatMs,
  formatPercent,
  isPast,
  plural,
  relativeTime,
  rfc3339ToUtcInput,
  shortDigest,
  shortKeyId,
  utcInputToRfc3339,
} from '../src/format.ts';

const NOW = Date.parse('2026-10-28T12:00:00.000Z');
const ago = (seconds: number): string => new Date(NOW - seconds * 1000).toISOString();

describe('numbers', () => {
  test('formatInt groups thousands and shows a dash for missing values', () => {
    assert.equal(formatInt(1234567), '1,234,567');
    assert.equal(formatInt(null), DASH);
    assert.equal(formatInt(Number.NaN), DASH);
  });

  test('formatBytes uses binary units like the CLI', () => {
    assert.equal(formatBytes(0), '0 B');
    assert.equal(formatBytes(1023), '1023 B');
    assert.equal(formatBytes(1024), '1.0 KiB');
    assert.equal(formatBytes(491_400_032), '469 MiB');
    assert.equal(formatBytes(200 * 1024 ** 3), '200 GiB');
    assert.equal(formatBytes(-1), DASH);
    assert.equal(formatBytes(undefined), DASH);
  });

  test('formatPercent never divides by zero and marks tiny shares', () => {
    assert.equal(formatPercent(1, 3), '33%');
    assert.equal(formatPercent(5, 1000), '0.5%');
    assert.equal(formatPercent(13, 260), '5%');
    assert.equal(formatPercent(1, 8), '13%');
    assert.equal(formatPercent(1, 40), '2.5%');
    assert.equal(formatPercent(1, 5000), '<0.1%');
    assert.equal(formatPercent(0, 10), '0%');
    assert.equal(formatPercent(10, 10), '100%');
    assert.equal(formatPercent(0, 0), DASH);
  });

  test('formatMs', () => {
    assert.equal(formatMs(12.4), '12 ms');
    assert.equal(formatMs(1500), '1.50 s');
    assert.equal(formatMs(15_000), '15.0 s');
    assert.equal(formatMs(null), DASH);
  });

  test('plural', () => {
    assert.equal(plural(1, 'event'), '1 event');
    assert.equal(plural(2, 'event'), '2 events');
    assert.equal(plural(1200, 'key'), '1,200 keys');
    assert.equal(plural(3, 'policy', 'policies'), '3 policies');
  });
});

describe('time', () => {
  test('relativeTime in the past and future', () => {
    assert.equal(relativeTime(ago(3), NOW), 'just now');
    assert.equal(relativeTime(ago(30), NOW), '30 s ago');
    assert.equal(relativeTime(ago(5 * 60), NOW), '5 min ago');
    assert.equal(relativeTime(ago(3 * 3600), NOW), '3 h ago');
    assert.equal(relativeTime(ago(2 * 86_400), NOW), '2 d ago');
    assert.equal(relativeTime(ago(-180), NOW), 'in 3 min');
    assert.equal(relativeTime(ago(40 * 86_400), NOW), '2026-09-18');
  });

  test('unparseable timestamps are shown as given', () => {
    assert.equal(relativeTime('yesterday', NOW), 'yesterday');
    assert.equal(exactUtc('yesterday'), 'yesterday');
    assert.equal(relativeTime(null, NOW), DASH);
  });

  test('exactUtc is unambiguous', () => {
    assert.equal(exactUtc('2026-10-28T02:00:00.000Z'), '2026-10-28 02:00:00.000 UTC');
    assert.equal(exactUtc('2026-10-28T04:00:00+02:00'), '2026-10-28 02:00:00.000 UTC');
  });

  test('isPast', () => {
    assert.equal(isPast(ago(1), NOW), true);
    assert.equal(isPast(ago(-1), NOW), false);
    assert.equal(isPast('garbage', NOW), false);
  });

  test('UTC datetime-local conversion round-trips', () => {
    assert.equal(utcInputToRfc3339('2026-10-28T02:00'), '2026-10-28T02:00:00.000Z');
    assert.equal(utcInputToRfc3339('2026-10-28T02:00:30'), '2026-10-28T02:00:30.000Z');
    assert.equal(utcInputToRfc3339(''), '');
    assert.equal(utcInputToRfc3339('not a date'), '');
    assert.equal(rfc3339ToUtcInput('2026-10-28T02:00:00.000Z'), '2026-10-28T02:00');
    assert.equal(rfc3339ToUtcInput('nope'), '');
  });
});

describe('identifiers', () => {
  const hex = '74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db';

  test('shortDigest keeps the algorithm prefix and both ends', () => {
    assert.equal(shortDigest(`sha256:${hex}`), 'sha256:74a4da8c9fdb…d7a9db');
    assert.equal(shortDigest(hex, 8, 4), '74a4da8c…a9db');
    assert.equal(shortDigest('abc'), 'abc');
  });

  test('shortKeyId shows the first 16 hex digits like the CLI', () => {
    assert.equal(shortKeyId(hex), '74a4da8c9fdbcd15…');
    assert.equal(shortKeyId('short'), 'short');
  });
});
