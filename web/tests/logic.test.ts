import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { TRAFFIC_OUTCOMES, type Job } from '../src/api.ts';
import { columnsOf, isByteKey, looksLikeDigest, modelFacts, pick, provenanceOf, stringsOf, textOf } from '../src/evidence.ts';
import { APP_NAME, EMPTY_POLICY, MODEL_NAME, joinBaseUrl, optionalNumber, optionalText, splitBaseUrl } from '../src/forms.ts';
import { displayState, isTrackedJobActive, jobPercent, jobStatusText, type TrackedJob } from '../src/jobstate.ts';
import { canonicalText, jsonTokens, lineColumn, offsetOf, parseJson, prettyJson, sameDocument } from '../src/json.ts';
import { OUTCOME_TEXT, environmentSegments, trafficSegments } from '../src/metrics.ts';

describe('json', () => {
  const value = { id: 'rule-1', note: 'has 42 and true inside', quote: 'say "hi"', n: -1.5e3, ok: true, none: null, list: [1, 'two'] };

  test('tokens reassemble exactly into the pretty-printed text', () => {
    const tokens = jsonTokens(value);
    assert.equal(tokens.map((t) => t.text).join(''), JSON.stringify(value, null, 2));
  });

  test('keys, strings, numbers and literals are told apart; strings stay whole', () => {
    const tokens = jsonTokens(value).filter((t) => t.kind !== 'punct');
    const kinds = Object.fromEntries(tokens.map((t) => [t.text, t.kind]));
    assert.equal(kinds['"id"'], 'key');
    assert.equal(kinds['"rule-1"'], 'string');
    assert.equal(kinds['"has 42 and true inside"'], 'string');
    assert.equal(kinds['"say \\"hi\\""'], 'string');
    assert.equal(kinds['-1500'], 'number');
    assert.equal(kinds['true'], 'literal');
    assert.equal(kinds['null'], 'literal');
    assert.ok(!tokens.some((t) => t.text === '42'), 'digits inside a string are not a number token');
  });

  test('prettyJson of undefined is empty', () => {
    assert.equal(prettyJson(undefined), '');
    assert.deepEqual(jsonTokens(undefined), []);
  });

  test('parseJson reports where the document is broken', () => {
    const text = '{\n  "schema": "x",\n  "rules": [\n    { "id": "a" }\n    { "id": "b" }\n  ]\n}';
    const r = parseJson(text);
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.line, 5);
      assert.ok(r.column !== null && r.column >= 1);
      assert.doesNotMatch(r.message, /position \d+/);
    }
    assert.deepEqual(parseJson('{"a": 1}'), { ok: true, value: { a: 1 } });
    assert.equal(parseJson('   ').ok, false);
  });

  test('lineColumn and offsetOf are inverses', () => {
    const text = 'ab\ncde\nf';
    for (let offset = 0; offset <= text.length; offset += 1) {
      const { line, column } = lineColumn(text, offset);
      assert.equal(offsetOf(text, line, column), offset);
    }
    assert.equal(offsetOf(text, 99, 1), text.length);
  });

  test('sameDocument ignores layout and key order but not values', () => {
    assert.equal(sameDocument('{"a":1,"b":[1,2]}', '{\n  "b": [1, 2],\n  "a": 1\n}'), true);
    assert.equal(sameDocument('{"a":1}', '{"a":2}'), false);
    assert.equal(sameDocument('{"a":[1,2]}', '{"a":[2,1]}'), false);
    assert.equal(sameDocument('{broken', '{broken'), true);
    assert.equal(sameDocument('{broken', '{broken2'), false);
    assert.equal(sameDocument('{"__proto__": 1}', '{"__proto__": 2}'), false);
    assert.equal(canonicalText({ b: 1, a: { d: 1, c: 2 } }), '{"a":{"c":2,"d":1},"b":1}');
  });
});

describe('metrics', () => {
  const traffic = { total: 10, success: 6, denied: 2, error: 1, unavailable: 0, rejected: 1, unauthenticated: 0, p50_ms: 1, p95_ms: 2 };

  test('segments cover every outcome, sum to one and stack in order', () => {
    const segs = trafficSegments(traffic);
    assert.deepEqual(
      segs.map((s) => s.key),
      [...TRAFFIC_OUTCOMES],
    );
    assert.ok(Math.abs(segs.reduce((n, s) => n + s.share, 0) - 1) < 1e-9);
    assert.equal(segs[0]?.offset, 0);
    assert.equal(segs[1]?.offset, 0.6);
    assert.equal(segs[2]?.offset, 0.8);
  });

  test('no traffic, negative or non-finite counts give zero shares', () => {
    const empty = trafficSegments({ ...traffic, total: 0, success: 0, denied: 0, error: 0, rejected: 0 });
    assert.ok(empty.every((s) => s.share === 0));
    const odd = trafficSegments({ ...traffic, success: -5, denied: Number.NaN, error: 0, rejected: 0 });
    assert.ok(odd.every((s) => s.share === 0 && s.count === 0));
  });

  test('environments', () => {
    const segs = environmentSegments({ test: 1, pilot: 3, production: 0 });
    assert.deepEqual(
      segs.map((s) => [s.key, s.share]),
      [
        ['test', 0.25],
        ['pilot', 0.75],
        ['production', 0],
      ],
    );
  });

  test('every outcome has a label and a hint', () => {
    for (const o of TRAFFIC_OUTCOMES) {
      assert.ok(OUTCOME_TEXT[o].label);
      assert.ok(OUTCOME_TEXT[o].hint);
    }
  });
});

describe('forms', () => {
  test('a pasted base URL is split into scheme and address', () => {
    assert.deepEqual(splitBaseUrl('http://10.0.0.5:8080'), { scheme: 'http', address: '10.0.0.5:8080' });
    assert.deepEqual(splitBaseUrl(' HTTPS://gpu-1.internal '), { scheme: 'https', address: 'gpu-1.internal' });
    assert.deepEqual(splitBaseUrl('127.0.0.1:11434'), { scheme: null, address: '127.0.0.1:11434' });
    assert.deepEqual(splitBaseUrl('ftp://x'), { scheme: null, address: 'ftp://x' });
  });

  test('joinBaseUrl adds the scheme, and leaves an explicit one for the server to judge', () => {
    assert.equal(joinBaseUrl('http', ' 127.0.0.1:8080 '), 'http://127.0.0.1:8080');
    assert.equal(joinBaseUrl('https', 'gpu-1.internal'), 'https://gpu-1.internal');
    assert.equal(joinBaseUrl('http', 'ftp://x'), 'ftp://x');
  });

  test('optionalNumber', () => {
    assert.deepEqual(optionalNumber(''), { ok: true, value: undefined });
    assert.deepEqual(optionalNumber(' 12 '), { ok: true, value: 12 });
    assert.deepEqual(optionalNumber('2.5'), { ok: true, value: 2.5 });
    assert.equal(optionalNumber('2.5', { integer: true }).ok, false);
    assert.equal(optionalNumber('abc').ok, false);
    assert.equal(optionalNumber('0', { min: 1 }).ok, false);
    assert.equal(optionalNumber('Infinity').ok, false);
  });

  test('optionalText', () => {
    assert.equal(optionalText('  '), undefined);
    assert.equal(optionalText(' x '), 'x');
  });

  test('name grammars match the server rules', () => {
    for (const ok of ['report-assistant', 'a', 'app_1']) assert.ok(APP_NAME.test(ok), ok);
    for (const bad of ['Report', '-x', '', 'a'.repeat(65), 'app:x', 'a b']) assert.ok(!APP_NAME.test(bad), bad);
    for (const ok of ['qwen2.5-0.5b-instruct', 'Llama:3', 'm']) assert.ok(MODEL_NAME.test(ok), ok);
    for (const bad of ['qwen-*', '*', '.x', 'a b', '']) assert.ok(!MODEL_NAME.test(bad), bad);
  });

  test('the starter policy is the documented empty policy', () => {
    assert.equal(EMPTY_POLICY.schema, 'ferry.dev/access-policy/v1');
    assert.deepEqual(EMPTY_POLICY.rules, []);
  });
});

describe('evidence readers', () => {
  test('pick tries names in order and skips null', () => {
    assert.equal(pick({ bundle_id: null, id: 'b' }, 'bundle_id', 'id'), 'b');
    assert.equal(pick({}, 'a'), undefined);
    assert.equal(pick({}, 'constructor'), undefined);
  });

  test('textOf and stringsOf', () => {
    assert.equal(textOf('x'), 'x');
    assert.equal(textOf(3), '3');
    assert.equal(textOf(true), 'yes');
    assert.equal(textOf({}), null);
    assert.deepEqual(stringsOf(['a', 1, 'b']), ['a', 'b']);
    assert.deepEqual(stringsOf('a'), []);
  });

  test('provenance as a state or an object', () => {
    assert.deepEqual(provenanceOf('verified'), { state: 'verified', detail: null });
    assert.deepEqual(provenanceOf({ state: 'mismatch', detail: 'serving another file' }), { state: 'mismatch', detail: 'serving another file' });
    assert.deepEqual(provenanceOf(null), { state: null, detail: null });
  });

  test('columnsOf keeps first-appearance order and caps', () => {
    assert.deepEqual(columnsOf([{ a: 1, b: 2 }, { c: 3, a: 4 }]), ['a', 'b', 'c']);
    assert.deepEqual(columnsOf([{ a: 1, b: 2, c: 3 }], 2), ['a', 'b']);
  });

  test('digest and byte-count detection', () => {
    assert.ok(looksLikeDigest(`sha256:${'a'.repeat(64)}`));
    assert.ok(!looksLikeDigest('qwen2.5'));
    assert.ok(isByteKey('max_bundle_bytes'));
    assert.ok(!isByteKey('bytesize'));
  });

  test('modelFacts summarises GGUF and safetensors metadata', () => {
    const gguf = { gguf: { version: 3, architecture: 'qwen2', file_type: 'MOSTLY_Q4_K_M', context_length: 32768, parameter_count: 494032768 } };
    assert.deepEqual(modelFacts(gguf), ['qwen2', '494M parameters', 'MOSTLY_Q4_K_M', 'context 32,768']);
    assert.deepEqual(modelFacts({ safetensors: { parameter_count: 1_500_000_000, dtypes: ['BF16'] } }), ['1.5B parameters', 'BF16']);
    assert.deepEqual(modelFacts({}), []);
  });
});

describe('job state', () => {
  const job = (over: Partial<Job>): Job => ({
    job_id: 'j1',
    kind: 'import',
    source_name: 'b.ferry.tar',
    state: 'running',
    progress: { bytes_done: 0, bytes_total: null },
    started_at: null,
    finished_at: null,
    result: null,
    error: null,
    ...over,
  });
  const tracked = (over: Partial<TrackedJob>): TrackedJob => ({
    jobId: 'j1',
    kind: 'import',
    sourceName: 'b.ferry.tar',
    job: null,
    problem: null,
    stopped: false,
    ...over,
  });

  test('jobPercent is bounded and null without a total', () => {
    assert.equal(jobPercent(50, 200), 25);
    assert.equal(jobPercent(500, 200), 100);
    assert.equal(jobPercent(5, null), null);
    assert.equal(jobPercent(5, 0), null);
  });

  test('status text announces progress in 10 % steps', () => {
    assert.equal(jobStatusText(tracked({})), 'Import of b.ferry.tar: queued.');
    const running = tracked({ job: job({ progress: { bytes_done: 47, bytes_total: 100 } }) });
    assert.equal(jobStatusText(running), 'Import of b.ferry.tar: running, 40%.');
    assert.equal(jobStatusText(tracked({ job: job({}) })), 'Import of b.ferry.tar: running.');
  });

  test('final states include the verdict', () => {
    const done = job({ state: 'succeeded', result: { verdict: 'accepted', bundle_id: null, report: null, already_imported: true } });
    assert.equal(jobStatusText(tracked({ job: done })), 'Import of b.ferry.tar: finished, accepted, already imported.');
    assert.equal(jobStatusText(tracked({ kind: 'verify', job: job({ state: 'failed' }) })), 'Verification of b.ferry.tar: failed.');
  });

  test('a job the console stopped following is shown as unknown, not running', () => {
    const lost = tracked({ job: job({}), stopped: true });
    assert.equal(displayState(lost), 'unknown');
    assert.equal(isTrackedJobActive(lost), false);
    assert.equal(jobStatusText(lost), 'Import of b.ferry.tar: status unknown.');
    assert.equal(isTrackedJobActive(tracked({ job: job({}) })), true);
    assert.equal(isTrackedJobActive(tracked({ job: job({ state: 'succeeded' }) })), false);
  });
});
