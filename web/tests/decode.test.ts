import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  DecodeError,
  array,
  bool,
  decode,
  either,
  extend,
  flag,
  idString,
  int,
  jsonObject,
  jsonText,
  map,
  maybe,
  nullable,
  num,
  object,
  oneOf,
  record,
  str,
  withDefault,
} from '../src/decode.ts';

function fails(fn: () => unknown, path: string, fragment: string): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof DecodeError, 'expected a DecodeError');
    assert.equal(err.path, path);
    assert.match(err.message, new RegExp(fragment));
    return true;
  });
}

describe('scalars', () => {
  test('str, num, int, bool accept their type and name the path otherwise', () => {
    assert.equal(str('a', 'p'), 'a');
    assert.equal(num(1.5, 'p'), 1.5);
    assert.equal(int(3, 'p'), 3);
    assert.equal(bool(false, 'p'), false);
    fails(() => str(1, 'r.name'), 'r.name', 'expected string, got number');
    fails(() => num('1', 'r.size'), 'r.size', 'expected number, got string');
    fails(() => int(1.5, 'r.count'), 'r.count', 'expected integer');
    fails(() => bool(0, 'r.ok'), 'r.ok', 'expected boolean, got number');
    fails(() => str(null, 'r.x'), 'r.x', 'got null');
    fails(() => str([], 'r.x'), 'r.x', 'got array');
  });

  test('num rejects non-finite values', () => {
    fails(() => num(Number.NaN, 'p'), 'p', 'expected number');
    fails(() => num(Number.POSITIVE_INFINITY, 'p'), 'p', 'expected number');
  });

  test('flag accepts SQLite 0/1 and booleans only', () => {
    assert.equal(flag(1, 'p'), true);
    assert.equal(flag(0, 'p'), false);
    assert.equal(flag(true, 'p'), true);
    fails(() => flag(2, 'p'), 'p', 'expected boolean');
    fails(() => flag('1', 'p'), 'p', 'expected boolean');
  });

  test('idString accepts numbers and strings', () => {
    assert.equal(idString(7, 'p'), '7');
    assert.equal(idString('job-1', 'p'), 'job-1');
    fails(() => idString(null, 'p'), 'p', 'expected string');
  });

  test('oneOf restricts the value set', () => {
    const d = oneOf(['up', 'down'] as const);
    assert.equal(d('up', 'p'), 'up');
    fails(() => d('sideways', 'p'), 'p', 'expected one of up, down');
  });
});

describe('optional values', () => {
  test('maybe turns missing and null into null', () => {
    assert.equal(maybe(str)(undefined, 'p'), null);
    assert.equal(maybe(str)(null, 'p'), null);
    assert.equal(maybe(str)('x', 'p'), 'x');
    fails(() => maybe(str)(3, 'p'), 'p', 'expected string');
  });

  test('nullable accepts null but still requires the key', () => {
    assert.equal(nullable(str)(null, 'p'), null);
    fails(() => nullable(str)(undefined, 'p'), 'p', 'got undefined');
  });

  test('withDefault fills missing and null', () => {
    assert.deepEqual(withDefault(array(str), [])(undefined, 'p'), []);
    assert.equal(withDefault(int, 0)(null, 'p'), 0);
    assert.equal(withDefault(int, 0)(4, 'p'), 4);
  });
});

describe('structures', () => {
  test('array reports the index of a bad element', () => {
    fails(() => array(str)(['a', 2], 'response.items'), 'response.items[1]', 'expected string');
    fails(() => array(str)({}, 'response.items'), 'response.items', 'expected array, got object');
  });

  test('object ignores unknown fields and requires declared ones', () => {
    const d = object({ id: int, name: str });
    assert.deepEqual(d({ id: 1, name: 'a', extra: true }, 'r'), { id: 1, name: 'a' });
    fails(() => d({ id: 1 }, 'r'), 'r.name', 'got undefined');
    fails(() => d([], 'r'), 'r', 'expected object, got array');
  });

  test('object reads own properties only, never inherited ones', () => {
    fails(() => object({ toString: str })({}, 'r'), 'r.toString', 'got undefined');
  });

  test('a "__proto__" key from the server stays data and never becomes a prototype', () => {
    const payload = JSON.parse('{"__proto__": {"polluted": "yes"}, "ok": {}}') as unknown;
    const out = record(jsonObject)(payload, 'r');
    assert.equal(Object.getPrototypeOf(out), Object.prototype);
    assert.equal((out as Record<string, unknown>)['polluted'], undefined);
    assert.ok(Object.prototype.hasOwnProperty.call(out, '__proto__'));
    assert.deepEqual(Object.keys(out), ['__proto__', 'ok']);
    assert.equal(({} as Record<string, unknown>)['polluted'], undefined);

    const shaped = object({ ['__proto__']: jsonObject })(payload, 'r');
    assert.equal(Object.getPrototypeOf(shaped), Object.prototype);
    assert.ok(Object.prototype.hasOwnProperty.call(shaped, '__proto__'));
  });

  test('extend merges a base decoder with extra fields', () => {
    const base = object({ id: int });
    const d = extend(base, { report: str });
    assert.deepEqual(d({ id: 2, report: 'r' }, 'x'), { id: 2, report: 'r' });
    fails(() => d({ id: 2 }, 'x'), 'x.report', 'got undefined');
  });

  test('either tries alternatives and reports the first failure', () => {
    const d = either(str, map(object({ state: str }), (o) => o.state));
    assert.equal(d('verified', 'p'), 'verified');
    assert.equal(d({ state: 'mismatch' }, 'p'), 'mismatch');
    fails(() => d(5, 'p'), 'p', 'expected string');
  });

  test('jsonText accepts stored JSON text or the parsed value', () => {
    const d = jsonText(object({ state: str }));
    assert.deepEqual(d('{"state":"up"}', 'p'), { state: 'up' });
    assert.deepEqual(d({ state: 'up' }, 'p'), { state: 'up' });
    fails(() => d('{not json', 'p'), 'p', 'JSON text that parses');
  });

  test('record decodes every value', () => {
    assert.deepEqual(record(int)({ a: 1, b: 2 }, 'p'), { a: 1, b: 2 });
    fails(() => record(int)({ a: 'x' }, 'p'), 'p.a', 'expected number');
  });

  test('jsonObject rejects arrays and null', () => {
    assert.deepEqual(jsonObject({ a: 1 }, 'p'), { a: 1 });
    fails(() => jsonObject(null, 'p'), 'p', 'got null');
    fails(() => jsonObject([1], 'p'), 'p', 'got array');
  });

  test('decode uses "response" as the root path', () => {
    fails(() => decode(object({ a: str }), {}), 'response.a', 'got undefined');
  });
});
