/**
 * Hash routing, and the guarantee that links coming from data (attention
 * items, ?next= after login) can only ever lead to console pages.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import {
  actionGroups,
  auditFiltersFromParams,
  auditParams,
  navPageOf,
  parseHash,
  paths,
  safeInternalHref,
  safeNext,
  toHash,
} from '../src/router.ts';

const ID = `sha256:${'0123456789abcdef'.repeat(4)}`;

describe('parseHash', () => {
  test('pages', () => {
    assert.deepEqual(parseHash(''), { page: 'overview' });
    assert.deepEqual(parseHash('#/'), { page: 'overview' });
    assert.deepEqual(parseHash('#/overview'), { page: 'overview' });
    assert.deepEqual(parseHash('#/bundles'), { page: 'bundles' });
    assert.deepEqual(parseHash('#/models'), { page: 'models' });
    assert.deepEqual(parseHash('#/evidence'), { page: 'evidence' });
    assert.deepEqual(parseHash('#/login'), { page: 'login', next: null });
  });

  test('bundle detail accepts only a full sha256 bundle id; numbers are verification records', () => {
    assert.deepEqual(parseHash(`#/bundles/${ID}`), { page: 'bundle', bundleId: ID });
    assert.deepEqual(parseHash(`#/bundles/${ID.replace(':', '%3A')}`), { page: 'bundle', bundleId: ID });
    assert.deepEqual(parseHash('#/bundles/12'), { page: 'verification', id: 12 });
    assert.equal(parseHash('#/bundles/0').page, 'not_found');
    assert.equal(parseHash('#/bundles/012').page, 'not_found');
    assert.equal(parseHash('#/bundles/sha256:xyz').page, 'not_found');
    assert.equal(parseHash(`#/bundles/${ID.toUpperCase()}`).page, 'not_found');
    assert.equal(parseHash('#/bundles/1/2').page, 'not_found');
    assert.equal(parseHash('#/bundles/99999999999999999').page, 'not_found');
  });

  test('access tabs fall back to apps', () => {
    assert.deepEqual(parseHash('#/access?tab=policy'), { page: 'access', tab: 'policy' });
    assert.deepEqual(parseHash('#/access?tab=explain'), { page: 'access', tab: 'explain' });
    assert.deepEqual(parseHash('#/access?tab=../../x'), { page: 'access', tab: 'apps' });
  });

  test('audit keeps its query', () => {
    const r = parseHash('#/audit?outcome=denied&q=key');
    assert.equal(r.page, 'audit');
    if (r.page === 'audit') assert.equal(r.params.get('outcome'), 'denied');
  });

  test('unknown or malformed paths are not found', () => {
    assert.equal(parseHash('#/nope').page, 'not_found');
    assert.equal(parseHash('#/models/extra').page, 'not_found');
    assert.equal(parseHash('#/%E0%A4%A').page, 'not_found');
  });

  test('login next is validated', () => {
    assert.deepEqual(parseHash('#/login?next=%2Fmodels'), { page: 'login', next: '/models' });
    assert.deepEqual(parseHash('#/login?next=%2F%2Fevil.example'), { page: 'login', next: null });
  });
});

describe('safeNext', () => {
  test('accepts in-console paths only', () => {
    assert.equal(safeNext('/models'), '/models');
    assert.equal(safeNext(`/bundles/${ID}`), `/bundles/${ID}`);
    assert.equal(safeNext('/audit?outcome=denied'), '/audit?outcome=denied');
  });

  test('rejects other origins, schemes, the login page and junk', () => {
    for (const bad of ['//evil.example', 'javascript:alert(1)', 'models', '/login', '/nope', '/models\\x', ' /models', '/mo dels', '', null, undefined]) {
      assert.equal(safeNext(bad), null, String(bad));
    }
  });
});

describe('safeInternalHref', () => {
  test('normalises the accepted spellings to a fragment', () => {
    assert.equal(safeInternalHref('#/models'), '#/models');
    assert.equal(safeInternalHref('/#/models'), '#/models');
    assert.equal(safeInternalHref('/models'), '#/models');
    assert.equal(safeInternalHref(`#/bundles/${ID}`), `#/bundles/${ID}`);
    assert.equal(safeInternalHref('#/access?tab=policy'), '#/access?tab=policy');
  });

  test('never yields an off-console link', () => {
    for (const bad of [
      'https://evil.example/#/models',
      'http://127.0.0.1:8750/#/models',
      '//evil.example/#/models',
      'javascript:alert(1)',
      'JAVASCRIPT:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      '#/unknown',
      '#/login',
      '#/mod els',
      '#/models\u0000',
      '#\\/models',
      '/\\evil.example',
      '',
      null,
      undefined,
    ]) {
      assert.equal(safeInternalHref(bad), null, String(bad));
    }
  });
});

describe('paths', () => {
  test('builders', () => {
    assert.equal(paths.bundle(ID), `/bundles/${ID}`);
    assert.equal(paths.verification(7), '/bundles/7');
    assert.equal(paths.access(), '/access');
    assert.equal(paths.access('policy'), '/access?tab=policy');
    assert.equal(paths.audit(), '/audit');
    assert.equal(paths.audit({ outcome: 'denied', q: '  key  ', action: '' }), '/audit?outcome=denied&q=key');
    assert.equal(paths.login(null), '/login');
    assert.equal(paths.login('/models'), '/login?next=%2Fmodels');
    assert.equal(toHash('/models'), '#/models');
    assert.equal(toHash('models'), '#/models');
  });

  test('every built path parses back to its page', () => {
    assert.equal(parseHash(toHash(paths.bundle(ID))).page, 'bundle');
    assert.equal(parseHash(toHash(paths.verification(3))).page, 'verification');
    assert.equal(parseHash(toHash(paths.access('explain'))).page, 'access');
    assert.equal(parseHash(toHash(paths.audit({ correlation_id: 'req-1' }))).page, 'audit');
  });

  test('navPageOf maps detail pages to their sidebar entry', () => {
    assert.equal(navPageOf({ page: 'bundle', bundleId: ID }), 'bundles');
    assert.equal(navPageOf({ page: 'verification', id: 1 }), 'bundles');
    assert.equal(navPageOf({ page: 'access', tab: 'policy' }), 'access');
    assert.equal(navPageOf({ page: 'login', next: null }), null);
    assert.equal(navPageOf({ page: 'not_found', path: '/x' }), null);
  });
});

describe('audit filters in the URL', () => {
  test('only known filter keys are read, trimmed and capped', () => {
    const params = new URLSearchParams({ outcome: ' denied ', before_seq: '5', limit: '9999', evil: 'x', q: 'k'.repeat(600) });
    const f = auditFiltersFromParams(params);
    assert.deepEqual(Object.keys(f).sort(), ['outcome', 'q']);
    assert.equal(f.outcome, 'denied');
    assert.equal(f.q?.length, 512);
  });

  test('auditParams writes non-empty values in a fixed order', () => {
    assert.equal(auditParams({ q: 'x', action: 'bundle.*', outcome: '' }).toString(), 'action=bundle.*&q=x');
  });

  test('actionGroups offers prefix filters for the actions present', () => {
    assert.deepEqual(actionGroups(['bundle.import', 'bundle.verify', 'auth.login', 'gateway.chat.completions', 'odd']), [
      'auth.*',
      'bundle.*',
      'gateway.*',
    ]);
    assert.deepEqual(actionGroups([]), []);
  });
});
