/**
 * The API client against a stubbed fetch: transport rules (cookie, CSRF
 * header, no redirects, no cache), error handling, path encoding, and the
 * decoders against payloads shaped like spec section 9.
 */

import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';
import {
  ApiError,
  BAD_RESPONSE,
  NETWORK_ERROR,
  activationValidation,
  api,
  buildUrl,
  errorFromResponse,
  isAbortError,
  seg,
  setUnauthorizedHandler,
} from '../src/api.ts';

interface Call {
  url: string;
  init: RequestInit;
}

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>;

const original = globalThis.fetch;
let calls: Call[] = [];
let handler: Handler = () => json(200, {});

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

function headersOf(call: Call | undefined): Record<string, string> {
  assert.ok(call, 'expected a request');
  return { ...(call.init.headers as Record<string, string>) };
}

beforeEach(() => {
  calls = [];
  handler = () => json(200, {});
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });
    return handler(url, init ?? {});
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = original;
  setUnauthorizedHandler(null);
});

const USER = { user: { username: 'ops', role: 'admin' } };
const HEX = 'a'.repeat(64);

describe('transport', () => {
  test('GET carries the cookie, refuses redirects and caching, and has no CSRF header or body', async () => {
    handler = () => json(200, USER);
    await api.me();
    const call = calls[0];
    assert.ok(call);
    assert.equal(call.url, '/api/auth/me');
    assert.equal(call.init.method, 'GET');
    assert.equal(call.init.credentials, 'same-origin');
    assert.equal(call.init.redirect, 'error');
    assert.equal(call.init.cache, 'no-store');
    assert.equal(call.init.body, undefined);
    const h = headersOf(call);
    assert.equal(h['Accept'], 'application/json');
    assert.equal(h['X-Ferry-CSRF'], undefined);
    assert.equal(h['Content-Type'], undefined);
  });

  test('POST sends X-Ferry-CSRF: 1 and a JSON body', async () => {
    handler = () => json(200, USER);
    const user = await api.login('ops', 'correct horse battery');
    assert.deepEqual(user, { username: 'ops', role: 'admin' });
    const call = calls[0];
    assert.ok(call);
    assert.equal(call.init.method, 'POST');
    assert.equal(call.init.credentials, 'same-origin');
    const h = headersOf(call);
    assert.equal(h['X-Ferry-CSRF'], '1');
    assert.equal(h['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(String(call.init.body)), { username: 'ops', password: 'correct horse battery' });
  });

  test('POST without a payload still sends JSON ({}) and the CSRF header', async () => {
    handler = () =>
      json(200, { ok: true, events_checked: 3, head_seq: 3, head_hash: HEX, first_bad_seq: null, problem: null, verified_at: '2026-10-28T00:00:00.000Z' });
    await api.verifyAudit();
    const call = calls[0];
    assert.ok(call);
    assert.equal(call.init.body, '{}');
    assert.equal(headersOf(call)['X-Ferry-CSRF'], '1');
    assert.equal(headersOf(call)['Content-Type'], 'application/json');
  });

  test('PATCH sends the CSRF header and the patch', async () => {
    handler = () => json(200, ROUTE);
    await api.updateRoute(4, { enabled: false });
    const call = calls[0];
    assert.ok(call);
    assert.equal(call.url, '/api/routes/4');
    assert.equal(call.init.method, 'PATCH');
    assert.equal(headersOf(call)['X-Ferry-CSRF'], '1');
    assert.deepEqual(JSON.parse(String(call.init.body)), { enabled: false });
  });

  test('DELETE sends the CSRF header without a body and accepts 204', async () => {
    handler = () => new Response(null, { status: 204 });
    const result = await api.deleteRoute(9);
    assert.equal(result, undefined);
    const call = calls[0];
    assert.ok(call);
    assert.equal(call.init.method, 'DELETE');
    assert.equal(call.init.body, undefined);
    assert.equal(headersOf(call)['X-Ferry-CSRF'], '1');
    assert.equal(headersOf(call)['Content-Type'], undefined);
  });

  test('a network failure becomes status 0 with an actionable message', async () => {
    handler = () => {
      throw new TypeError('Failed to fetch');
    };
    await assert.rejects(api.overview(), (err: unknown) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.status, 0);
      assert.equal(err.code, NETWORK_ERROR);
      assert.match(err.message, /Cannot reach the Ferry server/);
      return true;
    });
  });

  test('an aborted request rejects with the AbortError itself, not an ApiError', async () => {
    handler = () => {
      throw new DOMException('The operation was aborted.', 'AbortError');
    };
    await assert.rejects(api.overview(new AbortController().signal), (err: unknown) => {
      assert.ok(!(err instanceof ApiError));
      assert.ok(isAbortError(err));
      return true;
    });
  });

  test('the abort signal is passed to fetch', async () => {
    handler = () => json(200, USER);
    const ctrl = new AbortController();
    await api.me(ctrl.signal);
    assert.equal(calls[0]?.init.signal, ctrl.signal);
  });
});

describe('401 and 403', () => {
  test('a 401 from a data call signs the console out', async () => {
    let signedOut = 0;
    setUnauthorizedHandler(() => {
      signedOut += 1;
    });
    handler = () => json(401, { error: { code: 'not_authenticated', message: 'Not signed in.' } });
    await assert.rejects(api.apps(), (err: unknown) => err instanceof ApiError && err.status === 401);
    assert.equal(signedOut, 1);
  });

  test('the session probe, login and logout handle 401 themselves', async () => {
    let signedOut = 0;
    setUnauthorizedHandler(() => {
      signedOut += 1;
    });
    handler = () => json(401, { error: { code: 'not_authenticated', message: 'Not signed in.' } });
    await assert.rejects(api.me());
    await assert.rejects(api.login('ops', 'wrong password'));
    await assert.rejects(api.logout());
    assert.equal(signedOut, 0);
  });

  test('a 403 keeps the server code and does not sign out', async () => {
    let signedOut = 0;
    setUnauthorizedHandler(() => {
      signedOut += 1;
    });
    handler = () => json(403, { error: { code: 'forbidden', message: 'admin role required' } });
    await assert.rejects(api.createApp({ name: 'x', environment: 'test' }), (err: unknown) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.status, 403);
      assert.equal(err.code, 'forbidden');
      return true;
    });
    assert.equal(signedOut, 0);
  });
});

describe('error bodies', () => {
  test('Ferry error shape: code, message and details', () => {
    const err = errorFromResponse(409, { error: { code: 'conflict', message: 'backend is used by 2 routes', details: { routes: 2 } } });
    assert.equal(err.code, 'conflict');
    assert.equal(err.message, 'backend is used by 2 routes');
    assert.deepEqual(err.details, { routes: 2 });
  });

  test('FastAPI default shapes', () => {
    const plain = errorFromResponse(404, { detail: 'Not Found' });
    assert.equal(plain.message, 'Not Found');
    const list = errorFromResponse(422, { detail: [{ loc: ['body', 'name'], msg: 'Field required', type: 'missing' }] });
    assert.equal(list.code, 'validation_failed');
    assert.deepEqual(list.details, { errors: [{ loc: ['body', 'name'], msg: 'Field required', type: 'missing' }] });
    assert.equal(list.message, 'The request did not pass validation.');
  });

  test('an HTML error page is never shown as the message', () => {
    const err = errorFromResponse(502, '<html><body>Bad Gateway</body></html>');
    assert.equal(err.message, 'The server failed (HTTP 502).');
    assert.equal(err.code, 'http_502');
  });

  test('short plain text is kept', () => {
    assert.equal(errorFromResponse(500, 'database is locked').message, 'database is locked');
  });

  test('retry hints from Retry-After, details.retry_after_s or the body', () => {
    assert.equal(errorFromResponse(429, {}, '120').retryAfterS, 120);
    assert.equal(errorFromResponse(429, { error: { code: 'rate_limited', message: 'x', details: { retry_after_s: 900 } } }, '5').retryAfterS, 900);
    assert.equal(errorFromResponse(429, { retry_after_s: 60 }).retryAfterS, 60);
    assert.equal(errorFromResponse(429, {}, 'soon').retryAfterS, null);
  });

  test('a 2xx body that does not match the contract is a bad_response naming the field', async () => {
    handler = () => json(200, { items: [{ id: 'one' }] });
    await assert.rejects(api.apps(), (err: unknown) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.code, BAD_RESPONSE);
      assert.equal(err.status, 200);
      assert.match(err.message, /GET \/api\/apps/);
      assert.match(err.message, /response\.items\[0\]\.id/);
      return true;
    });
  });

  test('the query string is not repeated in decode error messages', async () => {
    handler = () => json(200, { nope: true });
    await assert.rejects(api.audit({ q: 'needle' }), (err: unknown) => {
      assert.ok(err instanceof ApiError);
      assert.doesNotMatch(err.message, /needle/);
      return true;
    });
  });
});

describe('paths and queries', () => {
  test('path segments are encoded, so ids cannot change the route', async () => {
    assert.equal(seg('sha256:abc'), 'sha256%3Aabc');
    assert.equal(seg('../../etc/passwd'), '..%2F..%2Fetc%2Fpasswd');
    handler = () => json(404, { error: { code: 'not_found', message: 'no such job' } });
    await assert.rejects(api.job('../admin'));
    assert.equal(calls[0]?.url, '/api/jobs/..%2Fadmin');
  });

  test('bundle ids keep their colon encoded in API paths', async () => {
    handler = () => json(404, { error: { code: 'not_found', message: 'x' } });
    await assert.rejects(api.bundle(`sha256:${HEX}`));
    assert.equal(calls[0]?.url, `/api/bundles/sha256%3A${HEX}`);
  });

  test('buildUrl drops empty values and encodes the rest', () => {
    assert.equal(buildUrl('/api/audit', { q: 'a b&c', outcome: '', actor_id: undefined, before_seq: 10, limit: null }), '/api/audit?q=a+b%26c&before_seq=10');
    assert.equal(buildUrl('/api/audit', {}), '/api/audit');
  });

  test('verifications and audit queries', async () => {
    handler = () => json(200, { items: [], next_before_seq: null });
    await api.verifications(50);
    await api.audit({ action: 'bundle.*', before_seq: 120, limit: 100 });
    assert.equal(calls[0]?.url, '/api/verifications?limit=50');
    assert.equal(calls[1]?.url, '/api/audit?action=bundle.*&before_seq=120&limit=100');
  });

  test('issueKey sends expires_in_days only when given', async () => {
    handler = () => json(201, { key_id: '0123456789ab', api_key: 'fyk_0123456789ab_secret', expires_at: null });
    await api.issueKey(5, null);
    await api.issueKey(5, 30);
    assert.equal(calls[0]?.url, '/api/apps/5/keys');
    assert.equal(calls[0]?.init.body, '{}');
    assert.deepEqual(JSON.parse(String(calls[1]?.init.body)), { expires_in_days: 30 });
  });

  test('inbox jobs post the item name and return the job id', async () => {
    handler = () => json(202, { job_id: 'j-1' });
    assert.equal(await api.verifyInbox('qwen.ferry.tar'), 'j-1');
    assert.equal(await api.importInbox('qwen.ferry.tar'), 'j-1');
    assert.equal(calls[0]?.url, '/api/inbox/verify');
    assert.equal(calls[1]?.url, '/api/inbox/import');
    assert.deepEqual(JSON.parse(String(calls[1]?.init.body)), { name: 'qwen.ferry.tar' });
  });
});

const OVERVIEW = {
  version: '0.1.0',
  started_at: '2026-10-28T01:00:00.000Z',
  policy: { version: 3, sha256: HEX, activated_at: '2026-10-28T01:10:00.000Z', rule_count: 2 },
  counts: { apps: 2, active_keys: 3, backends: 1, routes: 1, bundles: 1, model_artifacts: 1, trusted_keys: 2 },
  backends: [{ id: 1, name: 'llama', kind: 'llamacpp', state: 'up', checked_at: '2026-10-28T01:59:00.000Z' }],
  routes: [{ model: 'qwen2.5-0.5b-instruct', backend: 'llama', provenance: 'verified', available: true, reason: null }],
  traffic_24h: { total: 10, success: 7, denied: 1, error: 1, unavailable: 0, rejected: 1, unauthenticated: 0, p50_ms: 120.5, p95_ms: 900 },
  traffic_by_environment_24h: { test: 2, pilot: 8, production: 0 },
  inbox_pending: 0,
  audit: { head_seq: 42, head_hash: HEX, last_verify: null },
  attention: [{ severity: 'warning', message: 'No checkpoint in 7 days', href: '#/audit' }],
};

const ROUTE = {
  id: 4,
  model: 'qwen2.5-0.5b-instruct',
  backend_id: 1,
  backend_name: 'llama',
  upstream_model: 'qwen2.5-0.5b-instruct',
  artifact_digest: HEX,
  require_verified: 1,
  enabled: 1,
  provenance: { state: 'verified', detail: 'model_path is in the store', served_digest: HEX },
  available: true,
  reason: null,
};

describe('contract decoding', () => {
  test('overview decodes; a missing count is an error', async () => {
    handler = () => json(200, OVERVIEW);
    const o = await api.overview();
    assert.equal(o.counts.apps, 2);
    assert.equal(o.routes[0]?.provenance, 'verified');
    assert.equal(o.traffic_24h.p50_ms, 120.5);
    const broken = { ...OVERVIEW, counts: { ...OVERVIEW.counts, apps: undefined } };
    handler = () => json(200, broken);
    await assert.rejects(api.overview(), (err: unknown) => err instanceof ApiError && /counts\.apps/.test(err.message));
  });

  test('overview route provenance may be the full object', async () => {
    handler = () => json(200, { ...OVERVIEW, routes: [{ ...OVERVIEW.routes[0], provenance: { state: 'mismatch' } }] });
    const o = await api.overview();
    assert.equal(o.routes[0]?.provenance, 'mismatch');
  });

  test('routes: SQLite flags become booleans; provenance may be a bare state', async () => {
    handler = () => json(200, { items: [ROUTE, { ...ROUTE, id: 5, provenance: 'not_pinned', artifact_digest: null, require_verified: 0 }] });
    const routes = await api.routes();
    assert.equal(routes[0]?.require_verified, true);
    assert.equal(routes[0]?.provenance.served_digest, HEX);
    assert.deepEqual(routes[1]?.provenance, { state: 'not_pinned', detail: null, served_digest: null });
    assert.equal(routes[1]?.require_verified, false);
  });

  test('backends: last_status stored as JSON text is parsed', async () => {
    const status = { state: 'up', checked_at: '2026-10-28T01:59:00.000Z', latency_ms: 4.2, http_status: 200, version: 'b4567', models: ['qwen'], served: [{ model_id: 'qwen', path: '/data/store/sha256/x', digest: HEX }], error: null };
    handler = () =>
      json(200, { items: [{ id: 1, name: 'llama', kind: 'llamacpp', base_url: 'h', has_token: 0, timeout_s: 120, max_concurrency: 4, enabled: 1, last_status: JSON.stringify(status), last_checked_at: null }] });
    const [b] = await api.backends();
    assert.ok(b);
    assert.equal(b.has_token, false);
    assert.equal(b.last_status?.state, 'up');
    assert.equal(b.last_status?.served[0]?.digest, HEX);
  });

  test('bundles: signers stored as JSON text are parsed', async () => {
    const signers = [{ key_id: HEX, name: 'build', roles: ['publisher'] }];
    handler = () =>
      json(200, { items: [{ bundle_id: `sha256:${HEX}`, name: 'qwen', version: '1.0.0', imported_at: 't', imported_by: 'admin:ops', source_name: 'q.ferry.tar', signers: JSON.stringify(signers), artifact_count: 2, total_bytes: 10 }] });
    const [b] = await api.bundles();
    assert.deepEqual(b?.signers, [{ key_id: HEX, name: 'build', roles: ['publisher'] }]);
  });

  test('job status: progress defaults, report as JSON text, unknown fields ignored', async () => {
    const report = { report_version: 1, verdict: 'rejected', checks: [{ id: 'signatures.valid', status: 'fail', message: 'x' }], errors: ['bad signature'] };
    handler = () =>
      json(200, { job_id: 'j1', kind: 'import', source_name: 'b.ferry.tar', state: 'succeeded', started_at: 't', finished_at: 't', result: { verdict: 'rejected', bundle_id: null, report: JSON.stringify(report) }, error: null, extra: 1 });
    const job = await api.job('j1');
    assert.deepEqual(job.progress, { bytes_done: 0, bytes_total: null });
    assert.equal(job.result?.already_imported, false);
    assert.equal(job.result?.report?.checks[0]?.status, 'fail');
    assert.deepEqual(job.result?.report?.signatures, []);
    assert.deepEqual(job.result?.report?.warnings, []);
  });

  test('policy validation paths may arrive as arrays', async () => {
    handler = () => json(200, { valid: false, errors: [{ path: ['rules', 0, 'id'], message: 'required' }, { path: 'schema', message: 'x' }], warnings: [] });
    const v = await api.validatePolicy({});
    assert.equal(v.errors[0]?.path, 'rules[0].id');
    assert.equal(v.errors[1]?.path, 'schema');
  });

  test('explain: trace and app status are read when present and default otherwise', async () => {
    handler = () =>
      json(200, {
        allowed: false,
        decisive_rule: 'no-experimental',
        matched_rules: [{ id: 'no-experimental', effect: 'deny' }],
        reason: "denied by rule 'no-experimental'",
        limits: { max_tokens: null, allow_stream: true },
        policy_version: 3,
        policy_sha256: HEX,
        principal: 'app:report-assistant',
        principal_status: 'active',
        policy_allowed: false,
        trace: [{ id: 'no-experimental', effect: 'deny', matched: true, principal_matched: true, action_matched: true, model_matched: true }],
      });
    const d = await api.explain({ app: 'report-assistant', action: 'chat.completions', model: 'experimental-x' });
    assert.equal(d.trace[0]?.matched, true);
    assert.equal(d.principal_status, 'active');
    handler = () => json(200, { allowed: true, decisive_rule: 'r', matched_rules: [], reason: 'ok', limits: null, policy_version: 1, policy_sha256: HEX, principal: 'app:a' });
    const bare = await api.explain({ app: 'a', action: 'chat.completions', model: 'm' });
    assert.deepEqual(bare.trace, []);
    assert.equal(bare.principal_status, null);
    assert.equal(bare.policy_allowed, null);
  });

  test('activation result: warnings default to an empty list', async () => {
    handler = () => json(201, { version: 4, sha256: HEX });
    assert.deepEqual(await api.activatePolicy({}, 'why'), { version: 4, sha256: HEX, warnings: [] });
  });

  test('evidence: sections the contract leaves open are kept as objects', async () => {
    handler = () =>
      json(200, {
        generated_at: 't',
        ferry_version: '0.1.0',
        host: { platform: 'Linux', python: '3.12' },
        trust_anchors: [{ key_id: HEX, name: 'k', roles: ['publisher'], status: 'active' }],
        network_inventory: [{ component: 'gateway', direction: 'inbound', destination: '127.0.0.1:8750', purpose: 'API', configurable: true, notes: '' }],
        dependencies: [{ name: 'fastapi', version: '0.115.0' }],
      });
    const e = await api.evidence();
    assert.equal(e.trust_anchors.length, 1);
    assert.deepEqual(e.bundles, []);
    assert.equal(e.audit, null);
    assert.equal(e.network_inventory[0]?.configurable, true);
  });
});

describe('activationValidation', () => {
  const validation = { valid: false, errors: [{ path: 'rules[1].effect', message: 'required' }], warnings: [] };

  test('reads the validation next to error (section 9 shape)', () => {
    const err = errorFromResponse(422, { error: { code: 'validation_failed', message: 'invalid' }, validation });
    assert.equal(activationValidation(err)?.errors[0]?.path, 'rules[1].effect');
  });

  test('reads the validation under error.details (ferry.policy ValidationFailed shape)', () => {
    const err = errorFromResponse(422, { error: { code: 'validation_failed', message: 'invalid', details: { validation } } });
    assert.equal(activationValidation(err)?.errors.length, 1);
  });

  test('returns null for other statuses or unusable bodies', () => {
    assert.equal(activationValidation(errorFromResponse(400, { validation })), null);
    assert.equal(activationValidation(errorFromResponse(422, { validation: 'nope' })), null);
    assert.equal(activationValidation(errorFromResponse(422, 'text')), null);
  });
});
