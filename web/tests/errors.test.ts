import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { ApiError, BAD_RESPONSE, NETWORK_ERROR, errorFromResponse } from '../src/api.ts';
import { appliedDespiteBody, describeError, formErrors, loginError, retryMessage } from '../src/errors.ts';

const BACKEND_FIELDS = ['name', 'kind', 'base_url', 'auth_token_file', 'timeout_s', 'max_concurrency'] as const;

describe('describeError', () => {
  test('403 says the admin role is required, and which role the user has', () => {
    const err = errorFromResponse(403, { error: { code: 'forbidden', message: 'admin role required' } });
    assert.equal(describeError(err, 'auditor'), 'Requires the admin role. You are signed in with the auditor role, which is read-only.');
    assert.equal(describeError(err, 'admin'), 'Requires the admin role.');
    assert.equal(describeError(err), 'Requires the admin role.');
  });

  test('a CSRF or origin rejection is not mistaken for a role problem', () => {
    const csrf = errorFromResponse(403, { error: { code: 'csrf_failed', message: 'missing X-Ferry-CSRF header' } });
    assert.match(describeError(csrf, 'admin'), /origin check \(csrf_failed\)/);
    const origin = errorFromResponse(403, { detail: 'Origin does not match' });
    assert.match(describeError(origin, 'auditor'), /origin check/);
  });

  test('429 explains when to retry', () => {
    assert.equal(describeError(errorFromResponse(429, {}, '61')), 'Too many failed attempts. Try again in 2 minutes.');
  });

  test('other errors pass the server message through; unknown values get a generic one', () => {
    assert.equal(describeError(errorFromResponse(409, { error: { code: 'conflict', message: 'name taken' } })), 'name taken');
    assert.equal(describeError(new Error('boom')), 'boom');
    assert.equal(describeError('weird'), 'Unexpected error.');
  });
});

describe('retryMessage', () => {
  test('rounds up to whole minutes', () => {
    assert.equal(retryMessage(null), 'Too many failed attempts. Wait a few minutes and try again.');
    assert.equal(retryMessage(1), 'Too many failed attempts. Try again in 1 minute.');
    assert.equal(retryMessage(900), 'Too many failed attempts. Try again in 15 minutes.');
  });
});

describe('loginError', () => {
  test('never says whether the username or the password was wrong', () => {
    const err = errorFromResponse(401, { error: { code: 'bad_credentials', message: 'unknown user ops' } });
    assert.equal(loginError(err), 'Incorrect username or password.');
  });

  test('throttling, validation and network failures', () => {
    assert.equal(loginError(errorFromResponse(429, { retry_after_s: 900 })), 'Too many failed attempts. Try again in 15 minutes.');
    assert.equal(loginError(errorFromResponse(422, { detail: [] })), 'Enter your username and password.');
    const net = new ApiError({ status: 0, code: NETWORK_ERROR, message: 'Cannot reach the Ferry server.' });
    assert.equal(loginError(net), 'Cannot reach the Ferry server.');
  });
});

describe('formErrors', () => {
  test('details.field names the one offending field (ferry.policy style)', () => {
    const err = errorFromResponse(422, { error: { code: 'validation_failed', message: 'model must be a model name, not a pattern', details: { field: 'model' } } });
    const f = formErrors(err, ['app', 'model', 'action']);
    assert.deepEqual(f.fields, { model: 'model must be a model name, not a pattern' });
    assert.deepEqual(f.general, []);
  });

  test('details.field outside the form becomes a general error', () => {
    const err = errorFromResponse(422, { error: { code: 'validation_failed', message: 'nope', details: { field: 'other' } } });
    assert.deepEqual(formErrors(err, ['name']), { fields: {}, general: ['nope'] });
  });

  test('details.fields maps and details.errors lists', () => {
    const err = errorFromResponse(422, {
      error: {
        code: 'validation_failed',
        message: 'invalid backend',
        details: {
          fields: { base_url: 'must resolve to a private address' },
          errors: [{ path: 'timeout_s', message: 'must be positive' }, { message: 'something else' }],
        },
      },
    });
    const f = formErrors(err, BACKEND_FIELDS);
    assert.deepEqual(f.fields, { base_url: 'must resolve to a private address', timeout_s: 'must be positive' });
    assert.deepEqual(f.general, ['something else']);
  });

  test('FastAPI request validation (loc arrays) maps onto fields', () => {
    const err = errorFromResponse(422, { detail: [{ loc: ['body', 'name'], msg: 'Field required', type: 'missing' }, { loc: ['body', 'x'], msg: 'Extra' }] });
    const f = formErrors(err, BACKEND_FIELDS);
    assert.deepEqual(f.fields, { name: 'Field required' });
    assert.equal(f.general.length, 1);
  });

  test('a 409 without details falls back to its message', () => {
    const err = errorFromResponse(409, { error: { code: 'conflict', message: 'a backend named llama exists' } });
    assert.deepEqual(formErrors(err, BACKEND_FIELDS), { fields: {}, general: ['a backend named llama exists'] });
  });

  test('non-validation failures are general errors, with the role-aware 403 text', () => {
    const forbidden = errorFromResponse(403, { error: { code: 'forbidden', message: 'x' } });
    assert.deepEqual(formErrors(forbidden, BACKEND_FIELDS, 'auditor').general, [
      'Requires the admin role. You are signed in with the auditor role, which is read-only.',
    ]);
    assert.deepEqual(formErrors(errorFromResponse(500, 'boom'), BACKEND_FIELDS).general, ['boom']);
    assert.deepEqual(formErrors(new Error('offline'), BACKEND_FIELDS).general, ['offline']);
  });

  test('the first message for a field wins', () => {
    const err = errorFromResponse(422, { error: { code: 'v', message: 'm', details: { errors: [{ field: 'name', message: 'first' }, { field: 'name', message: 'second' }] } } });
    assert.deepEqual(formErrors(err, ['name']).fields, { name: 'first' });
  });
});

describe('appliedDespiteBody', () => {
  test('only a 2xx whose body failed to decode counts as applied', () => {
    assert.equal(appliedDespiteBody(new ApiError({ status: 201, code: BAD_RESPONSE, message: 'x' })), true);
    assert.equal(appliedDespiteBody(new ApiError({ status: 422, code: BAD_RESPONSE, message: 'x' })), false);
    assert.equal(appliedDespiteBody(new ApiError({ status: 0, code: NETWORK_ERROR, message: 'x' })), false);
    assert.equal(appliedDespiteBody(new Error('x')), false);
  });
});
