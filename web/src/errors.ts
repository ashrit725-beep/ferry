/**
 * Turns API failures into text an operator can act on, and maps server-side
 * validation errors onto form fields. Server messages are shown as-is (the
 * backend guarantees they carry no secrets); nothing here adds request data.
 */

import { ApiError, BAD_RESPONSE } from './api.ts';
import { isObject } from './decode.ts';

export function retryMessage(retryAfterS: number | null): string {
  if (retryAfterS === null) return 'Too many failed attempts. Wait a few minutes and try again.';
  const minutes = Math.max(1, Math.ceil(retryAfterS / 60));
  return `Too many failed attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
}

function isOriginCheck(err: ApiError): boolean {
  return /csrf|origin/i.test(err.code) || /csrf|origin/i.test(err.message);
}

export function describeError(err: unknown, role?: string | null): string {
  if (err instanceof ApiError) {
    if (err.status === 403) {
      if (isOriginCheck(err)) {
        return `The server rejected the request's origin check (${err.code}). Reload the console and try again.`;
      }
      return role && role !== 'admin'
        ? `Requires the admin role. You are signed in with the ${role} role, which is read-only.`
        : 'Requires the admin role.';
    }
    if (err.status === 429) return retryMessage(err.retryAfterS);
    return err.message;
  }
  if (err instanceof Error && err.message) return err.message;
  return 'Unexpected error.';
}

/**
 * Login failures. The server deliberately does not say whether the username
 * or the password was wrong (spec section 6), and neither does the console.
 */
export function loginError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return 'Incorrect username or password.';
    if (err.status === 400 || err.status === 422) return 'Enter your username and password.';
  }
  return describeError(err);
}

/**
 * A 2xx response whose body did not decode: the change was applied, so the
 * caller should reload rather than report that it failed.
 */
export function appliedDespiteBody(err: unknown): boolean {
  return err instanceof ApiError && err.code === BAD_RESPONSE && err.status >= 200 && err.status < 300;
}

export interface FormErrors {
  fields: Record<string, string>;
  general: string[];
}

function fieldOf(path: unknown, fieldNames: readonly string[]): string | null {
  const parts: unknown[] = Array.isArray(path) ? path : typeof path === 'string' ? path.split(/[.[\]/]+/) : [];
  for (let i = parts.length - 1; i >= 0; i -= 1) {
    const part = parts[i];
    if (typeof part === 'string' && fieldNames.includes(part)) return part;
  }
  return null;
}

function messageOf(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const texts = value.filter((v): v is string => typeof v === 'string');
    return texts.length ? texts.join(' ') : null;
  }
  if (isObject(value)) {
    const m = value['message'] ?? value['msg'];
    return typeof m === 'string' ? m : null;
  }
  return null;
}

/**
 * Accepts the shapes a validation failure may take: `details.field` naming the
 * one offending field (the message is the error's own, as ferry.policy raises
 * it), `details.fields` maps, `details.errors` lists ({path|field|loc,
 * message|msg}), a plain field -> message map, or FastAPI's default `detail` list.
 */
export function formErrors(err: unknown, fieldNames: readonly string[], role?: string | null): FormErrors {
  const result: FormErrors = { fields: {}, general: [] };
  if (!(err instanceof ApiError) || ![400, 409, 422].includes(err.status)) {
    result.general.push(describeError(err, role));
    return result;
  }
  const leftovers: string[] = [];
  const add = (path: unknown, value: unknown): void => {
    const message = messageOf(value);
    if (!message) return;
    const field = fieldOf(path, fieldNames);
    if (field && !result.fields[field]) result.fields[field] = message;
    else if (!field) leftovers.push(typeof path === 'string' && path ? `${path}: ${message}` : message);
  };
  const addList = (list: unknown[]): void => {
    for (const item of list) {
      if (isObject(item)) add(item['path'] ?? item['field'] ?? item['loc'] ?? item['name'], item);
      else add(null, item);
    }
  };

  const d = err.details;
  if (Array.isArray(d)) {
    addList(d);
  } else if (isObject(d)) {
    const field = d['field'];
    const fields = d['fields'];
    const errors = d['errors'];
    if (typeof field === 'string') {
      if (fieldNames.includes(field)) add(field, err.message);
      else leftovers.push(err.message);
    }
    if (isObject(fields)) for (const [k, v] of Object.entries(fields)) add(k, v);
    if (Array.isArray(errors)) addList(errors);
    for (const [k, v] of Object.entries(d)) if (fieldNames.includes(k)) add(k, v);
  }

  result.general.push(...leftovers);
  if (Object.keys(result.fields).length === 0 && result.general.length === 0) result.general.push(err.message);
  return result;
}
