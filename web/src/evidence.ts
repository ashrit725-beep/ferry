/**
 * Readers for evidence sections (spec section 10). The spec names each
 * section's fields but not every key spelling, so values are read by trying
 * the documented names in order and anything unrecognised still renders
 * generically instead of being dropped.
 */

import { isObject, type JsonObject } from './decode.ts';
import { formatCompact, formatInt } from './format.ts';

export function pick(obj: JsonObject, ...keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key) && obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return undefined;
}

export function textOf(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  return null;
}

export function numberOf(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function listOf(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function stringsOf(value: unknown): string[] {
  return listOf(value).filter((v): v is string => typeof v === 'string');
}

export function objectsOf(value: unknown): JsonObject[] {
  return listOf(value).filter(isObject);
}

/** Provenance may be a bare state or {state, detail, served_digest}. */
export function provenanceOf(value: unknown): { state: string | null; detail: string | null } {
  if (typeof value === 'string') return { state: value, detail: null };
  if (isObject(value)) return { state: textOf(value['state']), detail: textOf(value['detail']) };
  return { state: null, detail: null };
}

/** Column keys for a generic table: keys in order of first appearance, capped. */
export function columnsOf(rows: readonly JsonObject[], max = 8): string[] {
  const seen: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!seen.includes(key)) seen.push(key);
      if (seen.length >= max) return seen;
    }
  }
  return seen;
}

export function looksLikeDigest(value: string): boolean {
  return /^(sha256:)?[0-9a-f]{40,}$/i.test(value);
}

/** Config values whose key says they are byte counts are also shown in binary units. */
export function isByteKey(key: string): boolean {
  return /(^|_)bytes$/.test(key);
}

/**
 * Short facts from format metadata recorded at import ({"gguf": {...}} or
 * {"safetensors": {...}}, spec section 4), e.g. "qwen2", "494M parameters".
 */
export function modelFacts(metadata: JsonObject): string[] {
  const inner = [metadata['gguf'], metadata['safetensors']].find(isObject) ?? metadata;
  const facts: string[] = [];
  const architecture = textOf(inner['architecture']);
  if (architecture) facts.push(architecture);
  const params = numberOf(inner['parameter_count']);
  if (params !== null) facts.push(`${formatCompact(params)} parameters`);
  const fileType = textOf(inner['file_type']);
  if (fileType) facts.push(fileType);
  const context = numberOf(inner['context_length']);
  if (context !== null) facts.push(`context ${formatInt(context)}`);
  const dtypes = stringsOf(inner['dtypes']);
  if (dtypes.length) facts.push(dtypes.join(', '));
  return facts;
}
