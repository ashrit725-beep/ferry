/**
 * Generic rendering for JSON values whose shape the contract leaves open
 * (effective config, import policy, evidence rows). Values are shown as text;
 * strings that came from the server are never turned into links.
 */

import { isObject, type JsonObject } from '../decode.ts';
import { columnsOf, isByteKey, looksLikeDigest } from '../evidence.ts';
import { DASH, formatBytes, formatInt } from '../format.ts';
import { Digest } from './Digest.tsx';
import { JsonView } from './JsonView.tsx';

export function Value({ value, name }: { value: unknown; name?: string }) {
  if (value === null || value === undefined) return <span className="subtle">{DASH}</span>;
  if (typeof value === 'boolean') return <span>{value ? 'yes' : 'no'}</span>;
  if (typeof value === 'number') {
    if (name && isByteKey(name) && Number.isFinite(value)) {
      return (
        <span className="num">
          {formatInt(value)} <span className="subtle">({formatBytes(value)})</span>
        </span>
      );
    }
    return <span className="num">{String(value)}</span>;
  }
  if (typeof value === 'string') {
    if (value === '') return <span className="subtle">(empty)</span>;
    if (looksLikeDigest(value)) return <Digest value={value} />;
    return <span className="break">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="subtle">(none)</span>;
    if (value.every((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      return (
        <span className="inline-list">
          {value.map((v, i) => (
            <span key={i} className="tag tag--mono">
              {String(v)}
            </span>
          ))}
        </span>
      );
    }
    return <JsonView value={value} short />;
  }
  if (isObject(value)) return <JsonView value={value} short />;
  return <span>{String(value)}</span>;
}

/** An object as a two-column key/value table; keys are shown as written (they are config names). */
export function ObjectTable({ value, caption }: { value: JsonObject; caption: string }) {
  const entries = Object.entries(value);
  if (entries.length === 0) return <p className="table-note">No entries.</p>;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Setting</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([key, v]) => (
            <tr key={key}>
              <th scope="row" className="row-head">
                <code>{key}</code>
              </th>
              <td>{isObject(v) ? <ObjectInline value={v} /> : <Value value={v} name={key} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ObjectInline({ value }: { value: JsonObject }) {
  return (
    <dl className="kv kv--inline">
      {Object.entries(value).map(([k, v]) => (
        <div key={k} className="kv__pair">
          <dt>
            <code>{k}</code>
          </dt>
          <dd>
            <Value value={v} name={k} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Rows of objects as a table with columns in order of first appearance. */
export function RowsTable({ rows, caption, max = 8 }: { rows: readonly JsonObject[]; caption: string; max?: number }) {
  if (rows.length === 0) return <p className="table-note">No entries.</p>;
  const columns = columnsOf(rows, max);
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} scope="col">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} className="top">
                  <Value value={row[c]} name={c} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
