/**
 * Generic rendering for JSON values whose shape the contract leaves open
 * (effective config, import policy, evidence rows). Values are shown as text;
 * strings that came from the server are never turned into links.
 */

import { isObject, type JsonObject } from '../../decode.ts';
import { columnsOf, isByteKey, looksLikeDigest } from '../../evidence.ts';
import { DASH, formatBytes, formatInt } from '../../format.ts';
import { Digest, PathText } from './digest.tsx';
import { JsonView } from './json-view.tsx';

const PATH_LIKE = /^(?:\/|~\/|\.{1,2}\/)\S*$/;
const ADDRESS_LIKE = /^(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\]|[a-z][a-z0-9+.-]*:\/\/\S+)(?::\d{1,5})?$/i;

export function Value({ value, name }: { value: unknown; name?: string }) {
  if (value === null || value === undefined) return <span className="text-text-3">{DASH}</span>;
  if (typeof value === 'boolean') return <span>{value ? 'yes' : 'no'}</span>;
  if (typeof value === 'number') {
    if (name && isByteKey(name) && Number.isFinite(value)) {
      return (
        <span className="tabular-nums">
          {formatInt(value)} <span className="whitespace-nowrap text-text-3">({formatBytes(value)})</span>
        </span>
      );
    }
    return <span className="tabular-nums">{String(value)}</span>;
  }
  if (typeof value === 'string') {
    if (value === '') return <span className="text-text-3">(empty)</span>;
    if (looksLikeDigest(value)) return <Digest value={value} />;
    // Paths and addresses are identifiers: mono, and paths break after "/" only.
    if (PATH_LIKE.test(value)) return <PathText value={value} className="text-xs" />;
    if (ADDRESS_LIKE.test(value)) return <code className="font-mono text-xs [overflow-wrap:anywhere]">{value}</code>;
    return <span className="[overflow-wrap:anywhere]">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-text-3">(none)</span>;
    if (value.every((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
      return (
        <span className="inline-flex flex-wrap gap-1">
          {value.map((v, i) => (
            <span key={i} className="rounded-sm border border-line-control/50 bg-raised px-1 font-mono text-2xs text-bone">
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

const TABLE = 'w-full border-collapse text-xs';
const TH = 'h-8 border-b border-hairline px-3 text-left text-xs font-medium text-text-2';
const TD = 'border-b border-hairline px-3 py-1 align-top text-bone last:border-0';

/** An object as a two-column key/value table; keys are shown as written (they are config names). */
export function ObjectTable({ value, caption }: { value: JsonObject; caption: string }) {
  const entries = Object.entries(value);
  if (entries.length === 0) return <p className="px-3 py-2 text-xs text-text-3">No entries.</p>;
  return (
    <div className="w-full overflow-auto">
      <table className={`${TABLE} table-fixed`}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col" className={`${TH} w-1/2 sm:w-64`}>
              Setting
            </th>
            <th scope="col" className={TH}>
              Value
            </th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([key, v]) => (
            <tr key={key} className="border-b border-hairline last:border-0">
              <th scope="row" className="px-3 py-1 text-left align-top font-normal [overflow-wrap:break-word]">
                <code className="text-xs text-text-2">
                  <SnakeKey value={key} />
                </code>
              </th>
              <td className="px-3 py-1 align-top text-bone [overflow-wrap:anywhere]">{isObject(v) ? <ObjectInline value={v} /> : <Value value={v} name={key} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** A config key that may wrap only after "_" ("session_idle_" / "minutes"), never inside a word. */
function SnakeKey({ value }: { value: string }) {
  const parts = value.split('_');
  return (
    <>
      {parts.map((part, i) => (
        <span key={i}>
          {part}
          {i < parts.length - 1 ? (
            <>
              _<wbr />
            </>
          ) : null}
        </span>
      ))}
    </>
  );
}

function ObjectInline({ value }: { value: JsonObject }) {
  return (
    <dl className="m-0 flex flex-wrap gap-x-3 gap-y-0.5">
      {Object.entries(value).map(([k, v]) => (
        <div key={k} className="flex items-baseline gap-1">
          <dt>
            <code className="text-xs text-text-3">{k}</code>
          </dt>
          <dd className="m-0">
            <Value value={v} name={k} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Rows of objects as a table with columns in order of first appearance. */
export function RowsTable({ rows, caption, max = 8 }: { rows: readonly JsonObject[]; caption: string; max?: number }) {
  if (rows.length === 0) return <p className="px-3 py-2 text-xs text-text-3">No entries.</p>;
  const columns = columnsOf(rows, max);
  return (
    <div className="w-full overflow-auto">
      <table className={TABLE}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c} scope="col" className={TH}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-hairline last:border-0">
              {columns.map((c) => (
                <td key={c} className={TD}>
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
