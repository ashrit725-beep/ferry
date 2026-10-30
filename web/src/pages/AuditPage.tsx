/**
 * Audit log: filterable, newest first, paged backwards with before_seq; an
 * event detail panel with its hash links; chain verification; export.
 */

import { useMemo, useState, type KeyboardEvent } from 'react';
import { AUDIT_EXPORT_URL, api, type AuditEvent, type AuditQuery, type ChainVerification } from '../api.ts';
import { describeError } from '../errors.ts';
import { formatInt, plural } from '../format.ts';
import { useResource } from '../hooks.ts';
import { auditFiltersFromParams, auditParams, navigate, paths } from '../router.ts';
import { useRole } from '../session.tsx';
import { Digest } from '../components/Digest.tsx';
import { IconDownload, IconShield } from '../components/Icons.tsx';
import { Callout, PageHeader, Panel, RefreshButton } from '../components/Panel.tsx';
import { Async, EmptyState } from '../components/States.tsx';
import { StatusBadge } from '../components/StatusBadge.tsx';
import { Time } from '../components/Time.tsx';
import { AuditFilters } from './audit/AuditFilters.tsx';
import { EventDetail } from './audit/EventDetail.tsx';

const PAGE_SIZE = 100;

interface Older {
  key: string;
  items: AuditEvent[];
  next: number | null;
}

export function AuditPage({ params }: { params: URLSearchParams }) {
  const role = useRole();
  const filters = useMemo(() => auditFiltersFromParams(params), [params]);
  const filterKey = auditParams(filters).toString();
  const facets = useResource((s) => api.auditFacets(s), []);
  const first = useResource((s) => api.audit({ ...filters, limit: PAGE_SIZE }, s), [filterKey]);
  const [older, setOlder] = useState<Older | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [olderError, setOlderError] = useState<unknown>(null);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const olderNow = older && older.key === filterKey && first.data ? older : null;
  const items = first.data ? [...first.data.items, ...(olderNow?.items ?? [])] : [];
  const cursor = olderNow ? olderNow.next : (first.data?.next_before_seq ?? null);
  const selected = selectedSeq !== null ? (items.find((e) => e.seq === selectedSeq) ?? null) : null;

  const apply = (next: AuditQuery): void => {
    setSelectedSeq(null);
    navigate(paths.audit(next));
  };

  const refresh = (): void => {
    setOlder(null);
    setOlderError(null);
    first.reload();
    facets.reload();
  };

  const loadOlder = async (): Promise<void> => {
    if (cursor === null || loadingOlder) return;
    const key = filterKey;
    setLoadingOlder(true);
    setOlderError(null);
    try {
      const page = await api.audit({ ...filters, before_seq: cursor, limit: PAGE_SIZE });
      setOlder((prev) => ({
        key,
        items: [...(prev && prev.key === key ? prev.items : []), ...page.items],
        next: page.next_before_seq,
      }));
    } catch (err) {
      setOlderError(err);
    } finally {
      setLoadingOlder(false);
    }
  };

  const verify = async (): Promise<void> => {
    if (verifying) return;
    setVerifying(true);
    setChainError(null);
    try {
      setChain(await api.verifyAudit());
    } catch (err) {
      setChain(null);
      setChainError(describeError(err, role));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Security-relevant events, each hashed together with the one before it. Prompts, completions and credentials are never recorded."
        actions={
          <>
            <button type="button" className="button" onClick={() => void verify()} aria-disabled={verifying || undefined}>
              <IconShield />
              {verifying ? 'Verifying…' : 'Verify chain'}
            </button>
            <a className="button" href={AUDIT_EXPORT_URL} download>
              <IconDownload />
              Export all (NDJSON)
            </a>
            <RefreshButton onClick={refresh} busy={first.refreshing} />
          </>
        }
      />
      <div className="stack">
        <div aria-live="polite">
          {chain ? <ChainResult chain={chain} onShow={setSelectedSeq} /> : null}
          {chainError ? (
            <Callout tone="bad" role="alert" title="The chain check did not run.">
              <p>{chainError}</p>
            </Callout>
          ) : null}
        </div>

        <Panel title="Filters">
          <AuditFilters filters={filters} facets={facets.data} onApply={apply} />
        </Panel>

        <div className={selectedSeq !== null ? 'grid grid--split' : undefined}>
          <Panel
            title="Events"
            description={first.data ? `${plural(items.length, 'event')} shown, newest first.` : null}
            flush
            footer={
              first.data && (cursor !== null || olderError) ? (
                <>
                  {cursor !== null ? (
                    <button type="button" className="button button--small" onClick={() => void loadOlder()} aria-disabled={loadingOlder || undefined}>
                      {loadingOlder ? 'Loading…' : 'Load older events'}
                    </button>
                  ) : null}
                  {olderError ? (
                    <span className="text-bad" role="alert">
                      Older events could not be loaded: {describeError(olderError, role)}
                    </span>
                  ) : null}
                </>
              ) : null
            }
          >
            <Async resource={first} loadingLabel="Loading events…">
              {() =>
                items.length === 0 ? (
                  filterKey ? (
                    <EmptyState
                      title="No events match these filters."
                      action={
                        <button type="button" className="button" onClick={() => apply({})}>
                          Clear filters
                        </button>
                      }
                    />
                  ) : (
                    <EmptyState title="No audit events recorded yet.">
                      Sign-ins, bundle imports, policy and key changes, backend changes and every gateway request are recorded here.
                    </EmptyState>
                  )
                ) : (
                  <EventsTable events={items} selectedSeq={selectedSeq} onSelect={setSelectedSeq} compact={selectedSeq !== null} />
                )
              }
            </Async>
          </Panel>
          {selectedSeq !== null ? (
            <div className="detail-panel">
              <EventDetail key={selectedSeq} seq={selectedSeq} known={selected} onClose={() => setSelectedSeq(null)} />
            </div>
          ) : null}
        </div>
      </div>
      <p className="sr-only" role="status">
        {selectedSeq !== null ? `Event ${selectedSeq} is shown in the detail panel.` : ''}
      </p>
    </>
  );
}

function ChainResult({ chain, onShow }: { chain: ChainVerification; onShow: (seq: number) => void }) {
  if (chain.ok) {
    return (
      <Callout tone="ok" role="status" title="Chain intact">
        <p>
          {plural(chain.events_checked, 'event')} recomputed from the first; head #{formatInt(chain.head_seq)}{' '}
          <Digest value={chain.head_hash} label="head hash" />. Checked <Time value={chain.verified_at} />.
        </p>
        <p className="muted">
          This detects edited or deleted events inside the log. Removal of the newest events shows up only against a checkpoint
          kept outside the database: <code>ferry audit checkpoint</code>, later <code>ferry audit verify --checkpoint FILE</code>.
        </p>
      </Callout>
    );
  }
  return (
    <Callout tone="bad" role="alert" title={chain.first_bad_seq !== null ? `Chain broken at event #${chain.first_bad_seq}` : 'Chain broken'}>
      <p>{chain.problem ?? 'The server reported a problem without a description.'}</p>
      <p>
        {plural(chain.events_checked, 'event')} verified before the problem. Checked <Time value={chain.verified_at} />.
      </p>
      {chain.first_bad_seq !== null ? (
        <p>
          <button type="button" className="button button--small" onClick={() => onShow(chain.first_bad_seq as number)}>
            Show event #{chain.first_bad_seq}
          </button>
        </p>
      ) : null}
    </Callout>
  );
}

function moveFocus(event: KeyboardEvent<HTMLButtonElement>): void {
  if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
  const row = event.currentTarget.closest('tr');
  const target = event.key === 'ArrowDown' ? row?.nextElementSibling : row?.previousElementSibling;
  const button = target?.querySelector<HTMLButtonElement>('button[data-seq]');
  if (button) {
    event.preventDefault();
    button.focus();
  }
}

/** `compact` (detail panel open) leaves out the correlation id, which the panel shows. */
function EventsTable({
  events,
  selectedSeq,
  onSelect,
  compact,
}: {
  events: readonly AuditEvent[];
  selectedSeq: number | null;
  onSelect: (seq: number) => void;
  compact: boolean;
}) {
  return (
    <div className="table-wrap table-wrap--tall">
      <table className="table">
        <caption className="sr-only">Audit events, newest first. Use the event number buttons to open details; arrow keys move between rows.</caption>
        <thead>
          <tr>
            <th scope="col" className="num">
              Seq
            </th>
            <th scope="col">Time</th>
            <th scope="col">Outcome</th>
            <th scope="col">Action</th>
            <th scope="col">Actor</th>
            <th scope="col">Resource</th>
            {compact ? null : <th scope="col">Correlation id</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const isSelected = e.seq === selectedSeq;
            return (
              <tr key={e.seq} className={isSelected ? 'is-clickable is-selected' : 'is-clickable'} onClick={() => onSelect(e.seq)}>
                <td className="num">
                  <button
                    type="button"
                    className="link-button num"
                    data-seq={e.seq}
                    aria-current={isSelected || undefined}
                    aria-label={`Event ${e.seq}: ${e.action}, ${e.outcome}`}
                    onClick={(ev) => {
                      ev.stopPropagation();
                      onSelect(e.seq);
                    }}
                    onKeyDown={moveFocus}
                  >
                    {e.seq}
                  </button>
                </td>
                <td className="nowrap">
                  <Time value={e.ts} />
                </td>
                <td className="nowrap">
                  <StatusBadge domain="outcome" value={e.outcome} />
                </td>
                <td>
                  <code>{e.action}</code>
                </td>
                <td className="nowrap">
                  <span className="tag">{e.actor_type}</span> <code>{e.actor_id}</code>
                </td>
                <td className="cell-truncate">
                  <code title={e.resource}>{e.resource}</code>
                </td>
                {compact ? null : (
                  <td className="nowrap">
                    {e.correlation_id ? (
                      <code title={e.correlation_id}>{e.correlation_id.length > 14 ? `${e.correlation_id.slice(0, 12)}…` : e.correlation_id}</code>
                    ) : (
                      <span className="subtle">—</span>
                    )}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
