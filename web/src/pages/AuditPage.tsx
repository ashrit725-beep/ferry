/**
 * Audit log: filterable, newest first, paged backwards with before_seq; an
 * event detail panel (non-modal) with its hash links; chain verification; export.
 *
 * Events that arrive on a Refresh rerank in place (rows are keyed by seq) and
 * hold an amber tint with a "New" word until they are opened or marked read.
 */

import { useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import { Download, ShieldCheck } from 'lucide-react';
import { AUDIT_EXPORT_URL, api, type AuditEvent, type AuditQuery, type ChainVerification, type Overview } from '../api.ts';
import { describeError } from '../errors.ts';
import { formatInt, plural } from '../format.ts';
import { useResource } from '../hooks.ts';
import { useMediaQuery } from '@/hooks/use-media';
import { auditFiltersFromParams, auditParams, navigate, paths } from '../router.ts';
import { useRole } from '../session.tsx';
import { chainCoverage, toneFor } from '../status.ts';
import { Callout, RefreshButton } from '../components/console/callout.tsx';
import { Checklist, ChecklistLine } from '../components/console/checklist.tsx';
import { DataTable, type Column } from '../components/console/data-table.tsx';
import { Digest } from '../components/console/digest.tsx';
import { PageHeader } from '../components/console/page-header.tsx';
import { Section } from '../components/console/section.tsx';
import { Stamp, toneToStamp } from '../components/console/stamp.tsx';
import { EmptyState, InlineError } from '../components/console/states.tsx';
import { Time } from '../components/console/time.tsx';
import { Button, buttonVariants } from '../components/ui/button.tsx';
import { AuditFilters } from './audit/AuditFilters.tsx';
import { EventDetail } from './audit/EventDetail.tsx';
import { cn } from '@/lib/utils';

const PAGE_SIZE = 100;
/** On phones rows stack and the page scrolls (no inner scroller), so fewer events load at a time. */
const PHONE_PAGE_SIZE = 25;
/** DataTable animates reordered rows only up to about this many. */
const RERANK_MAX = 50;

interface Older {
  key: string;
  items: AuditEvent[];
  next: number | null;
}

interface Seen {
  key: string;
  max: number;
}

export function AuditPage({ params }: { params: URLSearchParams }) {
  const role = useRole();
  const filters = useMemo(() => auditFiltersFromParams(params), [params]);
  const filterKey = auditParams(filters).toString();
  const facets = useResource((s) => api.auditFacets(s), []);
  // The last check the server recorded, shown until a check runs in this session.
  const recorded = useResource((s) => api.overview(s), []);
  const phone = useMediaQuery('(max-width: 639px)');
  const pageSize = phone ? PHONE_PAGE_SIZE : PAGE_SIZE;
  const first = useResource((s) => api.audit({ ...filters, limit: pageSize }, s), [filterKey, pageSize]);
  const [older, setOlder] = useState<Older | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [olderError, setOlderError] = useState<unknown>(null);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [chainError, setChainError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [seen, setSeen] = useState<Seen | null>(null);
  const [fresh, setFresh] = useState<ReadonlySet<number>>(() => new Set());

  // The first page for a filter set is the baseline; events above it that a
  // later Refresh brings in are new until read.
  useEffect(() => {
    const data = first.data;
    if (!data) return;
    const max = data.items.reduce((m, e) => Math.max(m, e.seq), 0);
    if (!seen || seen.key !== filterKey) {
      setSeen({ key: filterKey, max });
      setFresh(new Set());
      return;
    }
    if (max > seen.max) {
      const added = data.items.filter((e) => e.seq > seen.max).map((e) => e.seq);
      setFresh((prev) => new Set([...prev, ...added]));
      setSeen({ key: filterKey, max });
    }
    // `seen` is written here; reading it as a dependency would loop.
  }, [first.data, filterKey]);

  // Older pages belong to one filter set and one page size (a phone rotated past 640 px reloads).
  const pageKey = `${filterKey}#${pageSize}`;
  const olderNow = older && older.key === pageKey && first.data ? older : null;
  const items = useMemo(() => (first.data ? [...first.data.items, ...(olderNow?.items ?? [])] : []), [first.data, olderNow]);
  const cursor = olderNow ? olderNow.next : (first.data?.next_before_seq ?? null);
  const selected = selectedSeq !== null ? (items.find((e) => e.seq === selectedSeq) ?? null) : null;
  const previous = selectedSeq !== null ? (items.find((e) => e.seq === selectedSeq - 1) ?? null) : null;
  const badSeq = chain && !chain.ok ? chain.first_bad_seq : null;

  const open = (seq: number): void => {
    setSelectedSeq(seq);
    markRead(seq);
  };

  const markRead = (seq: number): void => {
    setFresh((prev) => {
      if (!prev.has(seq)) return prev;
      const next = new Set(prev);
      next.delete(seq);
      return next;
    });
  };

  const step = (direction: 1 | -1): void => {
    if (selectedSeq === null) return;
    const index = items.findIndex((e) => e.seq === selectedSeq);
    const next = index >= 0 ? items[index + direction] : undefined;
    if (next) open(next.seq);
  };

  const closeDetail = (): void => {
    const seq = selectedSeq;
    setSelectedSeq(null);
    if (seq !== null) document.querySelector<HTMLButtonElement>(`button[data-seq="${seq}"]`)?.focus();
  };

  // Up and Down on an event button move focus to the neighbouring row; with the detail open it follows.
  const moveFocus = (event: KeyboardEvent<HTMLButtonElement>): void => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const row = event.currentTarget.closest('tr');
    const target = event.key === 'ArrowDown' ? row?.nextElementSibling : row?.previousElementSibling;
    const button = target?.querySelector<HTMLButtonElement>('button[data-seq]');
    if (button) {
      event.preventDefault();
      button.focus();
      const seq = Number(button.dataset.seq);
      if (selectedSeq !== null && Number.isFinite(seq)) open(seq);
    }
  };

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
    const key = pageKey;
    setLoadingOlder(true);
    setOlderError(null);
    try {
      const page = await api.audit({ ...filters, before_seq: cursor, limit: pageSize });
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

  const columns: ReadonlyArray<Column<AuditEvent>> = [
    {
      id: 'seq',
      header: '#',
      align: 'right',
      nowrap: true,
      width: 'w-20',
      cell: (e) => (
        <span className="inline-flex items-center justify-end gap-1.5">
          {fresh.has(e.seq) ? <span className="text-2xs font-medium tracking-[0.06em] text-amber uppercase">New</span> : null}
          {e.seq === badSeq ? <span className="text-2xs font-medium tracking-[0.06em] text-bad uppercase">First bad</span> : null}
          <button
            type="button"
            data-seq={e.seq}
            aria-current={e.seq === selectedSeq || undefined}
            aria-label={`Event ${e.seq}: ${e.action}, ${e.outcome}${fresh.has(e.seq) ? ', new' : ''}`}
            onClick={(ev) => {
              ev.stopPropagation();
              open(e.seq);
            }}
            onKeyDown={moveFocus}
            className="-mx-1 inline-flex h-6 items-center rounded-sm px-1 font-mono text-bone tabular-nums underline decoration-text-3 underline-offset-3 hover:decoration-bone"
          >
            {e.seq}
          </button>
        </span>
      ),
    },
    { id: 'time', header: 'Time', nowrap: true, cell: (e) => <Time value={e.ts} /> },
    { id: 'action', header: 'Action', mono: true, nowrap: true, cell: (e) => e.action },
    {
      id: 'outcome',
      header: 'Outcome',
      nowrap: true,
      cell: (e) => (
        <Stamp state={toneToStamp(toneFor('outcome', e.outcome))} land={false}>
          {e.outcome}
        </Stamp>
      ),
    },
    {
      id: 'actor',
      header: 'Actor',
      nowrap: true,
      cell: (e) => (
        <span className="inline-flex items-center gap-1.5">
          <span className="rounded-sm bg-neutral-subtle px-1 text-2xs text-text-2">{e.actor_type}</span>
          <code className="font-mono">{e.actor_id}</code>
        </span>
      ),
    },
    {
      id: 'resource',
      header: 'Resource',
      hideOnPhone: true,
      cell: (e) => (
        <code title={e.resource} className="block max-w-40 truncate font-mono max-sm:max-w-full 2xl:max-w-72">
          {e.resource}
        </code>
      ),
    },
    {
      id: 'correlation',
      header: 'Correlation id',
      hideOnPhone: true,
      nowrap: true,
      cell: (e) =>
        e.correlation_id ? (
          <code title={e.correlation_id} className="font-mono text-text-2">
            {e.correlation_id.length > 12 ? `${e.correlation_id.slice(0, 12)}…` : e.correlation_id}
          </code>
        ) : (
          <span className="text-text-3">none</span>
        ),
    },
  ];

  const empty = filterKey ? (
    <EmptyState
      title={filters.q ? `No events match "${filters.q}".` : 'No events match these filters.'}
      action={
        <Button type="button" variant="outline" size="sm" onClick={() => apply({})}>
          Clear filters
        </Button>
      }
    >
      {describeFilters(filters)} Change or clear a filter to see more events.
    </EmptyState>
  ) : (
    <EmptyState title="No audit events recorded yet.">
      Sign-ins, bundle imports, policy and key changes, backend changes and every gateway request are recorded here.
    </EmptyState>
  );

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Security-relevant events, each hashed together with the one before it. Prompts, completions and credentials are never recorded."
        actions={
          <>
            <Button type="button" onClick={() => void verify()} aria-disabled={verifying || undefined}>
              <ShieldCheck aria-hidden="true" />
              {verifying ? 'Verifying…' : 'Verify chain'}
            </Button>
            <a className={buttonVariants({ variant: 'outline' })} href={AUDIT_EXPORT_URL} download>
              <Download aria-hidden="true" />
              Export all (NDJSON)
            </a>
            <RefreshButton onClick={refresh} busy={first.refreshing} />
          </>
        }
      />
      {/* With an event open at 1280 px and wider, the panel takes the right column of this grid. */}
      <div className={cn(selectedSeq !== null && 'xl:grid xl:grid-cols-[minmax(0,1fr)_32rem] xl:items-start xl:gap-4')}>
      <div className="flex min-w-0 flex-col gap-4">
        <div aria-live="polite">
          {chainError ? (
            <Callout tone="bad" role="alert" title="The chain check did not run.">
              <p>{chainError}</p>
            </Callout>
          ) : (
            <ChainCheck chain={chain} recorded={recorded.data?.audit ?? null} recordedLoading={recorded.loading} verifying={verifying} onShow={open} />
          )}
        </div>

        <Section
          title="Events"
          description={first.data ? (items.length === 0 ? 'No events shown.' : `${plural(items.length, 'event')} shown, newest first.`) : null}
          flush
          actions={
            fresh.size ? (
              <>
                <span className="text-xs text-amber" role="status">
                  <span className="font-mono tabular-nums">{formatInt(fresh.size)}</span> new since the last load
                </span>
                <Button type="button" variant="ghost" size="sm" onClick={() => setFresh(new Set())}>
                  Mark read
                </Button>
              </>
            ) : null
          }
          footer={
            first.data && (cursor !== null || olderError) ? (
              <div className="flex flex-wrap items-center gap-3">
                {cursor !== null ? (
                  <Button type="button" variant="outline" size="sm" onClick={() => void loadOlder()} aria-disabled={loadingOlder || undefined}>
                    {loadingOlder ? 'Loading…' : 'Load older events'}
                  </Button>
                ) : null}
                {olderError ? (
                  <span className="text-bad" role="alert">
                    Older events could not be loaded: {describeError(olderError, role)}
                  </span>
                ) : null}
              </div>
            ) : null
          }
        >
          <div className="border-b border-hairline px-3 py-3">
            <AuditFilters filters={filters} facets={facets.data} onApply={apply} />
          </div>
          {first.data && first.error ? (
            <div className="px-3 pt-3">
              <InlineError error={first.error} prefix="Could not refresh; showing the last data loaded." onRetry={first.reload} />
            </div>
          ) : null}
          <DataTable
            caption="Audit events, newest first. Use the event number buttons to open details; arrow keys move between rows."
            // With an event open, the detail panel carries the resource and correlation id,
            // so Seq, Time, Action, Outcome and Actor stay in view without scrolling.
            columns={selectedSeq !== null ? columns.filter((c) => c.id !== 'resource' && c.id !== 'correlation') : columns}
            rows={first.data ? items : null}
            rowKey={(e) => String(e.seq)}
            loading={first.loading}
            error={first.error}
            onRetry={first.reload}
            empty={empty}
            rowTone={(e) => (e.seq === badSeq ? 'bad' : fresh.has(e.seq) ? 'warn' : null)}
            held={(e) => e.seq === badSeq || fresh.has(e.seq)}
            selectedKey={selectedSeq !== null ? String(selectedSeq) : null}
            rowProps={(e) => ({ className: 'cursor-pointer', onClick: () => open(e.seq) })}
            rerank={items.length <= RERANK_MAX}
            maxHeight="max-h-[calc(100vh-260px)]"
            skeletonRows={8}
          />
        </Section>
      </div>
      <EventDetail seq={selectedSeq} known={selected} previous={previous} onOpen={open} onStep={step} onClose={closeDetail} />
      </div>
      <p className="sr-only" role="status">
        {selectedSeq !== null ? `Event ${selectedSeq} is shown in the detail panel.` : ''}
      </p>
    </>
  );
}

/** The active filters as one sentence ("Filtered to action bundle.*, actor admin, since …."). */
function describeFilters(f: AuditQuery): string {
  const parts: string[] = [];
  if (f.action) parts.push(`action ${f.action}`);
  if (f.outcome) parts.push(`outcome ${f.outcome}`);
  if (f.actor_type) parts.push(`actor type ${f.actor_type}`);
  if (f.actor_id) parts.push(`actor ${f.actor_id}`);
  if (f.resource) parts.push(`resource ${f.resource}`);
  if (f.correlation_id) parts.push(`correlation id ${f.correlation_id}`);
  if (f.q) parts.push(`search "${f.q}"`);
  if (f.since) parts.push(`since ${f.since}`);
  if (f.until) parts.push(`until ${f.until}`);
  return parts.length ? `Filtered to ${parts.join(', ')}.` : '';
}

function ChainCheck({
  chain,
  recorded,
  recordedLoading,
  verifying,
  onShow,
}: {
  chain: ChainVerification | null;
  recorded: Overview['audit'] | null;
  recordedLoading: boolean;
  verifying: boolean;
  onShow: (seq: number) => void;
}) {
  let line;
  if (verifying) {
    line = (
      <ChecklistLine
        label="Hash chain"
        state="pending"
        pending
        stamp="Verifying"
        detail="Recomputing every event hash from the first event and comparing it with the stored chain."
      />
    );
  } else if (!chain && recorded && recorded.last_verify) {
    const cov = chainCoverage(recorded);
    const last = recorded.last_verify;
    const range = (to: number | null) => (to === null ? 'an unrecorded range' : to > 0 ? `events #1–${formatInt(to)}` : 'no events');
    line =
      cov.kind === 'current' ? (
        <ChecklistLine
          label="Hash chain"
          state="confirmed"
          stamp="Intact"
          value={<Time value={last.verified_at} />}
          detail={
            <>
              Last recorded check, <Time value={last.verified_at} exact />, covered {range(cov.checkedTo)}; nothing has been recorded since. Verify chain runs it
              again and records the check in the log.
            </>
          }
        />
      ) : cov.kind === 'stale' ? (
        <ChecklistLine
          label="Hash chain"
          state="pending"
          stamp="Recheck"
          value={
            <span>
              Intact to <span className="font-mono tabular-nums">{cov.checkedTo === null ? 'the check' : `#${formatInt(cov.checkedTo)}`}</span>
              {cov.since !== null ? <> · {plural(cov.since, 'event')} since</> : null}
            </span>
          }
          detail={
            <>
              Last recorded check, <Time value={last.verified_at} exact />, covered {range(cov.checkedTo)}
              {cov.since !== null ? `; ${plural(cov.since, 'newer event')} ${cov.since === 1 ? 'is' : 'are'} not checked yet` : '; newer events are not checked yet'}.
              Verify chain checks them and records the check in the log.
            </>
          }
        />
      ) : (
        <ChecklistLine
          label="Hash chain"
          state="failed"
          stamp="Broken"
          value={<Time value={last.verified_at} />}
          detail={
            <>
              The last recorded check found a problem: {last.problem ?? 'the server recorded no description.'} Verify chain runs it again to locate the event.
            </>
          }
        />
      );
  } else if (!chain && recordedLoading) {
    line = <ChecklistLine label="Hash chain" state="neutral" stamp="Reading" settled={false} detail="Reading the last recorded check…" />;
  } else if (!chain) {
    line = (
      <ChecklistLine
        label="Hash chain"
        state="neutral"
        stamp="Not checked"
        detail="Verify chain recomputes every event hash from the first event and records the check in the log; no event is changed. Every role may run it."
      />
    );
  } else if (chain.ok) {
    line = (
      <ChecklistLine
        label="Hash chain"
        state="confirmed"
        stamp="Intact"
        drawKey={chain.verified_at}
        value={<Digest value={chain.head_hash} label="head hash" />}
        detail={
          <span role="status">
            {plural(chain.events_checked, 'event')} recomputed from the first; head #{formatInt(chain.head_seq)}. Checked <Time value={chain.verified_at} />.
          </span>
        }
      />
    );
  } else {
    const bad = chain.first_bad_seq;
    line = (
      <ChecklistLine
        label={bad !== null ? `Chain broken at event #${bad}` : 'Chain broken'}
        state="failed"
        stamp="Broken"
        drawKey={chain.verified_at}
        value={bad !== null ? `#${formatInt(bad)}` : undefined}
        action={
          bad !== null ? (
            <Button type="button" variant="outline" size="sm" onClick={() => onShow(bad)}>
              Show event #{bad}
            </Button>
          ) : null
        }
        detail={
          <span role="alert">
            {chain.problem ?? 'The server reported a problem without a description.'} {plural(chain.events_checked, 'event')} verified before the problem. Checked{' '}
            <Time value={chain.verified_at} />.
          </span>
        }
      />
    );
  }
  return (
    <div className="flex flex-col gap-2">
      <Checklist label="Chain check">{line}</Checklist>
      {chain?.ok && !verifying ? (
        <p className="max-w-[72ch] text-xs text-text-3 text-pretty [&_code]:font-mono [&_code]:text-text-2">
          This detects edited or deleted events inside the log. Removal of the newest events shows up only against a checkpoint kept outside the database:{' '}
          <code>ferry audit checkpoint</code>, later <code>ferry audit verify --checkpoint FILE</code>.
        </p>
      ) : null}
    </div>
  );
}
