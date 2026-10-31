/**
 * Overview: the enclave's readiness checklist, built from GET /api/overview.
 * Every figure on this page is a value from that response or plain
 * arithmetic on it (counts of rows, shares, success rate). The server's
 * attention items are filed under the readiness line they concern; any the
 * page cannot place are listed under "Other findings".
 */

import { useEffect, useState, type ReactNode } from 'react';
import {
  api,
  type Attention,
  type Overview,
  type OverviewBackend,
  type OverviewPolicy,
  type OverviewRoute,
  type Traffic,
  type TrafficByEnvironment,
} from '../api.ts';
import { formatInt, formatMs, formatPercent, plural } from '../format.ts';
import { useAutoRefresh, useResource } from '../hooks.ts';
import { environmentSegments, OUTCOME_TEXT, trafficSegments, type Segment } from '../metrics.ts';
import { paths, safeInternalHref, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { chainCoverage, severityRank, statusLabel, toneFor } from '../status.ts';
import type { Environment, TrafficOutcome } from '../api.ts';
import { Callout, RefreshButton } from '@/components/console/callout.tsx';
import { Checklist, ChecklistLine } from '@/components/console/checklist.tsx';
import { DataTable, type Column } from '@/components/console/data-table.tsx';
import { Digest, MonoId } from '@/components/console/digest.tsx';
import { gatewayFromOverview, useGateway } from '@/components/console/gateway.tsx';
import { KeyValueList } from '@/components/console/key-value-list.tsx';
import { LifecycleStrip } from '@/components/console/lifecycle-strip.tsx';
import { PageHeader } from '@/components/console/page-header.tsx';
import { Readout } from '@/components/console/readout.tsx';
import { Section } from '@/components/console/section.tsx';
import { ShareBar, Swatch } from '@/components/console/share-bar.tsx';
import { Stamp, toneToStamp, type StampState } from '@/components/console/stamp.tsx';
import { Async, EmptyState, PanelSkeleton, TableSkeleton } from '@/components/console/states.tsx';
import { StatusBadge } from '@/components/console/status-badge.tsx';
import { Time } from '@/components/console/time.tsx';
import { buttonVariants } from '@/components/ui/button.tsx';
import { cn } from '@/lib/utils';

const REFRESH_MS = 30_000;

const CLOCK = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

export function OverviewPage() {
  const { isAdmin } = useSession();
  const overview = useResource((signal) => api.overview(signal), []);
  useAutoRefresh(overview.reload, REFRESH_MS);
  const data = overview.data;
  const { report } = useGateway();
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  useEffect(() => {
    if (data) {
      report(gatewayFromOverview(data));
      setUpdatedAt(Date.now());
    }
  }, [data, report]);
  const stale = data !== null && overview.error !== null;
  return (
    <>
      <PageHeader
        title="Overview"
        meta={
          data ? (
            <>
              Ferry {data.version} · server started <Time value={data.started_at} /> · updates every 30 s
              {updatedAt !== null ? (
                <span className={stale ? 'text-amber' : undefined}>
                  {' '}
                  · {stale ? 'stale, last updated' : 'updated'} {CLOCK.format(updatedAt)}
                </span>
              ) : null}
              {overview.refreshing ? <span className="text-amber"> · refreshing…</span> : null}
            </>
          ) : null
        }
        actions={<RefreshButton onClick={overview.reload} busy={overview.refreshing} />}
      />
      <Async resource={overview} loadingLabel="Loading overview…" skeleton={<OverviewSkeleton />}>
        {(o) => <OverviewBody overview={o} isAdmin={isAdmin} />}
      </Async>
    </>
  );
}

function OverviewSkeleton() {
  const box = 'overflow-hidden rounded-lg bg-panel ring-1 ring-hairline';
  return (
    <div className="flex flex-col gap-4">
      <p role="status" className="sr-only">
        Loading overview…
      </p>
      <div className={box}>
        <PanelSkeleton lines={3} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className={cn(box, 'lg:col-span-2')}>
          <PanelSkeleton lines={8} />
        </div>
        <div className={box}>
          <PanelSkeleton lines={4} />
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <div className={box}>
          <PanelSkeleton lines={4} />
        </div>
        <div className={box}>
          <PanelSkeleton lines={4} />
        </div>
      </div>
      <div className={box}>
        <TableSkeleton rows={4} columns={3} />
      </div>
    </div>
  );
}

function OverviewBody({ overview: o, isAdmin }: { overview: Overview; isAdmin: boolean }) {
  return (
    <div className="flex flex-col gap-4">
      <LifecycleSection overview={o} />
      <div className="grid gap-4 lg:grid-cols-3">
        <ReadinessSection overview={o} isAdmin={isAdmin} className="lg:col-span-2" />
        <GatewaySummary traffic={o.traffic_24h} />
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <PolicySection policy={o.policy} isAdmin={isAdmin} />
        <AuditSection audit={o.audit} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <BackendsSection backends={o.backends} isAdmin={isAdmin} />
        <RoutesSection routes={o.routes} isAdmin={isAdmin} />
      </div>
      <TrafficSection traffic={o.traffic_24h} byEnv={o.traffic_by_environment_24h} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Readiness checklist                                                 */
/* ------------------------------------------------------------------ */

type LineId = 'trust' | 'bundles' | 'inbox' | 'backends' | 'routes' | 'policy' | 'keys' | 'audit';

interface ReadinessLine {
  id: LineId;
  label: string;
  href: string;
  state: StampState;
  stamp: string;
  value?: ReactNode;
  /** What to do next when the server reported nothing for this line. */
  detail?: ReactNode;
  /** Label of the link that takes the operator to the fix. */
  actionLabel: string;
  /** Server attention items filed under this line. */
  items: Attention[];
}

/** File a server attention item under the readiness line it concerns (null: none fits). */
function lineOf(item: Attention): LineId | null {
  const m = item.message;
  if (m.startsWith('Trust store:') || m.startsWith('No trusted signing keys')) return 'trust';
  if (m.includes('bundle verification') || m.includes('in the inbox')) return 'inbox';
  if (m.startsWith('Backend ')) return 'backends';
  if (m.startsWith('Route ')) return 'routes';
  if (m.startsWith('No access policy')) return 'policy';
  if (m.includes('API key')) return 'keys';
  if (m.toLowerCase().includes('audit chain')) return 'audit';
  return null;
}

const STATE_RANK: Record<StampState, number> = { failed: 0, pending: 1, warning: 1, info: 2, neutral: 3, confirmed: 4 };

/** The state an attention item forces on its line: errors fail it, anything else leaves it pending. */
function itemState(item: Attention): StampState {
  return item.severity === 'error' ? 'failed' : 'pending';
}

/** Range of events a check covered, e.g. "#1–74". */
function coveredRange(checkedTo: number | null): string {
  return checkedTo === null ? 'an unrecorded range' : checkedTo > 0 ? `#1–${formatInt(checkedTo)}` : 'no events';
}

/**
 * The readiness line answers with the recorded check, never with the head:
 * events appended after the check are not vouched for until it runs again.
 */
function auditLine(audit: Overview['audit']): Pick<ReadinessLine, 'state' | 'stamp' | 'value' | 'detail' | 'actionLabel'> {
  const cov = chainCoverage(audit);
  switch (cov.kind) {
    case 'never':
      return {
        state: 'pending',
        stamp: 'Not checked',
        value: audit.head_seq > 0 ? `${plural(audit.head_seq, 'event')} recorded` : 'no events yet',
        detail: 'No check recorded. Verify chain recomputes every event hash and records the check in the log.',
        actionLabel: 'Verify chain',
      };
    case 'failed':
      return {
        state: 'failed',
        stamp: 'Broken',
        value: <Time value={cov.last.verified_at} />,
        detail: `Problem: ${cov.last.problem ?? 'not described'}`,
        actionLabel: 'Verify chain',
      };
    case 'current':
      return {
        state: 'confirmed',
        stamp: 'Intact',
        value: (
          <span className="inline-flex flex-wrap items-center gap-x-2">
            <span>
              Checked <span className="font-mono tabular-nums">{coveredRange(cov.checkedTo)}</span>
            </span>
            <Time value={cov.last.verified_at} />
          </span>
        ),
        actionLabel: 'Open audit log',
      };
    case 'stale':
      return {
        state: 'pending',
        stamp: 'Recheck',
        value: (
          <span className="inline-flex flex-wrap items-center gap-x-2">
            <span>
              Intact to <span className="font-mono tabular-nums">{cov.checkedTo === null ? 'the check' : `#${formatInt(cov.checkedTo)}`}</span>
              {cov.since !== null ? <> · {plural(cov.since, 'event')} since</> : null}
            </span>
            <Time value={cov.last.verified_at} />
          </span>
        ),
        detail: (
          <>
            The last check covered {coveredRange(cov.checkedTo)}
            {cov.since !== null ? `; ${plural(cov.since, 'newer event')} ${cov.since === 1 ? 'is' : 'are'} not checked yet` : '; newer events are not checked yet'}. Verify chain
            checks them and records the check in the log.
          </>
        ),
        actionLabel: 'Verify chain',
      };
  }
}

function buildLines(o: Overview, isAdmin: boolean): { lines: ReadinessLine[]; other: Attention[] } {
  const c = o.counts;
  const bucket = new Map<LineId, Attention[]>();
  const other: Attention[] = [];
  for (const item of [...o.attention].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))) {
    const id = lineOf(item);
    if (id === null) other.push(item);
    else bucket.set(id, [...(bucket.get(id) ?? []), item]);
  }

  const backendsUp = o.backends.filter((b) => b.state === 'up').length;
  const backendsDown = o.backends.filter((b) => b.state === 'down').length;
  const backendsLoading = o.backends.filter((b) => b.state === 'loading').length;
  const routesVerified = o.routes.filter((r) => r.provenance === 'verified').length;
  const routesMismatch = o.routes.filter((r) => r.provenance === 'mismatch').length;
  const routesUnavailable = o.routes.filter((r) => !r.available).length;
  const addOne = isAdmin ? 'Add one on the Models page' : 'An admin can add one on the Models page';

  const base: Array<Omit<ReadinessLine, 'items'>> = [
    {
      id: 'trust',
      label: 'Trusted signing keys',
      href: toHash(paths.bundles),
      ...(c.trusted_keys === 0
        ? {
            state: 'failed' as const,
            stamp: 'None trusted',
            detail: (
              <>
                Every bundle is rejected until a publisher key is trusted. On the host:{' '}
                <code className="font-mono text-bone">ferry trust add KEY.pub.pem --name NAME --role publisher</code>
              </>
            ),
          }
        : { state: 'confirmed' as const, stamp: 'Trusted' }),
      value: plural(c.trusted_keys, 'key'),
      actionLabel: 'Open trust store',
    },
    {
      id: 'bundles',
      label: 'Imported bundles',
      href: toHash(paths.bundles),
      ...(c.bundles === 0
        ? {
            state: 'pending' as const,
            stamp: 'None yet',
            detail: (
              <>
                Import one from the inbox on the Bundles page, or on the host with <code className="font-mono text-bone">ferry import BUNDLE</code>.
              </>
            ),
          }
        : { state: 'confirmed' as const, stamp: 'Imported' }),
      value: `${plural(c.bundles, 'bundle')} · ${plural(c.model_artifacts, 'model file')}`,
      actionLabel: isAdmin ? 'Import from the inbox' : 'Open bundles',
    },
    {
      id: 'inbox',
      label: 'Inbox',
      href: toHash(paths.bundles),
      ...(o.inbox_pending > 0 ? { state: 'pending' as const, stamp: 'Awaiting verify' } : { state: 'confirmed' as const, stamp: 'Clear' }),
      value: `${formatInt(o.inbox_pending)} waiting`,
      actionLabel: isAdmin && o.inbox_pending > 0 ? `Verify ${plural(o.inbox_pending, 'bundle')} in the inbox` : 'Open inbox',
    },
    {
      id: 'backends',
      label: 'Backends',
      href: toHash(paths.models),
      ...(o.backends.length === 0
        ? {
            state: 'pending' as const,
            stamp: 'None configured',
            detail: (
              <>
                {addOne}, or on the host with <code className="font-mono text-bone">ferry backend add NAME --kind llamacpp --url URL</code>.
              </>
            ),
          }
        : backendsDown > 0
          ? { state: 'failed' as const, stamp: 'Down' }
          : backendsUp < o.backends.length
            ? { state: 'pending' as const, stamp: backendsLoading > 0 ? 'Loading' : 'Not checked' }
            : { state: 'confirmed' as const, stamp: 'Healthy' }),
      value: `${formatInt(backendsUp)} of ${formatInt(o.backends.length)} up`,
      actionLabel: 'Open models',
    },
    {
      id: 'routes',
      label: 'Routes with verified provenance',
      href: toHash(paths.models),
      ...(o.routes.length === 0
        ? {
            state: 'pending' as const,
            stamp: 'None yet',
            detail: `A route maps a public model name to a backend and a pinned artifact. ${addOne}.`,
          }
        : routesMismatch > 0
          ? { state: 'failed' as const, stamp: 'Mismatch' }
          : routesVerified < o.routes.length
            ? { state: 'pending' as const, stamp: 'Unverified' }
            : routesUnavailable > 0
              ? { state: 'pending' as const, stamp: 'Unavailable' }
              : { state: 'confirmed' as const, stamp: 'Verified' }),
      value: `${formatInt(routesVerified)} of ${formatInt(o.routes.length)} verified`,
      actionLabel: 'Open routes',
    },
    {
      id: 'policy',
      label: 'Active policy',
      href: toHash(paths.access('policy')),
      ...(o.policy === null
        ? {
            state: 'failed' as const,
            stamp: 'None active',
            value: undefined,
            detail: `Every gateway request is denied until ${isAdmin ? 'you activate' : 'an admin activates'} a policy on the Access page.`,
          }
        : {
            state: 'confirmed' as const,
            stamp: 'Active',
            value: `v${o.policy.version} · ${plural(o.policy.rule_count, 'rule')}`,
          }),
      actionLabel: isAdmin && o.policy === null ? 'Activate a policy' : 'Open policy',
    },
    {
      id: 'keys',
      label: 'API keys',
      href: toHash(paths.access()),
      ...(c.active_keys === 0
        ? {
            state: 'pending' as const,
            stamp: 'None active',
            detail: 'Apps call the gateway with an API key issued on the Access page; no key is active.',
          }
        : { state: 'confirmed' as const, stamp: 'Issued' }),
      value: `${formatInt(c.active_keys)} active · ${plural(c.apps, 'app')}`,
      actionLabel: isAdmin && c.active_keys === 0 ? 'Issue an API key' : 'Open access',
    },
    {
      id: 'audit',
      label: 'Audit chain',
      href: toHash(paths.audit()),
      ...auditLine(o.audit),
    },
  ];

  const lines = base.map((line): ReadinessLine => {
    const items = bucket.get(line.id) ?? [];
    const worst = items.reduce<StampState | null>((acc, item) => {
      const s = itemState(item);
      return acc === null || STATE_RANK[s] < STATE_RANK[acc] ? s : acc;
    }, null);
    if (worst !== null && STATE_RANK[worst] < STATE_RANK[line.state]) {
      return { ...line, items, state: worst, stamp: worst === 'failed' ? 'Failed' : 'Needs attention' };
    }
    return { ...line, items };
  });
  // Attention first: failed, then pending, then confirmed; the order above holds within each.
  lines.sort((a, b) => STATE_RANK[a.state] - STATE_RANK[b.state]);
  return { lines, other };
}

function AttentionMessage({ item }: { item: Attention }) {
  const href = safeInternalHref(item.href);
  return href ? (
    <a href={href} className="text-text-2 underline underline-offset-3 hover:text-bone">
      {item.message}
    </a>
  ) : (
    <span className="text-text-2">{item.message}</span>
  );
}

function ReadinessSection({ overview: o, isAdmin, className }: { overview: Overview; isAdmin: boolean; className?: string }) {
  const { lines, other } = buildLines(o, isAdmin);
  const confirmed = lines.filter((l) => l.state === 'confirmed').length;
  const outstanding = lines.length - confirmed + other.length;
  const firstOpen = lines.findIndex((l) => l.state !== 'confirmed');
  return (
    <Section
      title="Enclave readiness"
      description={outstanding === 0 ? 'Nothing needs attention.' : 'Read top to bottom: what needs a human comes first.'}
      attention={outstanding > 0}
      className={className}
      actions={
        <span role="status" className="text-xs text-text-2 tabular-nums">
          {formatInt(confirmed)} of {formatInt(lines.length)} confirmed
        </span>
      }
    >
      <Checklist ariaLabel="Enclave readiness">
        {lines.map((line, i) => (
          <ChecklistLine
            key={line.id}
            label={line.label}
            href={line.href}
            state={line.state}
            stamp={line.stamp}
            value={line.value}
            
            detail={
              line.items.length > 0 ? (
                <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
                  {line.items.map((item, k) => (
                    <li key={k}>
                      <AttentionMessage item={item} />
                    </li>
                  ))}
                </ul>
              ) : line.state !== 'confirmed' ? (
                line.detail
              ) : undefined
            }
            action={
              line.state !== 'confirmed' ? (
                <a
                  href={line.href}
                  className={cn(buttonVariants({ size: 'sm', variant: i === firstOpen ? 'attention' : 'outline' }), 'rounded-md')}
                >
                  {line.actionLabel}
                </a>
              ) : undefined
            }
          />
        ))}
      </Checklist>
      {other.length > 0 ? (
        <div className="mt-3 border-t border-hairline pt-3">
          <Checklist label="Other findings" summary={plural(other.length, 'item')} as="ul">
            {other.map((item, k) => (
              <li key={k} className="flex min-h-8 items-start gap-2 py-1.5 text-sm">
                <Stamp state={toneToStamp(toneFor('severity', item.severity))}>{item.severity}</Stamp>
                <span className="min-w-0 text-pretty">
                  <AttentionMessage item={item} />
                </span>
              </li>
            ))}
          </Checklist>
        </div>
      ) : null}
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

function LifecycleSection({ overview: o }: { overview: Overview }) {
  const serving = o.routes.filter((r) => r.available && r.provenance === 'verified').length;
  return (
    <Section
      title="Bundle lifecycle"
      description="Where models stand on either side of the air gap."
      open={{ href: toHash(paths.bundles), label: 'Open bundles' }}
    >
      <LifecycleStrip
        className="py-1"
        verified={o.counts.bundles}
        imported={o.counts.model_artifacts}
        serving={serving}
        inboxPending={o.inbox_pending}
        inboxHref={toHash(paths.bundles)}
      />
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Gateway summary (row 2, right third)                                */
/* ------------------------------------------------------------------ */

function GatewaySummary({ traffic }: { traffic: Traffic }) {
  if (traffic.total === 0) {
    return (
      <Section title="Gateway, last 24 hours" description="Counted from gateway request audit events." flush>
        <EmptyState title="No gateway requests in the last 24 hours.">
          Apps call <code>POST /v1/chat/completions</code> on this server with an API key issued on the Access page.
        </EmptyState>
      </Section>
    );
  }
  const segments = trafficSegments(traffic).filter((s) => s.count > 0);
  return (
    <Section title="Gateway, last 24 hours" description="Counted from gateway request audit events." flush>
      <div className="grid grid-cols-2 gap-px border-b border-hairline bg-hairline *:bg-panel">
        <Readout label="Requests" value={traffic.total} />
        <Readout label="Success rate" value={formatPercent(traffic.success, traffic.total)} />
        <Readout label="Denied" value={traffic.denied} />
        <Readout label="Latency p50" value={formatMs(traffic.p50_ms)} hint={<>p95 {formatMs(traffic.p95_ms)}</>} />
      </div>
      <div className="flex flex-col gap-2 px-3 py-3">
        <ShareBar segments={segments} />
        <ul aria-label="Outcomes in the bar" className="m-0 grid list-none grid-cols-2 gap-x-3 gap-y-1 p-0 text-xs text-text-2">
          {segments.map((s) => (
            <li key={s.key} className="flex min-w-0 items-center gap-1.5">
              <Swatch name={s.key} />
              <span className="min-w-0 truncate">{OUTCOME_TEXT[s.key].label}</span>
              <span className="ml-auto font-mono text-text-3 tabular-nums">{formatInt(s.count)}</span>
            </li>
          ))}
        </ul>
      </div>
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Policy and audit                                                    */
/* ------------------------------------------------------------------ */

function PolicySection({ policy, isAdmin }: { policy: OverviewPolicy | null; isAdmin: boolean }) {
  return (
    <Section title="Access policy" open={{ href: toHash(paths.access('policy')), label: 'Open policy' }} attention={policy === null}>
      {policy ? (
        <KeyValueList
          items={[
            ['Active version', <span className="font-mono tabular-nums">v{policy.version}</span>],
            ['Rules', <span className="font-mono tabular-nums">{formatInt(policy.rule_count)}</span>],
            ['Activated', <Time value={policy.activated_at} exact />],
            ['SHA-256', <Digest value={policy.sha256} label="policy sha256" />],
          ]}
        />
      ) : (
        <Callout tone="bad" title="No active policy">
          <p>Every gateway request is denied until {isAdmin ? 'you activate' : 'an admin activates'} a policy on the Access page.</p>
        </Callout>
      )}
    </Section>
  );
}

function AuditSection({ audit }: { audit: Overview['audit'] }) {
  const cov = chainCoverage(audit);
  const last = audit.last_verify;
  const check =
    cov.kind === 'never' ? (
      <span className="text-text-3">no check recorded; run one from the audit log</span>
    ) : (
      <span className="inline-flex flex-wrap items-center gap-2">
        {cov.kind === 'failed' ? (
          <StatusBadge domain="chain" value="broken" />
        ) : cov.kind === 'current' ? (
          <StatusBadge domain="chain" value="intact" />
        ) : (
          <Stamp state="pending">Recheck</Stamp>
        )}
        <Time value={cov.last.verified_at} />
      </span>
    );
  const covered =
    cov.kind === 'current' || cov.kind === 'stale' ? (
      <span>
        <span className="font-mono tabular-nums">{cov.checkedTo === null ? 'unrecorded' : cov.checkedTo > 0 ? `#1–${formatInt(cov.checkedTo)}` : 'none'}</span>
        {cov.kind === 'stale' ? (
          <span className="text-text-2"> · {cov.since === null ? 'newer events not checked' : `${plural(cov.since, 'newer event')} not checked`}</span>
        ) : (
          <span className="text-text-2"> · nothing newer</span>
        )}
      </span>
    ) : null;
  return (
    <Section
      title="Audit log"
      open={{ href: toHash(paths.audit()), label: 'Open audit log' }}
      attention={cov.kind === 'failed' || cov.kind === 'stale' || cov.kind === 'never'}
    >
      <KeyValueList
        items={[
          ['Latest event', audit.head_seq > 0 ? <span className="font-mono tabular-nums">#{formatInt(audit.head_seq)}</span> : 'none yet'],
          ['Head hash', <Digest value={audit.head_hash} label="audit head hash" />],
          ['Last chain check', check],
          ['Checked events', covered],
          ['Problem', last && !last.ok ? (last.problem ?? 'not described') : null],
        ]}
      />
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Traffic                                                             */
/* ------------------------------------------------------------------ */

function TrafficSection({ traffic, byEnv }: { traffic: Traffic; byEnv: TrafficByEnvironment }) {
  if (traffic.total === 0) return null;
  const segments = trafficSegments(traffic);
  const environments = environmentSegments(byEnv);
  const share = (s: Segment<string>) => formatPercent(s.count, traffic.total);
  const outcomeColumns: ReadonlyArray<Column<Segment<TrafficOutcome>>> = [
    {
      id: 'outcome',
      header: 'Outcome',
      cell: (s) => (
        <span className="flex items-center gap-2 max-sm:items-start">
          <span className="shrink-0 max-sm:pt-px">
            <Swatch name={s.key} />
          </span>
          <span className="flex min-w-0 flex-col sm:flex-row sm:gap-1">
            <span className="text-bone">{OUTCOME_TEXT[s.key].label}</span>
            <span className="text-text-3">
              <span className="max-sm:hidden">· </span>
              {OUTCOME_TEXT[s.key].hint}
            </span>
          </span>
        </span>
      ),
    },
    { id: 'requests', header: 'Requests', align: 'right', mono: true, cell: (s) => formatInt(s.count) },
    { id: 'share', header: 'Share', align: 'right', mono: true, cell: share },
  ];
  const envColumns: ReadonlyArray<Column<Segment<Environment>>> = [
    { id: 'env', header: 'App environment', cell: (e) => e.key },
    { id: 'requests', header: 'Requests', align: 'right', mono: true, cell: (e) => formatInt(e.count) },
    { id: 'share', header: 'Share', align: 'right', mono: true, cell: share },
  ];
  return (
    <Section title="Gateway traffic by outcome and environment" description="Last 24 hours, counted from gateway.chat.completions audit events." flush>
      <div className="grid lg:grid-cols-2 lg:divide-x lg:divide-hairline">
        <DataTable caption="Requests by outcome, last 24 hours" columns={outcomeColumns} rows={segments} rowKey={(s) => s.key} />
        <DataTable caption="Requests by app environment, last 24 hours" columns={envColumns} rows={environments} rowKey={(e) => e.key} />
      </div>
    </Section>
  );
}

/* ------------------------------------------------------------------ */
/* Backends and routes                                                 */
/* ------------------------------------------------------------------ */

function BackendsSection({ backends, isAdmin }: { backends: readonly OverviewBackend[]; isAdmin: boolean }) {
  const columns: ReadonlyArray<Column<OverviewBackend>> = [
    { id: 'name', header: 'Backend', className: 'max-w-64', cell: (b) => <MonoId value={b.name} /> },
    { id: 'kind', header: 'Kind', mono: true, cell: (b) => b.kind },
    { id: 'state', header: 'State', nowrap: true, cell: (b) => <StatusBadge domain="backend" value={b.state} label={b.state ?? 'not checked'} /> },
    { id: 'checked', header: 'Last check', nowrap: true, cell: (b) => <Time value={b.checked_at} fallback="never" /> },
  ];
  return (
    <Section title="Backend health" open={{ href: toHash(paths.models), label: 'Open models' }} flush>
      {/* Under 640 px: checklist lines (name ..... kind, last check [STATE]), so the state is never scrolled away. */}
      {backends.length > 0 ? (
        <Checklist as="ul" ariaLabel="Backend health" className="px-3 py-1 sm:hidden">
          {backends.map((b) => (
            <ChecklistLine
              key={b.id}
              label={<MonoId value={b.name} className="text-xs" />}
              state={toneToStamp(toneFor('backend', b.state))}
              stamp={b.state ?? 'not checked'}
              value={
                <>
                  <span className="font-mono">{b.kind}</span> · checked <Time value={b.checked_at} fallback="never" />
                </>
              }
            />
          ))}
        </Checklist>
      ) : null}
      <DataTable
        className={backends.length > 0 ? 'max-sm:hidden' : undefined}
        caption="Backend health"
        columns={columns}
        rows={backends}
        rowKey={(b) => String(b.id)}
        rowTone={(b) => (b.state === 'down' ? 'bad' : b.state === 'loading' ? 'warn' : null)}
        empty={
          <EmptyState title="No inference backends configured.">
            {isAdmin ? 'Add one on the Models page' : 'An admin can add one on the Models page'}, or on the host with{' '}
            <code>ferry backend add NAME --kind llamacpp --url URL</code>.
          </EmptyState>
        }
      />
    </Section>
  );
}

function RoutesSection({ routes, isAdmin }: { routes: readonly OverviewRoute[]; isAdmin: boolean }) {
  const columns: ReadonlyArray<Column<OverviewRoute>> = [
    {
      id: 'model',
      header: 'Model and backend',
      className: 'max-w-72',
      cell: (r) => (
        <>
          <MonoId value={r.model} className="text-bone" />
          <div className="flex min-w-0 items-baseline gap-1 pt-0.5 text-2xs whitespace-nowrap text-text-2">
            via <MonoId value={r.backend} />
          </div>
        </>
      ),
    },
    { id: 'provenance', header: 'Provenance', nowrap: true, cell: (r) => <StatusBadge domain="provenance" value={r.provenance} /> },
    {
      id: 'availability',
      header: 'Availability',
      cell: (r) => (
        <>
          <StatusBadge domain="availability" value={r.available ? 'available' : 'unavailable'} />
          {!r.available && r.reason ? <div className="mt-0.5 text-xs text-text-3">{r.reason}</div> : null}
        </>
      ),
    },
  ];
  return (
    <Section title="Route availability" open={{ href: toHash(paths.models), label: 'Open models' }} flush>
      {/* Under 640 px: checklist lines (model ..... backend [PROVENANCE] [AVAILABILITY]). */}
      {routes.length > 0 ? (
        <Checklist as="ul" ariaLabel="Route availability" className="px-3 py-1 sm:hidden">
          {routes.map((r) => (
            <ChecklistLine
              key={r.model}
              label={<MonoId value={r.model} className="text-xs" />}
              state={toneToStamp(toneFor('availability', r.available ? 'available' : 'unavailable'))}
              stamp={statusLabel(r.available ? 'available' : 'unavailable')}
              value={
                <span className="inline-flex flex-wrap items-center justify-end gap-x-2 gap-y-1">
                  <MonoId value={r.backend} />
                  <StatusBadge domain="provenance" value={r.provenance} />
                </span>
              }
              detail={!r.available && r.reason ? r.reason : undefined}
            />
          ))}
        </Checklist>
      ) : null}
      <DataTable
        className={routes.length > 0 ? 'max-sm:hidden' : undefined}
        caption="Route availability"
        columns={columns}
        rows={routes}
        rowKey={(r) => r.model}
        rowTone={(r) => (r.provenance === 'mismatch' ? 'bad' : r.available ? null : 'warn')}
        empty={
          <EmptyState title="No routes.">
            A route maps a public model name to a backend and a pinned artifact.{' '}
            {isAdmin ? 'Add one on the Models page.' : 'An admin can add one on the Models page.'}
          </EmptyState>
        }
      />
    </Section>
  );
}
