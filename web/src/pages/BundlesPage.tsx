/**
 * Bundles: the inbox (verify or import, with live job progress), imported
 * bundles, verification history and the trust store the checks run against.
 * New verification records rerank into the history in place and hold their
 * amber tint until the operator opens them or refreshes.
 */

import { useCallback, useState, type ReactNode } from 'react';
import { toast } from 'sonner';
import {
  api,
  type BundleSummary,
  type Inbox,
  type InboxItem,
  type Job,
  type JobKind,
  type TrustKey,
  type TrustStore,
  type VerificationSummary,
} from '../api.ts';
import { formatBytes, formatInt, plural } from '../format.ts';
import type { Resource } from '../hooks.ts';
import { useResource } from '../hooks.ts';
import { isTrackedJobActive, useJobFinished, useJobs, type TrackedJob } from '../jobs.tsx';
import { paths, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { Callout, RefreshButton } from '@/components/console/callout.tsx';
import { Checklist, ChecklistLine } from '@/components/console/checklist.tsx';
import { DataTable, type Column } from '@/components/console/data-table.tsx';
import { Digest, KeyId, MonoId, PathText } from '@/components/console/digest.tsx';
import { JobCard } from '@/components/console/job-card.tsx';
import { KeyValueList } from '@/components/console/key-value-list.tsx';
import { PageHeader } from '@/components/console/page-header.tsx';
import { Section } from '@/components/console/section.tsx';
import { Stamp } from '@/components/console/stamp.tsx';
import { EmptyState, InlineError, PanelSkeleton, Spinner } from '@/components/console/states.tsx';
import { StatusBadge } from '@/components/console/status-badge.tsx';
import { Time } from '@/components/console/time.tsx';
import { Button } from '@/components/ui/button.tsx';

const HISTORY_STEP = 50;
/** Rerank animates rows by identity; past this many rows they swap in place. */
const RERANK_MAX = 60;

interface StartFailure {
  kind: JobKind;
  name: string;
  error: unknown;
}

function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-block rounded-sm border border-line-control/50 px-1 text-2xs whitespace-nowrap text-text-2">{children}</span>;
}

function Roles({ roles }: { roles: readonly string[] }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {roles.map((r) => (
        <Tag key={r}>{r}</Tag>
      ))}
    </span>
  );
}

/** The stale-data banner and the screen-reader loading text around a DataTable. */
function TableFrame<T>({ resource, loadingLabel, children }: { resource: Resource<T>; loadingLabel: string; children: ReactNode }) {
  return (
    <>
      {resource.data !== null && resource.error ? (
        <div className="border-b border-hairline px-3 py-2">
          <InlineError error={resource.error} prefix="Could not refresh; showing the last data loaded." onRetry={resource.reload} />
        </div>
      ) : null}
      {resource.data === null && resource.loading ? (
        <p role="status" className="sr-only">
          {loadingLabel}
        </p>
      ) : null}
      {children}
    </>
  );
}

function maxId(items: readonly VerificationSummary[] | null): number {
  return (items ?? []).reduce((m, v) => Math.max(m, v.id), 0);
}

function jobSubject(tracked: TrackedJob): string {
  return `${tracked.kind === 'import' ? 'Import' : 'Verification'} of ${tracked.sourceName}`;
}

/** A finished job is a committed result: say so once, beside the card that holds the detail. */
function announceFinished(job: Job, tracked: TrackedJob): void {
  if (job.state === 'failed') {
    toast.error(`${jobSubject(tracked)} failed`, { description: job.error ?? 'The job card lists what the server reported.', duration: Infinity });
    return;
  }
  const result = job.result;
  if (!result) return;
  if (result.verdict === 'accepted') {
    const title =
      tracked.kind === 'import'
        ? result.already_imported
          ? `${tracked.sourceName} was already imported`
          : `Imported ${tracked.sourceName}`
        : `Verified ${tracked.sourceName}`;
    toast.success(title, { description: result.bundle_id ?? undefined });
    return;
  }
  toast.error(`${jobSubject(tracked)}: rejected`, {
    description: result.report?.errors[0] ?? 'Open the full report on the job card for the failed checks.',
    duration: Infinity,
  });
}

export function BundlesPage() {
  const { isAdmin } = useSession();
  const { jobs, start, dismiss } = useJobs();
  const inbox = useResource((s) => api.inbox(s), []);
  const bundles = useResource((s) => api.bundles(s), []);
  const [historyLimit, setHistoryLimit] = useState(HISTORY_STEP);
  const history = useResource((s) => api.verifications(historyLimit, s), [historyLimit]);
  const trust = useResource((s) => api.trust(s), []);
  const [starting, setStarting] = useState<string | null>(null);
  const [failure, setFailure] = useState<StartFailure | null>(null);

  // History acknowledgement: records above `ackUpTo` arrived while the page
  // was open (a job finished) and stay amber until opened or refreshed.
  const [ackUpTo, setAckUpTo] = useState<number | null>(null);
  const [ackOnNext, setAckOnNext] = useState(false);
  const [opened, setOpened] = useState<ReadonlySet<number>>(() => new Set());
  const [seen, setSeen] = useState<readonly VerificationSummary[] | null>(null);
  if (history.data !== seen) {
    setSeen(history.data);
    if (history.data && (ackUpTo === null || ackOnNext)) {
      setAckUpTo(maxId(history.data));
      setAckOnNext(false);
    }
  }
  const isNew = (v: VerificationSummary): boolean => ackUpTo !== null && v.id > ackUpTo && !opened.has(v.id);
  const newCount = (history.data ?? []).filter(isNew).length;

  const reloadInbox = inbox.reload;
  const reloadBundles = bundles.reload;
  const reloadHistory = history.reload;
  useJobFinished(
    useCallback(
      (job: Job, tracked: TrackedJob) => {
        reloadInbox();
        reloadBundles();
        reloadHistory();
        announceFinished(job, tracked);
      },
      [reloadInbox, reloadBundles, reloadHistory],
    ),
  );

  const refreshAll = (): void => {
    setAckUpTo(maxId(history.data));
    setAckOnNext(true);
    inbox.reload();
    bundles.reload();
    history.reload();
    trust.reload();
  };

  const run = async (kind: JobKind, name: string): Promise<void> => {
    setStarting(`${kind}:${name}`);
    setFailure(null);
    try {
      await start(kind, name);
    } catch (error) {
      setFailure({ kind, name, error });
    } finally {
      setStarting(null);
    }
  };

  const busyNames = new Set(jobs.filter(isTrackedJobActive).map((j) => j.sourceName));
  const activeCount = jobs.filter(isTrackedJobActive).length;

  return (
    <>
      <PageHeader
        title="Bundles"
        description="Bundles are verified against the trust store and the import policy before anything is copied into the store. A rejected bundle changes nothing."
        actions={<RefreshButton onClick={refreshAll} busy={inbox.refreshing || bundles.refreshing || history.refreshing || trust.refreshing} />}
      />
      <div className="flex flex-col gap-4">
        {jobs.length > 0 ? (
          <Section
            title="Jobs started from this console"
            description="Status is kept in this browser tab only; results are recorded by the server."
            actions={
              activeCount > 0 ? (
                <Stamp state="pending" running>
                  {plural(activeCount, 'job')} running
                </Stamp>
              ) : null
            }
            attention={activeCount > 0}
          >
            <div className="flex flex-col gap-2">
              {jobs.map((j) => (
                <JobCard key={j.jobId} tracked={j} onDismiss={() => dismiss(j.jobId)} />
              ))}
            </div>
          </Section>
        ) : null}

        <Section
          title="Inbox"
          description={
            inbox.data ? (
              <>
                Waiting in <PathText value={inbox.data.inbox_dir} className="text-bone" /> on the server.
              </>
            ) : null
          }
          actions={inbox.data ? <span className="text-xs text-text-3 tabular-nums">{plural(inbox.data.items.length, 'item')}</span> : null}
          flush
        >
          {failure ? (
            <div className="border-b border-hairline px-3 py-2">
              <InlineError error={failure.error} prefix={`Could not start ${failure.kind === 'import' ? 'the import' : 'verification'} of ${failure.name}.`} />
            </div>
          ) : null}
          <TableFrame resource={inbox} loadingLabel="Reading the inbox…">
            <InboxTable resource={inbox} imported={bundles.data} isAdmin={isAdmin} busyNames={busyNames} starting={starting} onRun={run} />
          </TableFrame>
        </Section>

        <Section
          title="Imported bundles"
          actions={bundles.data ? <span className="text-xs text-text-3 tabular-nums">{plural(bundles.data.length, 'bundle')}</span> : null}
          flush
        >
          <TableFrame resource={bundles} loadingLabel="Loading imported bundles…">
            <DataTable
              columns={BUNDLE_COLUMNS}
              rows={bundles.data}
              rowKey={(b) => b.bundle_id}
              caption="Imported bundles"
              loading={bundles.loading}
              error={bundles.error}
              onRetry={bundles.reload}
              skeletonRows={3}
              empty={
                <EmptyState title="No bundles imported yet.">
                  Import one from the inbox above, or on the host with <code className="font-mono">ferry import BUNDLE</code>.
                </EmptyState>
              }
            />
          </TableFrame>
        </Section>

        <Section
          title="Verification history"
          description="Every verify and import, accepted or rejected, newest first."
          actions={
            newCount > 0 ? (
              <Stamp state="pending" title="New since this page loaded; open a record or refresh to acknowledge.">
                {formatInt(newCount)} new
              </Stamp>
            ) : null
          }
          attention={newCount > 0}
          flush
          footer={
            history.data && history.data.length >= historyLimit ? (
              <Button type="button" variant="outline" size="sm" onClick={() => setHistoryLimit((n) => n + HISTORY_STEP * 3)}>
                Show more
              </Button>
            ) : null
          }
        >
          <p role="status" className="sr-only">
            {newCount > 0 ? `${plural(newCount, 'new verification record')} in the history.` : ''}
          </p>
          <TableFrame resource={history} loadingLabel="Loading verification history…">
            <DataTable
              columns={historyColumns((id) => setOpened((s) => new Set(s).add(id)))}
              rows={history.data}
              rowKey={(v) => String(v.id)}
              caption="Verification history"
              loading={history.loading}
              error={history.error}
              onRetry={history.reload}
              rerank={(history.data?.length ?? 0) <= RERANK_MAX}
              rowTone={(v) => (isNew(v) ? (v.verdict === 'rejected' ? 'bad' : 'warn') : null)}
              held={isNew}
              empty={<EmptyState title="No verifications recorded yet.">Verify or import a bundle from the inbox to create the first record.</EmptyState>}
            />
          </TableFrame>
        </Section>

        <Section title="Trust store" description="Keys allowed to sign bundles. They are managed on the host with ferry trust, never from the console.">
          {trust.data ? (
            <div className="flex flex-col gap-3">
              {trust.error ? <InlineError error={trust.error} prefix="Could not refresh; showing the last data loaded." onRetry={trust.reload} /> : null}
              <TrustView trust={trust.data} />
            </div>
          ) : trust.error ? (
            <InlineError error={trust.error} prefix="Could not load this data." onRetry={trust.reload} />
          ) : (
            <>
              <p role="status" className="sr-only">
                Loading the trust store…
              </p>
              <PanelSkeleton lines={4} className="px-0 py-0" />
            </>
          )}
        </Section>
      </div>
    </>
  );
}

function InboxTable({
  resource,
  imported,
  isAdmin,
  busyNames,
  starting,
  onRun,
}: {
  resource: Resource<Inbox>;
  /** Imported bundles, to tell an inbox file already imported from one still waiting. */
  imported: readonly BundleSummary[] | null;
  isAdmin: boolean;
  busyNames: ReadonlySet<string>;
  starting: string | null;
  onRun: (kind: JobKind, name: string) => Promise<void>;
}) {
  const inbox = resource.data;
  const importedAs = (i: InboxItem): BundleSummary | null => {
    const id = i.last_verification?.bundle_id;
    if (!id || !imported) return null;
    return imported.find((b) => b.bundle_id === id) ?? null;
  };
  const columns: Column<InboxItem>[] = [
    {
      id: 'name',
      header: 'Name',
      className: 'max-w-56 xl:max-w-80',
      sortValue: (i) => i.name,
      cell: (i) => (
        <>
          <MonoId value={i.name} tail={14} className="text-bone" />
          <div className="flex flex-wrap items-center gap-x-1.5 pt-0.5 text-2xs text-text-2">
            <Tag>{i.type}</Tag>
            <span className="tabular-nums" title={i.size !== null ? `${i.size} bytes` : undefined}>
              {formatBytes(i.size)}
            </span>
            <span aria-hidden="true">·</span>
            <span className="whitespace-nowrap">
              modified <Time value={i.modified_at} />
            </span>
          </div>
        </>
      ),
    },
    {
      id: 'last',
      header: 'Last verification',
      className: 'max-w-56 xl:max-w-72',
      cell: (i) => {
        const done = importedAs(i);
        if (done) {
          return (
            <span className="flex min-w-0 flex-col gap-0.5">
              <span className="inline-flex items-center gap-2 whitespace-nowrap">
                <Stamp state="confirmed">Imported</Stamp>
                <Time value={i.last_verification?.created_at ?? null} />
              </span>
              <span className="flex min-w-0 items-baseline gap-1 text-2xs whitespace-nowrap text-text-3">
                as{' '}
                <a
                  href={toHash(paths.bundle(done.bundle_id))}
                  className="inline-flex min-w-0 rounded-sm text-text-2 underline decoration-text-3 underline-offset-3 hover:text-bone"
                >
                  <MonoId value={`${done.name} ${done.version}`} />
                </a>
              </span>
            </span>
          );
        }
        return i.last_verification ? (
          <span className="inline-flex items-center gap-2 whitespace-nowrap">
            <StatusBadge domain="verdict" value={i.last_verification.verdict} />
            <Time value={i.last_verification.created_at} />
          </span>
        ) : (
          <span className="text-text-3">never verified</span>
        );
      },
    },
  ];
  if (isAdmin) {
    columns.push({
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'right',
      nowrap: true,
      cell: (i) => <InboxActions item={i} imported={importedAs(i) !== null} busy={busyNames.has(i.name)} starting={starting} onRun={onRun} />,
    });
  }
  return (
    <DataTable
      columns={columns}
      rows={inbox ? inbox.items : null}
      rowKey={(i) => i.name}
      caption="Bundles in the inbox"
      loading={resource.loading}
      error={resource.error}
      onRetry={resource.reload}
      skeletonRows={3}
      rowProps={(i) => (busyNames.has(i.name) ? { className: 'bg-amber-subtle/40' } : {})}
      empty={
        <EmptyState title="No bundles in the inbox.">
          Copy a <code className="font-mono">.ferry.tar</code> file (or an extracted bundle directory) into{' '}
          <code className="font-mono">{inbox?.inbox_dir ?? 'the inbox directory'}</code> on the server, then refresh this page.
        </EmptyState>
      }
    />
  );
}

function InboxActions({
  item,
  imported,
  busy,
  starting,
  onRun,
}: {
  item: InboxItem;
  imported: boolean;
  busy: boolean;
  starting: string | null;
  onRun: (kind: JobKind, name: string) => Promise<void>;
}) {
  const blocked = busy || starting !== null;
  const action = (kind: JobKind, label: string, primary: boolean) => (
    <Button
      type="button"
      size="sm"
      variant={primary ? 'attention' : 'outline'}
      aria-disabled={blocked || undefined}
      aria-label={`${label} ${item.name}`}
      className={blocked ? 'cursor-not-allowed opacity-50' : undefined}
      onClick={() => {
        if (!blocked) void onRun(kind, item.name);
      }}
    >
      {starting === `${kind}:${item.name}` ? 'Starting…' : label}
    </Button>
  );
  return (
    <span className="inline-flex items-center justify-end gap-2">
      {busy ? (
        <span className="inline-flex items-center gap-1 text-2xs text-text-2">
          <Spinner />
          job running
        </span>
      ) : null}
      {action('verify', 'Verify', false)}
      {action('import', 'Import', !imported)}
    </span>
  );
}

const BUNDLE_COLUMNS: ReadonlyArray<Column<BundleSummary>> = [
  {
    id: 'bundle',
    header: 'Bundle',
    className: 'max-w-56 xl:max-w-80',
    sortValue: (b) => `${b.name} ${b.version}`,
    cell: (b) => (
      <div className="flex min-w-0 flex-col gap-0.5">
        <a
          href={toHash(paths.bundle(b.bundle_id))}
          className="inline-flex max-w-full rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone"
        >
          <MonoId value={`${b.name} ${b.version}`} />
        </a>
        <span className="flex min-w-0 items-baseline gap-1 text-2xs whitespace-nowrap text-text-3">
          from <MonoId value={b.source_name} tail={14} />
        </span>
      </div>
    ),
  },
  { id: 'id', header: 'Bundle id', nowrap: true, cell: (b) => <Digest value={b.bundle_id} label={`bundle id of ${b.name} ${b.version}`} /> },
  {
    id: 'signers',
    header: 'Signers',
    cell: (b) =>
      b.signers.length === 0 ? (
        <span className="text-text-3">none recorded</span>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
          {b.signers.map((s) => (
            <li key={s.key_id} className="flex flex-wrap items-center gap-1">
              <span className="whitespace-nowrap">{s.name ?? <KeyId value={s.key_id} />}</span>
              <Roles roles={s.roles} />
            </li>
          ))}
        </ul>
      ),
  },
  {
    id: 'contents',
    header: 'Contents and import',
    label: 'Contents',
    nowrap: true,
    sortValue: (b) => b.imported_at,
    cell: (b) => (
      <div className="flex flex-col gap-0.5">
        <span className="tabular-nums">
          {plural(b.artifact_count, 'artifact')} · <span title={`${b.total_bytes} bytes`}>{formatBytes(b.total_bytes)}</span>
        </span>
        <span className="text-2xs text-text-3">
          imported <Time value={b.imported_at} /> by {b.imported_by}
        </span>
      </div>
    ),
  },
];

function historyColumns(onOpen: (id: number) => void): ReadonlyArray<Column<VerificationSummary>> {
  return [
    {
      id: 'id',
      header: '#',
      align: 'right',
      nowrap: true,
      cell: (v) => (
        <a
          href={toHash(paths.verification(v.id))}
          aria-label={`Verification ${v.id}: ${v.verdict}, ${v.source_name}`}
          onClick={() => onOpen(v.id)}
          className="font-mono rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone"
        >
          {v.id}
        </a>
      ),
    },
    {
      id: 'bundle',
      header: 'Bundle and source',
      label: 'Bundle',
      className: 'max-w-56 xl:max-w-80',
      cell: (v) => (
        <div className="flex min-w-0 flex-col gap-0.5">
          {v.bundle_name ? <MonoId value={`${v.bundle_name} ${v.bundle_version ?? ''}`.trim()} /> : <span className="text-text-3">unreadable manifest</span>}
          <span className="flex min-w-0 items-baseline gap-1 text-2xs whitespace-nowrap text-text-3">
            from <MonoId value={v.source_name} tail={14} />
          </span>
        </div>
      ),
    },
    {
      id: 'verdict',
      header: 'Verdict',
      nowrap: true,
      cell: (v) => (
        <>
          <StatusBadge domain="verdict" value={v.verdict} />
          <div className="pt-0.5 text-2xs text-text-2 tabular-nums">
            {plural(v.error_count, 'error')} · {plural(v.warning_count, 'warning')}
          </div>
        </>
      ),
    },
    { id: 'mode', header: 'Mode', nowrap: true, cell: (v) => <Tag>{v.mode}</Tag> },
    {
      id: 'recorded',
      header: 'Recorded',
      nowrap: true,
      cell: (v) => (
        <>
          <Time value={v.created_at} />
          <div className="pt-0.5 text-2xs text-text-3">by {v.actor}</div>
        </>
      ),
    },
  ];
}

const KEY_COLUMNS: ReadonlyArray<Column<TrustKey>> = [
  { id: 'name', header: 'Name', sortValue: (k) => k.name, cell: (k) => k.name || <span className="text-text-3">unnamed</span> },
  { id: 'key', header: 'Key id', nowrap: true, cell: (k) => <KeyId value={k.key_id} /> },
  { id: 'roles', header: 'Roles', cell: (k) => <Roles roles={k.roles} /> },
  {
    id: 'status',
    header: 'Status',
    sortValue: (k) => k.status,
    cell: (k) => (
      <div className="flex flex-col items-start gap-0.5">
        <StatusBadge domain="trust" value={k.status} />
        {k.revoked_at ? (
          <span className="text-2xs text-text-3">
            revoked <Time value={k.revoked_at} />
            {k.revocation_reason ? `: ${k.revocation_reason}` : ''}
          </span>
        ) : null}
      </div>
    ),
  },
  { id: 'from', header: 'Valid from', nowrap: true, cell: (k) => <Time value={k.not_before} fallback="any time" future /> },
  { id: 'until', header: 'Valid until', nowrap: true, cell: (k) => <Time value={k.not_after} fallback="no expiry" future /> },
];

function TrustView({ trust }: { trust: TrustStore }) {
  const active = trust.items.filter((k) => k.status === 'active').length;
  const none = trust.items.length === 0;
  return (
    <div className="flex flex-col gap-3">
      <KeyValueList items={[['Directory', <PathText value={trust.trust_dir} className="text-xs" />]]} />
      <Checklist ariaLabel="Trust store checks">
        <ChecklistLine
          label="Trusted signing keys"
          state={none ? 'failed' : active === 0 ? 'warning' : 'confirmed'}
          value={`${plural(trust.items.length, 'key')} · ${formatInt(active)} active`}
          stamp={none ? 'None trusted' : active === 0 ? 'None active' : 'Trusted'}
          detail={
            none ? (
              <>
                Every bundle is rejected until a publisher key is trusted. On the host:{' '}
                <code className="font-mono text-bone">ferry trust add KEY.pub.pem --name NAME --role publisher</code>
              </>
            ) : undefined
          }
        />
        <ChecklistLine
          label="Required roles"
          state={trust.required_roles.length ? 'info' : 'neutral'}
          value={trust.required_roles.length ? trust.required_roles.join(', ') : 'none'}
          stamp="Required"
        />
        <ChecklistLine
          label="Distinct signers"
          state={trust.distinct_signers ? 'confirmed' : 'warning'}
          stamp={trust.distinct_signers ? 'Enforced' : 'Not enforced'}
          detail={trust.distinct_signers ? 'Yes, one key cannot satisfy two roles.' : 'No, one key may satisfy several roles.'}
        />
        {trust.problems.length ? (
          <ChecklistLine label="Trust store problems" state="warning" value={formatInt(trust.problems.length)} stamp={plural(trust.problems.length, 'problem')} />
        ) : null}
      </Checklist>
      {trust.problems.length ? (
        <Callout tone="warn" title="Trust store problems">
          <ul>
            {trust.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </Callout>
      ) : null}
      {none ? null : (
        <div className="overflow-hidden rounded-sm border border-hairline">
          <DataTable
            columns={KEY_COLUMNS}
            rows={trust.items}
            rowKey={(k) => k.key_id}
            caption="Trusted signing keys"
            rowProps={(k) => (k.status === 'active' ? {} : { className: '[&>td]:text-text-3' })}
          />
        </div>
      )}
    </div>
  );
}
