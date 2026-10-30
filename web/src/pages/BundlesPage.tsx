/**
 * Bundles: the inbox (verify or import, with live job progress), imported
 * bundles, verification history and the trust store the checks run against.
 */

import { useCallback, useState } from 'react';
import {
  api,
  type BundleSummary,
  type Inbox,
  type InboxItem,
  type JobKind,
  type TrustStore,
  type VerificationSummary,
} from '../api.ts';
import { formatBytes, formatInt, plural } from '../format.ts';
import { useResource } from '../hooks.ts';
import { isTrackedJobActive, useJobFinished, useJobs } from '../jobs.tsx';
import { paths, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { Digest, KeyId } from '../components/Digest.tsx';
import { JobCard } from '../components/JobCard.tsx';
import { Callout, DefList, PageHeader, Panel, RefreshButton } from '../components/Panel.tsx';
import { Async, EmptyState, InlineError } from '../components/States.tsx';
import { StatusBadge } from '../components/StatusBadge.tsx';
import { Time } from '../components/Time.tsx';

const HISTORY_STEP = 50;

interface StartFailure {
  kind: JobKind;
  name: string;
  error: unknown;
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

  const reloadInbox = inbox.reload;
  const reloadBundles = bundles.reload;
  const reloadHistory = history.reload;
  useJobFinished(
    useCallback(() => {
      reloadInbox();
      reloadBundles();
      reloadHistory();
    }, [reloadInbox, reloadBundles, reloadHistory]),
  );

  const refreshAll = (): void => {
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

  return (
    <>
      <PageHeader
        title="Bundles"
        description="Bundles are verified against the trust store and the import policy before anything is copied into the store. A rejected bundle changes nothing."
        actions={
          <RefreshButton onClick={refreshAll} busy={inbox.refreshing || bundles.refreshing || history.refreshing || trust.refreshing} />
        }
      />
      <div className="stack">
        {jobs.length > 0 ? (
          <Panel title="Jobs started from this console" description="Status is kept in this browser tab only; results are recorded by the server.">
            <div className="jobs">
              {jobs.map((j) => (
                <JobCard key={j.jobId} tracked={j} onDismiss={() => dismiss(j.jobId)} />
              ))}
            </div>
          </Panel>
        ) : null}

        <Panel
          title="Inbox"
          description={inbox.data ? <>Waiting in <code>{inbox.data.inbox_dir}</code> on the server.</> : null}
          flush
        >
          {failure ? (
            <div className="panel-inset">
              <InlineError
                error={failure.error}
                prefix={`Could not start ${failure.kind === 'import' ? 'the import' : 'verification'} of ${failure.name}.`}
              />
            </div>
          ) : null}
          <Async resource={inbox} loadingLabel="Reading the inbox…">
            {(data) => <InboxTable inbox={data} isAdmin={isAdmin} busyNames={busyNames} starting={starting} onRun={run} />}
          </Async>
        </Panel>

        <Panel title="Imported bundles" flush>
          <Async resource={bundles} loadingLabel="Loading imported bundles…">
            {(items) => <BundlesTable bundles={items} />}
          </Async>
        </Panel>

        <Panel
          title="Verification history"
          description="Every verify and import, accepted or rejected, newest first."
          flush
          footer={
            history.data && history.data.length >= historyLimit ? (
              <button type="button" className="button button--small" onClick={() => setHistoryLimit((n) => n + HISTORY_STEP * 3)}>
                Show more
              </button>
            ) : null
          }
        >
          <Async resource={history} loadingLabel="Loading verification history…">
            {(items) => <HistoryTable items={items} />}
          </Async>
        </Panel>

        <Panel title="Trust store" description="Keys allowed to sign bundles. They are managed on the host with ferry trust, never from the console.">
          <Async resource={trust} loadingLabel="Loading the trust store…">
            {(data) => <TrustView trust={data} />}
          </Async>
        </Panel>
      </div>
    </>
  );
}

function InboxTable({
  inbox,
  isAdmin,
  busyNames,
  starting,
  onRun,
}: {
  inbox: Inbox;
  isAdmin: boolean;
  busyNames: ReadonlySet<string>;
  starting: string | null;
  onRun: (kind: JobKind, name: string) => Promise<void>;
}) {
  if (inbox.items.length === 0) {
    return (
      <EmptyState title="No bundles in the inbox.">
        Copy a <code>.ferry.tar</code> file (or an extracted bundle directory) into <code>{inbox.inbox_dir}</code> on the
        server, then refresh this page.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Bundles in the inbox</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Type</th>
            <th scope="col" className="num">
              Size
            </th>
            <th scope="col">Modified</th>
            <th scope="col">Last verification</th>
            {isAdmin ? (
              <th scope="col" className="actions">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {inbox.items.map((item) => (
            <InboxRow key={item.name} item={item} isAdmin={isAdmin} busy={busyNames.has(item.name)} starting={starting} onRun={onRun} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function InboxRow({
  item,
  isAdmin,
  busy,
  starting,
  onRun,
}: {
  item: InboxItem;
  isAdmin: boolean;
  busy: boolean;
  starting: string | null;
  onRun: (kind: JobKind, name: string) => Promise<void>;
}) {
  const last = item.last_verification;
  const blocked = busy || starting !== null;
  const action = (kind: JobKind, label: string, primary: boolean) => (
    <button
      type="button"
      className={primary ? 'button button--small button--primary' : 'button button--small'}
      aria-disabled={blocked || undefined}
      aria-label={`${label} ${item.name}`}
      onClick={() => {
        if (!blocked) void onRun(kind, item.name);
      }}
    >
      {starting === `${kind}:${item.name}` ? 'Starting…' : label}
    </button>
  );
  return (
    <tr>
      <td className="break">
        <code>{item.name}</code>
      </td>
      <td>
        <span className="tag">{item.type}</span>
      </td>
      <td className="num" title={item.size !== null ? `${item.size} bytes` : undefined}>
        {formatBytes(item.size)}
      </td>
      <td>
        <Time value={item.modified_at} />
      </td>
      <td>
        {last ? (
          <span className="row row--nowrap">
            <StatusBadge domain="verdict" value={last.verdict} />
            <Time value={last.created_at} />
          </span>
        ) : (
          <span className="subtle">never verified</span>
        )}
      </td>
      {isAdmin ? (
        <td className="actions">
          <div className="row">
            {busy ? <span className="cell-note">job running</span> : null}
            {action('verify', 'Verify', false)}
            {action('import', 'Import', true)}
          </div>
        </td>
      ) : null}
    </tr>
  );
}

function Signers({ signers }: { signers: BundleSummary['signers'] }) {
  if (signers.length === 0) return <span className="subtle">none recorded</span>;
  return (
    <ul className="signer-list">
      {signers.map((s) => (
        <li key={s.key_id}>
          <span>{s.name ?? <KeyId value={s.key_id} />}</span>
          {s.roles.map((r) => (
            <span key={r} className="tag">
              {r}
            </span>
          ))}
        </li>
      ))}
    </ul>
  );
}

function BundlesTable({ bundles }: { bundles: readonly BundleSummary[] }) {
  if (bundles.length === 0) {
    return (
      <EmptyState title="No bundles imported yet.">
        Import one from the inbox above, or on the host with <code>ferry import BUNDLE</code>.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Imported bundles</caption>
        <thead>
          <tr>
            <th scope="col">Bundle</th>
            <th scope="col">Bundle id</th>
            <th scope="col">Signers</th>
            <th scope="col" className="num">
              Artifacts
            </th>
            <th scope="col" className="num">
              Size
            </th>
            <th scope="col">Imported</th>
          </tr>
        </thead>
        <tbody>
          {bundles.map((b) => (
            <tr key={b.bundle_id}>
              <td>
                <a href={toHash(paths.bundle(b.bundle_id))}>
                  {b.name} <span className="mono">{b.version}</span>
                </a>
                <div className="cell-note">
                  from <code>{b.source_name}</code>
                </div>
              </td>
              <td className="nowrap">
                <Digest value={b.bundle_id} label={`bundle id of ${b.name} ${b.version}`} />
              </td>
              <td>
                <Signers signers={b.signers} />
              </td>
              <td className="num">{formatInt(b.artifact_count)}</td>
              <td className="num" title={`${b.total_bytes} bytes`}>
                {formatBytes(b.total_bytes)}
              </td>
              <td>
                <Time value={b.imported_at} />
                <div className="cell-note">by {b.imported_by}</div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HistoryTable({ items }: { items: readonly VerificationSummary[] }) {
  if (items.length === 0) {
    return <EmptyState title="No verifications recorded yet.">Verify or import a bundle from the inbox to create the first record.</EmptyState>;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Verification history</caption>
        <thead>
          <tr>
            <th scope="col" className="num">
              #
            </th>
            <th scope="col">Recorded</th>
            <th scope="col">Source</th>
            <th scope="col">Bundle</th>
            <th scope="col">Mode</th>
            <th scope="col">Verdict</th>
            <th scope="col" className="num">
              Errors
            </th>
            <th scope="col" className="num">
              Warnings
            </th>
            <th scope="col">Actor</th>
          </tr>
        </thead>
        <tbody>
          {items.map((v) => (
            <tr key={v.id}>
              <td className="num">
                <a href={toHash(paths.verification(v.id))} aria-label={`Verification ${v.id}: ${v.verdict}, ${v.source_name}`}>
                  {v.id}
                </a>
              </td>
              <td>
                <Time value={v.created_at} />
              </td>
              <td className="break">
                <code>{v.source_name}</code>
              </td>
              <td>
                {v.bundle_name ? (
                  <>
                    {v.bundle_name} <span className="mono">{v.bundle_version ?? ''}</span>
                  </>
                ) : (
                  <span className="subtle">unreadable manifest</span>
                )}
              </td>
              <td>
                <span className="tag">{v.mode}</span>
              </td>
              <td>
                <StatusBadge domain="verdict" value={v.verdict} />
              </td>
              <td className="num">{formatInt(v.error_count)}</td>
              <td className="num">{formatInt(v.warning_count)}</td>
              <td className="break">{v.actor}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TrustView({ trust }: { trust: TrustStore }) {
  const active = trust.items.filter((k) => k.status === 'active').length;
  return (
    <div className="stack stack--tight">
      <DefList
        items={[
          ['Directory', <code>{trust.trust_dir}</code>],
          [
            'Required roles',
            <span className="inline-list">
              {trust.required_roles.map((r) => (
                <span key={r} className="tag">
                  {r}
                </span>
              ))}
            </span>,
          ],
          ['Distinct signers', trust.distinct_signers ? 'yes, one key cannot satisfy two roles' : 'no, one key may satisfy several roles'],
          ['Keys', `${plural(trust.items.length, 'key')}, ${formatInt(active)} active`],
        ]}
      />
      {trust.problems.length ? (
        <Callout tone="warn" title="Trust store problems">
          <ul>
            {trust.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </Callout>
      ) : null}
      {trust.items.length === 0 ? (
        <Callout tone="warn" title="No trusted signing keys">
          <p>
            Every bundle is rejected until a publisher key is trusted. On the host:{' '}
            <code>ferry trust add KEY.pub.pem --name NAME --role publisher</code>
          </p>
        </Callout>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <caption className="sr-only">Trusted signing keys</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Key id</th>
                <th scope="col">Roles</th>
                <th scope="col">Status</th>
                <th scope="col">Valid from</th>
                <th scope="col">Valid until</th>
              </tr>
            </thead>
            <tbody>
              {trust.items.map((k) => (
                <tr key={k.key_id}>
                  <td>{k.name || <span className="subtle">unnamed</span>}</td>
                  <td className="nowrap">
                    <KeyId value={k.key_id} />
                  </td>
                  <td>
                    <span className="inline-list">
                      {k.roles.map((r) => (
                        <span key={r} className="tag">
                          {r}
                        </span>
                      ))}
                    </span>
                  </td>
                  <td>
                    <StatusBadge domain="trust" value={k.status} />
                    {k.revoked_at ? (
                      <div className="cell-note">
                        revoked <Time value={k.revoked_at} />
                        {k.revocation_reason ? `: ${k.revocation_reason}` : ''}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <Time value={k.not_before} fallback="any time" future />
                  </td>
                  <td>
                    <Time value={k.not_after} fallback="no expiry" future />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
