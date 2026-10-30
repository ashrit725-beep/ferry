/**
 * One verify or import job: progress in bytes, a status line announced to
 * screen readers (in 10 % steps, not on every 500 ms poll), and the result.
 */

import { useId } from 'react';
import type { JobResult } from '../api.ts';
import { formatBytes, plural } from '../format.ts';
import { displayState, isTrackedJobActive, jobPercent, jobStatusText, type TrackedJob } from '../jobstate.ts';
import { paths, toHash } from '../router.ts';
import { Callout } from './Panel.tsx';
import { ReportView } from './ReportView.tsx';
import { StatusBadge } from './StatusBadge.tsx';
import { Time } from './Time.tsx';

function ResultSummary({ kind, result }: { kind: string; result: JobResult }) {
  const report = result.report;
  if (result.verdict === 'accepted') {
    const href = kind === 'import' && result.bundle_id ? toHash(paths.bundle(result.bundle_id)) : null;
    return (
      <Callout tone="ok" title={kind === 'import' ? (result.already_imported ? 'Already imported' : 'Imported') : 'Verification passed'}>
        <p>
          {kind === 'import'
            ? result.already_imported
              ? 'This bundle was imported before; nothing changed.'
              : 'Artifacts are in the content-addressed store and can be routed on the Models page.'
            : 'Nothing was imported. Import the bundle to make its models available.'}
          {href ? (
            <>
              {' '}
              <a href={href}>Open the bundle</a>
            </>
          ) : null}
        </p>
      </Callout>
    );
  }
  return (
    <Callout tone="bad" title="Rejected">
      {report?.errors.length ? (
        <ul>
          {report.errors.slice(0, 8).map((e, i) => (
            <li key={i}>{e}</li>
          ))}
          {report.errors.length > 8 ? <li>{plural(report.errors.length - 8, 'more reason')} in the full report.</li> : null}
        </ul>
      ) : (
        <p>The report lists no reasons; open the full report for the failed checks.</p>
      )}
    </Callout>
  );
}

export function JobCard({ tracked, onDismiss }: { tracked: TrackedJob; onDismiss: () => void }) {
  const titleId = useId();
  const job = tracked.job;
  const state = displayState(tracked);
  const active = isTrackedJobActive(tracked);
  const done = job?.progress.bytes_done ?? 0;
  const total = job?.progress.bytes_total ?? null;
  const pct = jobPercent(done, total);
  const finished = job !== null && (job.state === 'succeeded' || job.state === 'failed');
  const bad = job?.state === 'failed' || job?.result?.verdict === 'rejected';
  const progressClass = finished ? (bad ? 'progress progress--bad' : 'progress progress--ok') : 'progress';

  return (
    <article className="job" aria-labelledby={titleId}>
      <div className="job__title" id={titleId}>
        <span className="tag">{tracked.kind === 'import' ? 'Import' : 'Verify'}</span>
        <code className="break">{tracked.sourceName}</code>
      </div>
      <div className="row">
        {job?.result ? <StatusBadge domain="verdict" value={job.result.verdict} /> : <StatusBadge domain="job" value={state} />}
        {!active ? (
          <button type="button" className="button button--small button--ghost" onClick={onDismiss}>
            Dismiss
          </button>
        ) : null}
      </div>
      <div className="job__progress">
        {finished ? (
          <progress className={progressClass} max={1} value={1} aria-labelledby={titleId} />
        ) : (
          <progress
            className={progressClass}
            max={total !== null && total > 0 ? total : undefined}
            value={total !== null && total > 0 ? Math.min(done, total) : undefined}
            aria-labelledby={titleId}
          />
        )}
        <p className="job__meta">
          {total !== null && total > 0 ? (
            <>
              {formatBytes(done)} of {formatBytes(total)}
              {pct !== null ? ` · ${pct}%` : ''}
            </>
          ) : (
            <>{formatBytes(done)} read</>
          )}
          {job?.started_at ? (
            <>
              {' · started '}
              <Time value={job.started_at} />
            </>
          ) : null}
          {job?.finished_at ? (
            <>
              {' · finished '}
              <Time value={job.finished_at} />
            </>
          ) : null}
        </p>
        <p className="job__status" role="status">
          {jobStatusText(tracked)}
        </p>
      </div>
      {tracked.problem ? (
        <p className="job__problem" role="alert">
          {tracked.problem}
        </p>
      ) : null}
      {job?.error ? (
        <div className="job__report">
          <Callout tone="bad" title="The job failed">
            <p>{job.error}</p>
          </Callout>
        </div>
      ) : null}
      {job?.result ? (
        <div className="job__report stack stack--tight">
          <ResultSummary kind={tracked.kind} result={job.result} />
          {job.result.report ? (
            <details className="disclosure">
              <summary>Full verification report</summary>
              <ReportView report={job.result.report} />
            </details>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
