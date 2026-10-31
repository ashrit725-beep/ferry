/**
 * One verify or import job: progress in bytes, a status line announced to
 * screen readers (in 10 % steps, not on every 500 ms poll), and the result.
 * An active job carries an amber hairline; the progress bar and status text
 * carry the running state (no ambient loop).
 */

import { useId } from 'react';
import { ChevronDown } from 'lucide-react';
import type { JobResult } from '../../api.ts';
import { formatBytes, plural } from '../../format.ts';
import { displayState, isTrackedJobActive, jobPercent, jobStatusText, type TrackedJob } from '../../jobstate.ts';
import { paths, toHash } from '../../router.ts';
import { Button } from '../ui/button.tsx';
import { Progress } from '../ui/progress.tsx';
import { Callout } from './callout.tsx';
import { ReportView } from './report-view.tsx';
import { StatusBadge } from './status-badge.tsx';
import { Time } from './time.tsx';
import { cn } from '@/lib/utils';

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
              <a href={href} className="underline underline-offset-3 hover:text-amber">
                Open the bundle
              </a>
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
  const fill = finished ? 1 : total !== null && total > 0 ? Math.min(done, total) / total : null;

  return (
    <article aria-labelledby={titleId} className={cn('relative flex flex-col gap-2 rounded-lg border bg-panel px-3 py-2', active ? 'border-amber/50' : bad ? 'border-bad/40' : 'border-hairline')}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div id={titleId} className="flex min-w-0 items-center gap-2">
          <span className="rounded-sm border border-hairline px-1 text-2xs font-medium tracking-[0.06em] text-text-2 uppercase">{tracked.kind === 'import' ? 'Import' : 'Verify'}</span>
          <code className="min-w-0 font-mono text-xs text-bone [overflow-wrap:anywhere]">{tracked.sourceName}</code>
        </div>
        <div className="flex items-center gap-2">
          {job?.result ? <StatusBadge domain="verdict" value={job.result.verdict} /> : <StatusBadge domain="job" value={state} />}
          {!active ? (
            <Button type="button" variant="ghost" size="sm" onClick={onDismiss}>
              Dismiss
            </Button>
          ) : null}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        <Progress
          value={fill === null ? null : Math.round(fill * 100)}
          aria-labelledby={titleId}
          className={cn(
            'gap-0 [&_[data-slot=progress-track]]:bg-raised',
            bad ? '[&_[data-slot=progress-indicator]]:bg-bad' : finished ? '[&_[data-slot=progress-indicator]]:bg-ok' : '[&_[data-slot=progress-indicator]]:bg-info',
            fill === null && active && '[&_[data-slot=progress-indicator]]:w-1/3 [&_[data-slot=progress-indicator]]:animate-pulse',
          )}
        />
        <p className="font-mono text-xs text-text-3 tabular-nums">
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
        <p role="status" aria-live="polite" className="text-xs text-text-2">
          {jobStatusText(tracked)}
        </p>
      </div>
      {tracked.problem ? (
        <p role="alert" className="text-xs text-bad">
          {tracked.problem}
        </p>
      ) : null}
      {job?.error ? (
        <Callout tone="bad" title="The job failed">
          <p>{job.error}</p>
        </Callout>
      ) : null}
      {job?.result ? (
        <div className="flex flex-col gap-2">
          <ResultSummary kind={tracked.kind} result={job.result} />
          {job.result.report ? (
            <details className="group rounded-sm border border-hairline">
              <summary className="flex cursor-pointer items-center gap-1 px-3 py-1.5 text-xs text-text-2 hover:text-bone [&::-webkit-details-marker]:hidden">
                <ChevronDown aria-hidden="true" className="size-3.5 transition-transform group-open:rotate-180" />
                Full verification report
              </summary>
              <div className="border-t border-hairline p-3">
                <ReportView report={job.result.report} />
              </div>
            </details>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
