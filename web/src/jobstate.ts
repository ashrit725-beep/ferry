/**
 * What the console knows about a job it started, and the text it shows and
 * announces for it. Kept free of React so it can be tested directly.
 */

import type { Job, JobKind } from './api.ts';
import { isJobActive } from './status.ts';

export interface TrackedJob {
  jobId: string;
  kind: JobKind;
  sourceName: string;
  /** Latest status from the server; null until the first poll answers. */
  job: Job | null;
  /** Latest polling problem, if any. */
  problem: string | null;
  /** Polling ended without a final state (job unknown to the server, or too many failures). */
  stopped: boolean;
}

export function isTrackedJobActive(tracked: TrackedJob): boolean {
  return !tracked.stopped && isJobActive(tracked.job?.state ?? 'queued');
}

/** The state to display: "unknown" once polling gave up before a final state. */
export function displayState(tracked: TrackedJob): string {
  const state = tracked.job?.state ?? 'queued';
  return tracked.stopped && isJobActive(state) ? 'unknown' : state;
}

export function jobPercent(done: number, total: number | null): number | null {
  if (total === null || !Number.isFinite(total) || total <= 0 || !Number.isFinite(done)) return null;
  return Math.max(0, Math.min(100, Math.floor((done / total) * 100)));
}

/**
 * The live-region text. Progress is rounded down to 10 % steps so a screen
 * reader hears a handful of updates, not one per 500 ms poll.
 */
export function jobStatusText(tracked: TrackedJob): string {
  const subject = `${tracked.kind === 'import' ? 'Import' : 'Verification'} of ${tracked.sourceName}`;
  const job = tracked.job;
  const state = displayState(tracked);
  switch (state) {
    case 'unknown':
      return `${subject}: status unknown.`;
    case 'queued':
      return `${subject}: queued.`;
    case 'running': {
      const pct = job ? jobPercent(job.progress.bytes_done, job.progress.bytes_total) : null;
      return `${subject}: running${pct !== null ? `, ${Math.floor(pct / 10) * 10}%` : ''}.`;
    }
    case 'succeeded': {
      const verdict = job?.result?.verdict;
      const already = job?.result?.already_imported ? ', already imported' : '';
      return `${subject}: finished${verdict ? `, ${verdict}` : ''}${already}.`;
    }
    case 'failed':
      return `${subject}: failed.`;
    default:
      return `${subject}: ${state}.`;
  }
}
