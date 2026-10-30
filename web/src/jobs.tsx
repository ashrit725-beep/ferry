/**
 * Verify and import jobs started from this console.
 *
 * The tracker lives above the pages so a job keeps being followed when the
 * operator navigates away from Bundles; the top bar shows how many are still
 * running. Polling is a timeout chain (never overlapping requests) at 500 ms,
 * backing off while the server is unreachable. Job status is held in memory
 * only; results are persisted by the server (verifications table and audit).
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ApiError, api, isAbortError, type Job, type JobKind } from './api.ts';
import { describeError } from './errors.ts';
import type { TrackedJob } from './jobstate.ts';
import { isJobActive } from './status.ts';

export { isTrackedJobActive, type TrackedJob } from './jobstate.ts';

export const POLL_INTERVAL_MS = 500;
const MAX_BACKOFF_MS = 8_000;
const MAX_FAILURES = 30;

export type JobListener = (job: Job, tracked: TrackedJob) => void;

interface Jobs {
  jobs: TrackedJob[];
  /** Starts a job on the server; rejects with the ApiError if the server refuses. */
  start: (kind: JobKind, sourceName: string) => Promise<string>;
  dismiss: (jobId: string) => void;
  /** Called once for each job that reaches a final state. */
  subscribe: (listener: JobListener) => () => void;
}

const JobsContext = createContext<Jobs | null>(null);

export function JobsProvider({ children }: { children: ReactNode }) {
  const [jobs, setJobs] = useState<TrackedJob[]>([]);
  const jobsRef = useRef<TrackedJob[]>([]);
  const timers = useRef(new Map<string, number>());
  const aborts = useRef(new Map<string, AbortController>());
  const listeners = useRef(new Set<JobListener>());
  const alive = useRef(true);

  const update = useCallback((next: (list: TrackedJob[]) => TrackedJob[]) => {
    jobsRef.current = next(jobsRef.current);
    setJobs(jobsRef.current);
  }, []);

  const patch = useCallback(
    (jobId: string, change: Partial<TrackedJob>) => {
      update((list) => list.map((j) => (j.jobId === jobId ? { ...j, ...change } : j)));
    },
    [update],
  );

  const poll = useCallback(
    (jobId: string, failures: number) => {
      timers.current.delete(jobId);
      const ctrl = new AbortController();
      aborts.current.set(jobId, ctrl);
      api.job(jobId, ctrl.signal).then(
        (job) => {
          aborts.current.delete(jobId);
          if (!alive.current || ctrl.signal.aborted) return;
          patch(jobId, { job, problem: null });
          if (isJobActive(job.state)) {
            timers.current.set(jobId, window.setTimeout(() => poll(jobId, 0), POLL_INTERVAL_MS));
            return;
          }
          const tracked = jobsRef.current.find((j) => j.jobId === jobId);
          if (tracked) for (const listener of listeners.current) listener(job, tracked);
        },
        (err: unknown) => {
          aborts.current.delete(jobId);
          if (!alive.current || ctrl.signal.aborted || isAbortError(err)) return;
          // A 401 has already signed the console out; this provider is about to unmount.
          if (err instanceof ApiError && err.status === 401) return;
          if (err instanceof ApiError && err.status === 404) {
            patch(jobId, {
              problem:
                'The server no longer knows this job, probably because it restarted. Any result it recorded is in the verification history.',
              stopped: true,
            });
            return;
          }
          const attempt = failures + 1;
          if (attempt >= MAX_FAILURES) {
            patch(jobId, { problem: `${describeError(err)} Stopped checking after ${attempt} attempts.`, stopped: true });
            return;
          }
          patch(jobId, { problem: `${describeError(err)} Retrying.` });
          const delay = Math.min(POLL_INTERVAL_MS * 2 ** attempt, MAX_BACKOFF_MS);
          timers.current.set(jobId, window.setTimeout(() => poll(jobId, attempt), delay));
        },
      );
    },
    [patch],
  );

  useEffect(() => {
    alive.current = true;
    const pending = timers.current;
    const inflight = aborts.current;
    return () => {
      alive.current = false;
      for (const id of pending.values()) window.clearTimeout(id);
      for (const ctrl of inflight.values()) ctrl.abort();
      pending.clear();
      inflight.clear();
    };
  }, []);

  const start = useCallback(
    async (kind: JobKind, sourceName: string) => {
      const jobId = kind === 'verify' ? await api.verifyInbox(sourceName) : await api.importInbox(sourceName);
      update((list) => [
        { jobId, kind, sourceName, job: null, problem: null, stopped: false },
        ...list.filter((j) => j.jobId !== jobId),
      ]);
      poll(jobId, 0);
      return jobId;
    },
    [poll, update],
  );

  const dismiss = useCallback(
    (jobId: string) => {
      const timer = timers.current.get(jobId);
      if (timer !== undefined) window.clearTimeout(timer);
      timers.current.delete(jobId);
      aborts.current.get(jobId)?.abort();
      aborts.current.delete(jobId);
      update((list) => list.filter((j) => j.jobId !== jobId));
    },
    [update],
  );

  const subscribe = useCallback((listener: JobListener) => {
    listeners.current.add(listener);
    return () => {
      listeners.current.delete(listener);
    };
  }, []);

  const value = useMemo<Jobs>(() => ({ jobs, start, dismiss, subscribe }), [jobs, start, dismiss, subscribe]);
  return <JobsContext value={value}>{children}</JobsContext>;
}

export function useJobs(): Jobs {
  const jobs = useContext(JobsContext);
  if (!jobs) throw new Error('useJobs() used outside JobsProvider');
  return jobs;
}

/** Runs `onFinished` whenever a tracked job reaches a final state. */
export function useJobFinished(onFinished: JobListener): void {
  const { subscribe } = useJobs();
  const ref = useRef(onFinished);
  useEffect(() => {
    ref.current = onFinished;
  });
  useEffect(() => subscribe((job, tracked) => ref.current(job, tracked)), [subscribe]);
}
