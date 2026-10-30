/**
 * Hooks shared by the pages: loading API data with cancellation, following the
 * hash route, and keeping the document title in step with the page.
 */

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { isAbortError } from './api.ts';
import { parseHash, type RouteMatch } from './router.ts';

export interface Resource<T> {
  /** Last successful result for the current inputs; kept while a reload runs or after a failed reload. */
  data: T | null;
  /** Error from the latest attempt, or null. */
  error: unknown;
  /** True until the first result or error for the current inputs. */
  loading: boolean;
  /** True while a reload runs and older data is still shown. */
  refreshing: boolean;
  reload: () => void;
}

type Input = string | number | boolean | null | undefined;

interface ResourceState<T> {
  key: string;
  data: T | null;
  error: unknown;
  loading: boolean;
  refreshing: boolean;
}

function initial<T>(key: string): ResourceState<T> {
  return { key, data: null, error: null, loading: true, refreshing: false };
}

/**
 * Runs `load` whenever `inputs` change or `reload()` is called. The previous
 * request is aborted first, so a slow response for old inputs can never
 * overwrite the result for new ones.
 */
export function useResource<T>(load: (signal: AbortSignal) => Promise<T>, inputs: readonly Input[]): Resource<T> {
  const key = JSON.stringify(inputs);
  const loadRef = useRef(load);
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<ResourceState<T>>(() => initial<T>(key));

  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    const ctrl = new AbortController();
    setState((s) => (s.key === key && s.data !== null ? { ...s, refreshing: true } : initial<T>(key)));
    loadRef.current(ctrl.signal).then(
      (data) => {
        if (!ctrl.signal.aborted) setState({ key, data, error: null, loading: false, refreshing: false });
      },
      (error: unknown) => {
        if (ctrl.signal.aborted || isAbortError(error)) return;
        setState((s) => ({ key, data: s.key === key ? s.data : null, error, loading: false, refreshing: false }));
      },
    );
    return () => ctrl.abort();
  }, [key, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  // Between an input change and its effect, never show data that belongs to the old inputs.
  const current = state.key === key ? state : initial<T>(key);
  return { data: current.data, error: current.error, loading: current.loading, refreshing: current.refreshing, reload };
}

/** Calls `reload` every `intervalMs` while the tab is visible. */
export function useAutoRefresh(reload: () => void, intervalMs: number, enabled = true): void {
  useEffect(() => {
    if (!enabled) return undefined;
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') reload();
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [reload, intervalMs, enabled]);
}

function subscribeHash(onChange: () => void): () => void {
  window.addEventListener('hashchange', onChange);
  return () => window.removeEventListener('hashchange', onChange);
}

function readHash(): string {
  return window.location.hash;
}

export function useHash(): string {
  return useSyncExternalStore(subscribeHash, readHash, () => '');
}

export function useRoute(): RouteMatch {
  const hash = useHash();
  return useMemo(() => parseHash(hash), [hash]);
}

export function useDocumentTitle(title: string | null): void {
  useEffect(() => {
    document.title = title ? `${title} · Ferry` : 'Ferry console';
  }, [title]);
}
