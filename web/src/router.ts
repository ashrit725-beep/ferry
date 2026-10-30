/**
 * Hash routing (#/bundles, #/bundles/<id>, ...). The server has no route
 * fallback, so every console URL is a fragment of `/`.
 *
 * Links that come from data (attention items, `next` after login) go through
 * `safeInternalHref` / `safeNext`, which only ever yield in-console fragments:
 * a server message can never turn into a navigation to another origin or a
 * `javascript:` URL.
 */

import { AUDIT_FILTER_KEYS, type AuditQuery } from './api.ts';

export type AccessTab = 'apps' | 'policy' | 'explain';
export const ACCESS_TABS: readonly AccessTab[] = ['apps', 'policy', 'explain'];

export type RouteMatch =
  | { page: 'login'; next: string | null }
  | { page: 'overview' }
  | { page: 'bundles' }
  | { page: 'bundle'; bundleId: string }
  | { page: 'verification'; id: number }
  | { page: 'models' }
  | { page: 'access'; tab: AccessTab }
  | { page: 'audit'; params: URLSearchParams }
  | { page: 'evidence' }
  | { page: 'not_found'; path: string };

export type NavPage = 'overview' | 'bundles' | 'models' | 'access' | 'audit' | 'evidence';

export const NAV_ITEMS: ReadonlyArray<{ page: NavPage; label: string; path: string }> = [
  { page: 'overview', label: 'Overview', path: '/overview' },
  { page: 'bundles', label: 'Bundles', path: '/bundles' },
  { page: 'models', label: 'Models', path: '/models' },
  { page: 'access', label: 'Access', path: '/access' },
  { page: 'audit', label: 'Audit', path: '/audit' },
  { page: 'evidence', label: 'Evidence', path: '/evidence' },
];

export const BUNDLE_ID = /^sha256:[0-9a-f]{64}$/;

/** Which sidebar entry a route belongs to. */
export function navPageOf(route: RouteMatch): NavPage | null {
  switch (route.page) {
    case 'bundle':
    case 'verification':
      return 'bundles';
    case 'login':
    case 'not_found':
      return null;
    default:
      return route.page;
  }
}

function splitHash(hash: string): { path: string; query: string } {
  const raw = hash.startsWith('#') ? hash.slice(1) : hash;
  const q = raw.indexOf('?');
  return q === -1 ? { path: raw, query: '' } : { path: raw.slice(0, q), query: raw.slice(q + 1) };
}

export function parseHash(hash: string): RouteMatch {
  const { path, query } = splitHash(hash);
  const params = new URLSearchParams(query);
  let segments: string[];
  try {
    segments = path.split('/').filter(Boolean).map((s) => decodeURIComponent(s));
  } catch {
    return { page: 'not_found', path };
  }
  const notFound: RouteMatch = { page: 'not_found', path: path || '/' };
  const [head, ...rest] = segments;
  if (head === undefined) return { page: 'overview' };
  switch (head) {
    case 'login':
      return rest.length ? notFound : { page: 'login', next: safeNext(params.get('next')) };
    case 'overview':
    case 'models':
    case 'evidence':
      return rest.length ? notFound : { page: head };
    case 'access': {
      if (rest.length) return notFound;
      const tab = params.get('tab');
      return { page: 'access', tab: ACCESS_TABS.find((t) => t === tab) ?? 'apps' };
    }
    case 'audit':
      return rest.length ? notFound : { page: 'audit', params };
    case 'bundles': {
      if (rest.length === 0) return { page: 'bundles' };
      const [id] = rest;
      if (rest.length === 1 && id !== undefined) {
        if (/^[1-9]\d{0,15}$/.test(id)) return { page: 'verification', id: Number(id) };
        if (BUNDLE_ID.test(id)) return { page: 'bundle', bundleId: id };
      }
      return notFound;
    }
    default:
      return notFound;
  }
}

/** Fragment for an in-console path such as "/bundles". */
export function toHash(path: string): string {
  return `#${path.startsWith('/') ? path : `/${path}`}`;
}

export const paths = {
  overview: '/overview',
  bundles: '/bundles',
  bundle: (bundleId: string) => `/bundles/${encodeURIComponent(bundleId).replace(/%3A/gi, ':')}`,
  verification: (id: number) => `/bundles/${id}`,
  models: '/models',
  access: (tab: AccessTab = 'apps') => (tab === 'apps' ? '/access' : `/access?tab=${tab}`),
  audit: (filters: AuditQuery = {}) => {
    const qs = auditParams(filters).toString();
    return qs ? `/audit?${qs}` : '/audit';
  },
  evidence: '/evidence',
  login: (next: string | null) => (next ? `/login?next=${encodeURIComponent(next)}` : '/login'),
};

export function navigate(path: string): void {
  const hash = toHash(path);
  if (window.location.hash !== hash) window.location.hash = hash;
}

/** Like navigate, without adding a history entry (tab switches, redirects). */
export function replaceRoute(path: string): void {
  const hash = toHash(path);
  if (window.location.hash !== hash) window.location.replace(hash);
}

/** In-console path to return to after signing in, or null if `next` is not one. */
export function safeNext(next: string | null | undefined): string | null {
  if (!next || !next.startsWith('/') || next.startsWith('//') || /[\s\\]/.test(next)) return null;
  const match = parseHash(`#${next}`);
  return match.page === 'not_found' || match.page === 'login' ? null : next;
}

/**
 * Normalises a link supplied by the server ("#/models", "/#/models" or
 * "/models") to an in-console fragment; anything else yields null and the UI
 * renders plain text instead of a link.
 */
export function safeInternalHref(href: string | null | undefined): string | null {
  if (!href) return null;
  let h = href.trim();
  if (/[\s\\\u0000-\u001f]/.test(h)) return null;
  if (h.startsWith('/#/')) h = h.slice(1);
  else if (h.startsWith('/') && !h.startsWith('//')) h = `#${h}`;
  if (!h.startsWith('#/')) return null;
  const match = parseHash(h);
  return match.page === 'not_found' || match.page === 'login' ? null : h;
}

export function auditParams(filters: AuditQuery): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of AUDIT_FILTER_KEYS) {
    const value = filters[key];
    if (typeof value === 'string' && value.trim()) params.set(key, value.trim());
  }
  return params;
}

export function auditFiltersFromParams(params: URLSearchParams): AuditQuery {
  const filters: AuditQuery = {};
  for (const key of AUDIT_FILTER_KEYS) {
    const value = params.get(key);
    if (value && value.trim()) filters[key] = value.trim().slice(0, 512);
  }
  return filters;
}

/**
 * Action groups for prefix filtering ("bundle.*"), from the actions present
 * in the log. The server treats an action ending in "*" or "." as a prefix.
 */
export function actionGroups(actions: readonly string[]): string[] {
  const groups = new Set<string>();
  for (const a of actions) {
    const dot = a.indexOf('.');
    if (dot > 0) groups.add(`${a.slice(0, dot)}.*`);
  }
  return [...groups].sort();
}
