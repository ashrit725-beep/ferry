/**
 * What the shell's gateway block shows. The provider loads the overview itself
 * (the same read the Overview page makes, every 30 s while the tab is
 * visible), so the rail is truthful on every page. A page that holds fresher
 * overview data may report it; the latest report wins.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, type Overview } from '../../api.ts';
import { useAutoRefresh, useResource } from '../../hooks.ts';

export interface GatewayStatus {
  /**
   * 'serving': a policy is active and at least one route is available;
   * 'unavailable': a policy is active but no route is available;
   * 'denied': no policy is active, so the gateway refuses every request.
   */
  serving: 'serving' | 'unavailable' | 'denied' | 'unknown';
  backendsHealthy: number | null;
  backendsTotal: number | null;
  reportedAt: number | null;
}

interface Gateway {
  status: GatewayStatus;
  report: (status: Omit<GatewayStatus, 'reportedAt'>) => void;
}

const UNKNOWN: GatewayStatus = { serving: 'unknown', backendsHealthy: null, backendsTotal: null, reportedAt: null };
const REFRESH_MS = 30_000;

/** The rail's summary of an overview response. */
export function gatewayFromOverview(o: Overview): Omit<GatewayStatus, 'reportedAt'> {
  const serving = o.policy === null ? 'denied' : o.routes.some((r) => r.available) ? 'serving' : 'unavailable';
  return {
    serving,
    backendsHealthy: o.backends.filter((b) => b.state === 'up').length,
    backendsTotal: o.backends.length,
  };
}

const GatewayContext = createContext<Gateway | null>(null);

export function GatewayProvider({ children }: { children: ReactNode }) {
  const overview = useResource((signal) => api.overview(signal), []);
  useAutoRefresh(overview.reload, REFRESH_MS);
  const [status, setStatus] = useState<GatewayStatus>(UNKNOWN);
  const report = useCallback((next: Omit<GatewayStatus, 'reportedAt'>) => setStatus({ ...next, reportedAt: Date.now() }), []);
  useEffect(() => {
    if (overview.data) report(gatewayFromOverview(overview.data));
  }, [overview.data, report]);
  const value = useMemo<Gateway>(() => ({ status, report }), [status, report]);
  return <GatewayContext value={value}>{children}</GatewayContext>;
}

export function useGateway(): Gateway {
  const gateway = useContext(GatewayContext);
  if (!gateway) throw new Error('useGateway() used outside the console shell');
  return gateway;
}
