/**
 * One shared clock for relative timestamps, so every "4 min ago" on screen
 * advances together instead of each cell running its own timer.
 */

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';

const NowContext = createContext<number>(Date.now());

export function NowProvider({ children, intervalMs = 15_000 }: { children: ReactNode; intervalMs?: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return <NowContext value={now}>{children}</NowContext>;
}

export function useNow(): number {
  return useContext(NowContext);
}
