/**
 * The signed-in user, available to every page. `isAdmin` only decides which
 * controls are shown; the server enforces roles on every request regardless.
 */

import { createContext, useContext } from 'react';
import type { User } from './api.ts';

export interface Session {
  user: User;
  isAdmin: boolean;
  /** Ends the server session. Rejects if the server could not be told. */
  signOut: () => Promise<void>;
}

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const session = useContext(SessionContext);
  if (!session) throw new Error('useSession() used outside a signed-in console');
  return session;
}

/** The role, or null on pages shown before sign-in. */
export function useRole(): string | null {
  return useContext(SessionContext)?.user.role ?? null;
}
