/**
 * Session bootstrap and routing.
 *
 * The console starts by asking the server who is signed in (GET /api/auth/me).
 * A 401 there, or from any later call, shows the sign-in page and remembers
 * where the operator was (an in-console path only). Pages are rendered only
 * for a signed-in session; everything they show comes from the API.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ApiError, api, isAbortError, setUnauthorizedHandler, type User } from './api.ts';
import { describeError } from './errors.ts';
import { useHash } from './hooks.ts';
import { JobsProvider } from './jobs.tsx';
import { NowProvider } from './now.tsx';
import { parseHash, paths, replaceRoute, safeNext, type RouteMatch } from './router.ts';
import { SessionContext, type Session } from './session.tsx';
import { isAdminRole } from './status.ts';
import { IconLogo } from './components/Icons.tsx';
import { Shell } from './components/Shell.tsx';
import { Spinner } from './components/States.tsx';
import { AccessPage } from './pages/AccessPage.tsx';
import { AuditPage } from './pages/AuditPage.tsx';
import { BundleDetailPage } from './pages/BundleDetailPage.tsx';
import { BundlesPage } from './pages/BundlesPage.tsx';
import { EvidencePage } from './pages/EvidencePage.tsx';
import { LoginPage } from './pages/LoginPage.tsx';
import { ModelsPage } from './pages/ModelsPage.tsx';
import { NotFoundPage } from './pages/NotFoundPage.tsx';
import { OverviewPage } from './pages/OverviewPage.tsx';
import { VerificationDetailPage } from './pages/VerificationDetailPage.tsx';

type SessionState =
  | { status: 'checking' }
  | { status: 'unreachable'; error: unknown }
  | { status: 'signed_out'; notice: string | null; keepPlace: boolean }
  | { status: 'signed_in'; user: User };

function pathOf(hash: string): string {
  return hash.startsWith('#') ? hash.slice(1) : hash;
}

/** Where the URL must go for this session state, or null if it is fine as it is. */
function redirectFor(session: SessionState, route: RouteMatch, hash: string): string | null {
  if (session.status === 'signed_out') {
    return route.page === 'login' ? null : paths.login(session.keepPlace ? safeNext(pathOf(hash)) : null);
  }
  if (session.status === 'signed_in') {
    if (route.page === 'login') return route.next ?? paths.overview;
    if (hash === '' || hash === '#' || hash === '#/') return paths.overview;
  }
  return null;
}

export function App() {
  const hash = useHash();
  const route = useMemo(() => parseHash(hash), [hash]);
  const [session, setSession] = useState<SessionState>({ status: 'checking' });
  const [probe, setProbe] = useState(0);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSession((s) =>
        s.status === 'signed_in'
          ? { status: 'signed_out', notice: 'Your session has ended. Sign in again to continue.', keepPlace: true }
          : s,
      );
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    api.me(ctrl.signal).then(
      (user) => setSession({ status: 'signed_in', user }),
      (error: unknown) => {
        if (isAbortError(error)) return;
        if (error instanceof ApiError && error.status === 401) setSession({ status: 'signed_out', notice: null, keepPlace: true });
        else setSession({ status: 'unreachable', error });
      },
    );
    return () => ctrl.abort();
  }, [probe]);

  const redirect = redirectFor(session, route, hash);
  useEffect(() => {
    if (redirect) replaceRoute(redirect);
  }, [redirect]);

  const signIn = useCallback((user: User) => setSession({ status: 'signed_in', user }), []);
  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch (err) {
      // 401: the session had already ended, which is what signing out wants.
      if (!(err instanceof ApiError && err.status === 401)) throw err;
    }
    setSession({ status: 'signed_out', notice: 'You have signed out.', keepPlace: false });
  }, []);

  if (session.status === 'checking') return <Boot />;
  if (session.status === 'unreachable') {
    return (
      <Unreachable
        error={session.error}
        onRetry={() => {
          setSession({ status: 'checking' });
          setProbe((p) => p + 1);
        }}
      />
    );
  }
  if (session.status === 'signed_out') {
    if (route.page !== 'login') return <Boot />;
    return <LoginPage notice={session.notice} onSignedIn={signIn} />;
  }
  if (redirect) return <Boot />;
  return <SignedIn user={session.user} signOut={signOut} route={route} />;
}

function SignedIn({ user, signOut, route }: { user: User; signOut: () => Promise<void>; route: RouteMatch }) {
  const session = useMemo<Session>(() => ({ user, isAdmin: isAdminRole(user.role), signOut }), [user, signOut]);
  return (
    <SessionContext value={session}>
      <NowProvider>
        <JobsProvider>
          <Shell route={route}>
            <Page route={route} />
          </Shell>
        </JobsProvider>
      </NowProvider>
    </SessionContext>
  );
}

function Page({ route }: { route: RouteMatch }) {
  switch (route.page) {
    case 'overview':
      return <OverviewPage />;
    case 'bundles':
      return <BundlesPage />;
    case 'bundle':
      return <BundleDetailPage key={route.bundleId} bundleId={route.bundleId} />;
    case 'verification':
      return <VerificationDetailPage key={route.id} id={route.id} />;
    case 'models':
      return <ModelsPage />;
    case 'access':
      return <AccessPage tab={route.tab} />;
    case 'audit':
      return <AuditPage params={route.params} />;
    case 'evidence':
      return <EvidencePage />;
    case 'not_found':
      return <NotFoundPage path={route.path} />;
    case 'login':
      return null;
  }
}

function Boot() {
  return (
    <div className="boot" role="status">
      <span className="row">
        <Spinner />
        Connecting to the Ferry server…
      </span>
    </div>
  );
}

function Unreachable({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return (
    <div className="boot">
      <main className="login__card" aria-labelledby="unreachable-title">
        <p className="login__brand">
          <IconLogo />
          Ferry
        </p>
        <h1 id="unreachable-title" className="login__title">
          The console cannot reach the server
        </h1>
        <p className="muted" role="alert">
          {describeError(error)}
        </p>
        <div className="form-actions">
          <button type="button" className="button button--primary" onClick={onRetry}>
            Try again
          </button>
        </div>
      </main>
    </div>
  );
}
