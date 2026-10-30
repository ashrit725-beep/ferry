/**
 * The signed-in layout: skip control, sidebar navigation, top bar with the
 * user, role and sign-out, and the main region. After every page change focus
 * moves to the new page's h1 so screen reader users hear where they are.
 */

import { useEffect, useRef, useState, type ComponentType, type ReactNode } from 'react';
import { describeError } from '../errors.ts';
import { plural } from '../format.ts';
import { isTrackedJobActive, useJobs } from '../jobs.tsx';
import { NAV_ITEMS, navPageOf, paths, toHash, type NavPage, type RouteMatch } from '../router.ts';
import { useSession } from '../session.tsx';
import {
  IconAccess,
  IconAudit,
  IconBundles,
  IconEvidence,
  IconLogo,
  IconModels,
  IconOverview,
  IconSignOut,
} from './Icons.tsx';
import { Spinner } from './States.tsx';
import { Badge } from './StatusBadge.tsx';

const NAV_ICONS: Record<NavPage, ComponentType> = {
  overview: IconOverview,
  bundles: IconBundles,
  models: IconModels,
  access: IconAccess,
  audit: IconAudit,
  evidence: IconEvidence,
};

/** Identity of a page for focus handling: tab and filter changes within a page do not count. */
function pageKey(route: RouteMatch): string {
  switch (route.page) {
    case 'bundle':
      return `bundle:${route.bundleId}`;
    case 'verification':
      return `verification:${route.id}`;
    case 'not_found':
      return `not_found:${route.path}`;
    default:
      return route.page;
  }
}

function focusHeading(main: HTMLElement | null): void {
  const heading = main?.querySelector<HTMLElement>('h1');
  (heading ?? main)?.focus({ preventScroll: true });
}

export function Shell({ route, children }: { route: RouteMatch; children: ReactNode }) {
  const { user, isAdmin, signOut } = useSession();
  const { jobs } = useJobs();
  const mainRef = useRef<HTMLElement>(null);
  const key = pageKey(route);
  const previousKey = useRef(key);
  const [signingOut, setSigningOut] = useState(false);
  const [signOutError, setSignOutError] = useState<unknown>(null);
  const current = navPageOf(route);
  const running = jobs.filter(isTrackedJobActive).length;

  useEffect(() => {
    if (previousKey.current === key) return;
    previousKey.current = key;
    window.scrollTo(0, 0);
    focusHeading(mainRef.current);
  }, [key]);

  const onSignOut = async (): Promise<void> => {
    setSigningOut(true);
    setSignOutError(null);
    try {
      await signOut();
    } catch (err) {
      setSignOutError(err);
      setSigningOut(false);
    }
  };

  return (
    <div className="shell">
      <button type="button" className="skip-link" onClick={() => focusHeading(mainRef.current)}>
        Skip to content
      </button>
      <div className="sidebar">
        <a className="brand" href={toHash(paths.overview)}>
          <IconLogo />
          Ferry
          <span className="brand__sub">console</span>
        </a>
        <nav className="nav" aria-label="Console pages">
          {NAV_ITEMS.map((item) => {
            const Icon = NAV_ICONS[item.page];
            return (
              <a
                key={item.page}
                className="nav__link"
                href={toHash(item.path)}
                aria-current={current === item.page ? 'page' : undefined}
              >
                <Icon />
                {item.label}
              </a>
            );
          })}
        </nav>
      </div>
      <div className="main-col">
        <header className="topbar">
          <p className="topbar__context">
            Server <code>{window.location.host}</code>
          </p>
          {running > 0 ? (
            <a className="topbar__jobs" href={toHash(paths.bundles)}>
              <Spinner />
              {plural(running, 'job')} running
            </a>
          ) : null}
          <div className="topbar__user">
            <span className="sr-only">Signed in as</span>
            <span className="topbar__user-name">{user.username}</span>
            <Badge tone={isAdmin ? 'info' : 'neutral'} title={isAdmin ? 'Full access' : 'Read-only access'}>
              {user.role}
            </Badge>
            {isAdmin ? null : <span className="topbar__note">read-only</span>}
            <span className="topbar__divider" aria-hidden="true" />
            <button
              type="button"
              className="button button--ghost button--small"
              aria-disabled={signingOut || undefined}
              onClick={() => {
                if (!signingOut) void onSignOut();
              }}
            >
              <IconSignOut />
              {signingOut ? 'Signing out…' : 'Sign out'}
            </button>
          </div>
        </header>
        {signOutError ? (
          <div className="banner banner--bad" role="alert">
            Sign-out failed: {describeError(signOutError)} The session stays valid on the server until it expires.
          </div>
        ) : null}
        <main id="main" ref={mainRef} className="main" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
