/**
 * The signed-in layout: skip control, the deep-blue rail (shadcn sidebar,
 * a sheet under 1024 px), a 48 px top bar with the page section, the Cmd-K
 * command field, the running-jobs indicator, the user, role and sign-out,
 * and the main region. After every page change focus moves to the new page's
 * h1 so screen reader users hear where they are. The toaster is mounted here
 * once.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react';
import { LogOut, Search, X } from 'lucide-react';
import { describeError } from '../errors.ts';
import { plural } from '../format.ts';
import { isTrackedJobActive, useJobs } from '../jobs.tsx';
import { useNow } from '../now.tsx';
import { NAV_ITEMS, navPageOf, paths, toHash, type NavPage, type RouteMatch } from '../router.ts';
import { useSession } from '../session.tsx';
import { CommandPalette, PALETTE_PLACEHOLDER } from './console/command-palette.tsx';
import { PageErrorBoundary } from './console/error-boundary.tsx';
import { GatewayProvider, useGateway } from './console/gateway.tsx';
import { IconButton } from './console/icon-button.tsx';
import { IconLogo, NAV_ICONS } from './console/nav-icons.tsx';
import { Stamp } from './console/stamp.tsx';
import { Spinner } from './console/states.tsx';
import { Button } from './ui/button.tsx';
import { Kbd } from './ui/kbd.tsx';
import { Separator } from './ui/separator.tsx';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from './ui/sidebar.tsx';
import { Toaster } from './ui/sonner.tsx';
import { cn } from '@/lib/utils';

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

/** Apple keyboards show the Command glyph; everything else is Ctrl. */
const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

const TIME = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZoneName: 'short' });

function LocalTime() {
  const now = useNow();
  const parts = TIME.formatToParts(new Date(Math.max(now, Date.now())));
  const time = parts
    .filter((p) => p.type === 'hour' || p.type === 'minute' || p.type === 'literal')
    .map((p) => p.value)
    .join('')
    .trim();
  const zone = parts.find((p) => p.type === 'timeZoneName')?.value ?? '';
  return (
    <span className="tabular-nums">
      {time} <span className="text-rail-muted">{zone}</span>
    </span>
  );
}

function GatewayBlock() {
  const { status } = useGateway();
  const serving = status.serving;
  return (
    <div className="flex flex-col gap-1.5 px-3 py-3 text-xs text-rail-text">
      <p className="text-2xs font-medium tracking-[0.14em] text-rail-muted uppercase">Gateway</p>
      <div className="flex items-center justify-between gap-2">
        <span>State</span>
        <Stamp
          state={serving === 'serving' ? 'confirmed' : serving === 'unavailable' ? 'warning' : serving === 'denied' ? 'failed' : 'neutral'}
          land={false}
        >
          {serving === 'serving' ? 'Serving' : serving === 'unavailable' ? 'No routes' : serving === 'denied' ? 'No policy' : 'Unknown'}
        </Stamp>
      </div>
      <div className="flex items-center justify-between gap-2">
        <span>Backends</span>
        {status.backendsTotal === null ? (
          <span className="font-mono tabular-nums">—</span>
        ) : (
          <span>
            <span className="font-mono tabular-nums">{`${status.backendsHealthy ?? 0}/${status.backendsTotal}`}</span> healthy
          </span>
        )}
      </div>
      <div className="flex items-center justify-between gap-2">
        <span>Server</span>
        <code className="min-w-0 truncate font-mono text-rail-text" title={window.location.host}>
          {window.location.host}
        </code>
      </div>
      <div className="flex items-center justify-between gap-2">
        <span>Local time</span>
        <LocalTime />
      </div>
    </div>
  );
}

function Rail({ current }: { current: NavPage | null }) {
  const { setOpenMobile, isMobile } = useSidebar();
  return (
    <Sidebar collapsible="offcanvas" className="border-r border-rail-border bg-rail text-rail-text">
      <SidebarHeader className="relative h-12 justify-center border-b border-rail-border p-0">
        <a href={toHash(paths.overview)} className="flex h-12 items-center gap-2 px-3 text-bone" onClick={() => setOpenMobile(false)}>
          <IconLogo className="size-5 text-amber" strokeWidth={1.75} />
          <span className="text-base font-medium">Ferry</span>
          <span className="text-xs text-rail-muted">console</span>
        </a>
        {isMobile ? (
          <IconButton
            label="Close navigation"
            noTooltip
            className="absolute top-1 right-1 size-10 text-rail-text hover:bg-rail-hover hover:text-bone"
            onClick={() => setOpenMobile(false)}
          >
            <X aria-hidden="true" />
          </IconButton>
        ) : null}
      </SidebarHeader>
      <SidebarContent className="py-2">
        <nav aria-label="Console pages">
          <SidebarMenu>
            {NAV_ITEMS.map((item) => {
              const Icon = NAV_ICONS[item.page];
              const active = current === item.page;
              return (
                <SidebarMenuItem key={item.page}>
                  <SidebarMenuButton
                    isActive={active}
                    render={<a href={toHash(item.path)} aria-current={active ? 'page' : undefined} onClick={() => setOpenMobile(false)} />}
                    className={cn(
                      'relative h-10 gap-2.5 rounded-none px-4 text-sm text-rail-text hover:bg-rail-hover hover:text-bone focus-visible:ring-0 active:bg-rail-hover',
                      'data-active:bg-rail-active data-active:font-medium data-active:text-bone data-active:before:absolute data-active:before:inset-y-2 data-active:before:left-0 data-active:before:w-0.5 data-active:before:bg-amber data-active:[&_svg]:text-amber',
                    )}
                  >
                    <Icon aria-hidden="true" className="size-4" strokeWidth={1.75} />
                    <span>{item.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              );
            })}
          </SidebarMenu>
        </nav>
      </SidebarContent>
      <SidebarFooter className="border-t border-rail-border p-0">
        <GatewayBlock />
      </SidebarFooter>
    </Sidebar>
  );
}

export function Shell({ route, children }: { route: RouteMatch; children: ReactNode }) {
  const { user, isAdmin, signOut } = useSession();
  const { jobs } = useJobs();
  const mainRef = useRef<HTMLElement>(null);
  const key = pageKey(route);
  const previousKey = useRef(key);
  const [signingOut, setSigningOut] = useState(false);
  const [signOutError, setSignOutError] = useState<unknown>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const current = navPageOf(route);
  const running = jobs.filter(isTrackedJobActive).length;
  const section = NAV_ITEMS.find((item) => item.page === current)?.label ?? (route.page === 'not_found' ? 'Not found' : 'Console');

  useEffect(() => {
    if (previousKey.current === key) return;
    previousKey.current = key;
    window.scrollTo(0, 0);
    focusHeading(mainRef.current);
  }, [key]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      if ((event.metaKey || event.ctrlKey) && !event.shiftKey && !event.altKey && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const onSignOut = async (): Promise<void> => {
    if (signingOut) return;
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
    <GatewayProvider>
      <SidebarProvider className="min-h-svh bg-ground">
        <button
          type="button"
          className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-amber focus:px-3 focus:py-1.5 focus:text-sm focus:font-medium focus:text-on-amber"
          onClick={() => focusHeading(mainRef.current)}
        >
          Skip to content
        </button>
        <Rail current={current} />
        <div className="flex min-w-0 flex-1 flex-col">
          {/* The command field is centred on the bar itself (absolute), so it never moves with the page title; the palette opens on the same axis. */}
          <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b sm:gap-3 border-hairline bg-ground px-4 lg:px-6">
            <SidebarTrigger
              className="relative -ml-2 size-10 pointer-coarse:size-11 lg:hidden"
              aria-label="Open navigation"
            />
            <a href={toHash(paths.overview)} aria-label="Ferry console overview" className="-ml-1 flex size-10 shrink-0 items-center justify-center rounded-sm lg:hidden">
              <IconLogo aria-hidden="true" className="size-5 text-amber" strokeWidth={1.75} />
            </a>
            <p className="min-w-0 flex-1 truncate text-sm font-medium text-bone sm:max-w-[calc(35%-6rem)] sm:flex-none sm:shrink lg:max-w-[calc(35%-3rem)]">{section}</p>
            <div className="flex shrink-0 justify-end sm:pointer-events-none sm:absolute sm:inset-y-0 sm:left-1/2 sm:w-[30%] sm:-translate-x-1/2 sm:items-center sm:justify-center xl:w-[420px]">
              <button
                type="button"
                aria-keyshortcuts="Meta+K Control+K"
                onClick={() => setPaletteOpen(true)}
                className="pointer-events-auto hidden h-8 w-full items-center gap-2 rounded-sm border border-line-control/60 bg-inset px-2 text-xs text-text-3 hover:border-line-control hover:text-text-2 sm:flex"
              >
                <Search aria-hidden="true" className="size-3.5" />
                <span className="min-w-0 flex-1 truncate text-left">{PALETTE_PLACEHOLDER}</span>
                <Kbd className="bg-raised text-text-3">{IS_MAC ? '⌘K' : 'Ctrl K'}</Kbd>
              </button>
              <IconButton label="Open the command palette" className="size-10 pointer-coarse:size-11 sm:hidden" onClick={() => setPaletteOpen(true)}>
                <Search aria-hidden="true" />
              </IconButton>
            </div>
            <span aria-hidden="true" className="hidden flex-1 sm:block" />
            {running > 0 ? (
              <a href={toHash(paths.bundles)} className="flex shrink-0 items-center gap-1.5 rounded-sm text-xs text-amber hover:underline">
                <Spinner />
                <span className="font-mono tabular-nums">{plural(running, 'job')}</span> running
              </a>
            ) : null}
            <div className="flex shrink-0 items-center gap-2">
              <span className="sr-only">Signed in as</span>
              <span className="hidden text-sm text-bone md:inline">{user.username}</span>
              {/* The role is a fact, not a state: a plain tag with no state glyph. */}
              <span
                title={isAdmin ? 'Full access' : 'Read-only access'}
                className="inline-flex h-6 items-center rounded-sm border border-line-control/50 bg-raised px-1.5 text-xs text-text-2"
              >
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </span>
              {isAdmin ? null : <span className="hidden text-xs text-text-3 md:inline">read-only</span>}
              <Separator orientation="vertical" className="mx-1 h-5 data-vertical:self-center" />
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="max-sm:size-10 max-sm:px-0"
                aria-disabled={signingOut || undefined}
                onClick={() => void onSignOut()}
              >
                <LogOut aria-hidden="true" />
                <span className="max-sm:sr-only">{signingOut ? 'Signing out…' : 'Sign out'}</span>
              </Button>
            </div>
          </header>
          {signOutError ? (
            <div role="alert" className="border-b border-bad/40 bg-bad-subtle px-4 py-2 text-sm text-bone lg:px-6">
              Sign-out failed: {describeError(signOutError)} The session stays valid on the server until it expires.
            </div>
          ) : null}
          <main id="main" ref={mainRef} tabIndex={-1} className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-4 lg:px-6 lg:py-5">
            <PageErrorBoundary resetKey={key}>{children}</PageErrorBoundary>
          </main>
        </div>
        <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} onSignOut={() => void onSignOut()} />
        <Toaster position="bottom-right" visibleToasts={3} closeButton />
      </SidebarProvider>
    </GatewayProvider>
  );
}
