/**
 * The Cmd-K palette: go to a page, open a bundle or verification by pasted
 * id, refresh, sign out. No open or close animation (keyboard-driven).
 */

import { useEffect, useState } from 'react';
import { ArrowRight, LogOut, RefreshCw } from 'lucide-react';
import { api, type BundleSummary } from '../../api.ts';
import { BUNDLE_ID, NAV_ITEMS, navigate, paths } from '../../router.ts';
import { Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '../ui/command.tsx';
import { NAV_ICONS } from './nav-icons.tsx';

/** A bundle id head as the console prints it (sha256:5b5a6ed8b8fb), 12 or more hex digits. */
const BUNDLE_HEAD = /^(?:sha256:)?([0-9a-f]{12,63})$/;

/** One wording for the top-bar field and the palette input. */
export const PALETTE_PLACEHOLDER = 'Go to a page or paste a bundle id…';

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSignOut: () => void;
}

export function CommandPalette({ open, onOpenChange, onSignOut }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const trimmed = query.trim();
  const bundleId = BUNDLE_ID.test(trimmed) ? trimmed : null;
  const verificationId = /^#?[1-9]\d{0,15}$/.test(trimmed) ? Number(trimmed.replace('#', '')) : null;
  const head = bundleId === null ? (BUNDLE_HEAD.exec(trimmed.toLowerCase())?.[1] ?? null) : null;
  const [bundles, setBundles] = useState<readonly BundleSummary[] | null>(null);

  // Read the imported bundles once a head is typed, to resolve it by prefix.
  const wantBundles = head !== null && bundles === null;
  useEffect(() => {
    if (!wantBundles) return;
    const controller = new AbortController();
    api.bundles(controller.signal).then(
      (rows) => setBundles(rows),
      () => setBundles([]),
    );
    return () => controller.abort();
  }, [wantBundles]);

  const headMatches = head !== null && bundles ? bundles.filter((b) => b.bundle_id.startsWith(`sha256:${head}`)).slice(0, 8) : [];

  const go = (path: string): void => {
    onOpenChange(false);
    navigate(path);
  };

  return (
    <CommandDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setQuery('');
          setBundles(null);
        }
        onOpenChange(next);
      }}
      title="Command palette"
      description="Go to a page, open a bundle by id, refresh or sign out"
      // Same axis and (from 1280 px) the same width as the top-bar field: centred on the bar, right of the 232 px rail.
      className="top-[20%] rounded-lg! bg-raised ring-1 ring-hairline shadow-float sm:max-w-[420px] lg:left-[calc(50%+116px)]"
    >
      <Command className="rounded-lg! bg-raised text-bone" shouldFilter={bundleId === null && verificationId === null && head === null}>
        <CommandInput placeholder={PALETTE_PLACEHOLDER} value={query} onValueChange={setQuery} className="font-sans" />
        <CommandList className="max-h-80">
          <CommandEmpty className="py-4 text-xs text-text-3">
            {head !== null && bundles === null
              ? 'Looking up imported bundles…'
              : `No match for "${trimmed}". Pages, a bundle id or its first 12 digits (sha256:…) or a verification number work here.`}
          </CommandEmpty>
          {bundleId ? (
            <CommandGroup heading="Bundle">
              <CommandItem value={bundleId} onSelect={() => go(paths.bundle(bundleId))}>
                <ArrowRight aria-hidden="true" />
                <span className="truncate font-mono text-xs">Open bundle {bundleId}</span>
              </CommandItem>
            </CommandGroup>
          ) : null}
          {headMatches.length ? (
            <CommandGroup heading="Bundles">
              {headMatches.map((b) => (
                <CommandItem key={b.bundle_id} value={b.bundle_id} onSelect={() => go(paths.bundle(b.bundle_id))}>
                  <ArrowRight aria-hidden="true" />
                  <span className="min-w-0 truncate">
                    Open{' '}
                    <span className="font-mono text-xs">
                      {b.name} {b.version}
                    </span>{' '}
                    <span className="font-mono text-xs text-text-3">{b.bundle_id.slice(0, 19)}</span>
                  </span>
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}
          {verificationId !== null ? (
            <CommandGroup heading="Verification">
              <CommandItem value={String(verificationId)} onSelect={() => go(paths.verification(verificationId))}>
                <ArrowRight aria-hidden="true" />
                Open verification #{verificationId}
              </CommandItem>
            </CommandGroup>
          ) : null}
          {head !== null ? null : (
          <CommandGroup heading="Pages">
            {NAV_ITEMS.map((item) => {
              const Icon = NAV_ICONS[item.page];
              return (
                <CommandItem key={item.page} value={`go ${item.label}`} onSelect={() => go(item.path)}>
                  <Icon aria-hidden="true" />
                  {item.label}
                </CommandItem>
              );
            })}
          </CommandGroup>
          )}
          <CommandGroup heading="Console">
            <CommandItem
              value="refresh page reload"
              onSelect={() => {
                onOpenChange(false);
                window.location.reload();
              }}
            >
              <RefreshCw aria-hidden="true" />
              Refresh this page
            </CommandItem>
            <CommandItem
              value="sign out"
              onSelect={() => {
                onOpenChange(false);
                onSignOut();
              }}
            >
              <LogOut aria-hidden="true" />
              Sign out
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
