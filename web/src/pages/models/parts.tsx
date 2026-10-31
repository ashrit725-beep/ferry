/**
 * Small pieces the three Models panels and the route map share: the state
 * words for a route's provenance and availability and a backend's health
 * (always a word beside the colour), a neutral fact tag, and the polite
 * loading line and refresh error that sit beside a DataTable.
 */

import type { ReactNode } from 'react';
import type { Backend, ModelRoute } from '../../api.ts';
import type { Resource } from '../../hooks.ts';
import { statusLabel, toneFor, type Tone } from '../../status.ts';
import { toneToStamp, type StampState } from '../../components/console/stamp.tsx';
import { InlineError } from '../../components/console/states.tsx';
import { cn } from '@/lib/utils';

export interface StateWord {
  state: StampState;
  tone: Tone;
  word: string;
}

/** Provenance as the server computed it: verified, mismatch, unverified, not pinned, unknown. */
export function provenanceWord(route: ModelRoute): StateWord {
  const tone = toneFor('provenance', route.provenance.state);
  return { tone, state: toneToStamp(tone), word: statusLabel(route.provenance.state || 'unknown') };
}

/** Availability: disabled when the route is off, else available or unavailable. */
export function availabilityWord(route: ModelRoute): StateWord {
  const value = route.enabled ? (route.available ? 'available' : 'unavailable') : 'disabled';
  const tone = toneFor('availability', value);
  return { tone, state: toneToStamp(tone), word: value };
}

/** Health from the last check: up, down, loading, or not checked. */
export function healthWord(backend: Backend): StateWord {
  const value = backend.last_status?.state ?? null;
  if (!value) return { tone: 'neutral', state: 'neutral', word: 'not checked' };
  const tone = toneFor('backend', value);
  return { tone, state: toneToStamp(tone), word: statusLabel(value) };
}

/** True while a backend's last check reports it down. */
export function isDown(backend: Backend): boolean {
  return toneFor('backend', backend.last_status?.state ?? null) === 'bad';
}

/** A neutral fact chip (kind, "token file", a route name): never a state. */
export function Tag({ children, mono = false, className }: { children: ReactNode; mono?: boolean; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 max-w-full items-center rounded-sm border border-line-control/50 bg-raised px-1.5 text-2xs text-text-2',
        mono && 'font-mono',
        className,
      )}
    >
      <span className="truncate">{children}</span>
    </span>
  );
}

/** A short note under a cell's main value. */
export function CellNote({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('pt-0.5 text-2xs leading-4 text-text-2 text-pretty', className)}>{children}</div>;
}

/**
 * What a DataTable fed straight from a resource cannot say itself: the
 * polite loading line while the first load runs, and the refresh error
 * above data that is still shown.
 */
export function ResourceStatus<T>({ resource, loadingLabel }: { resource: Resource<T>; loadingLabel: string }) {
  if (resource.data === null) {
    return resource.loading && !resource.error ? (
      <p role="status" className="sr-only">
        {loadingLabel}
      </p>
    ) : null;
  }
  if (!resource.error) return null;
  return (
    <div className="px-3 pt-3">
      <InlineError error={resource.error} prefix="Could not refresh; showing the last data loaded." onRetry={resource.reload} />
    </div>
  );
}
