/**
 * One horizontal bar split into proportional segments. A visual summary only
 * (hidden from assistive technology): the numbers are always also in an
 * adjacent table with text labels, and each row carries the same swatch so
 * segments match without relying on hue.
 */

import { useId } from 'react';
import type { Segment } from '../../metrics.ts';
import { cn } from '@/lib/utils';

/** Segment key to fill colour: state hues for outcomes, series colours for environments. */
const FILL: Record<string, string> = {
  success: 'fill-ok',
  // Denied is policy working as written, not a call for a human: a hatched
  // neutral, never the attention colour (the hatch separates it from Rejected).
  denied: 'fill-text-2',
  error: 'fill-bad',
  unavailable: 'fill-info',
  rejected: 'fill-bone',
  unauthenticated: 'fill-neutral',
  test: 'fill-text-3',
  pilot: 'fill-info',
  production: 'fill-bone',
};

export function fillClass(key: string): string {
  return FILL[key] ?? 'fill-neutral';
}

const HATCHED = new Set(['denied']);

function useHatchId(): string {
  return `hatch-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
}

function Hatch({ id, size }: { id: string; size: number }) {
  return (
    <defs>
      <pattern id={id} patternUnits="userSpaceOnUse" width={size} height={size} patternTransform="rotate(45)">
        <rect className="fill-ground" x="0" y="0" width={size / 2.5} height={size} />
      </pattern>
    </defs>
  );
}

export function ShareBar<K extends string>({ segments, className }: { segments: readonly Segment<K>[]; className?: string }) {
  const hatch = useHatchId();
  return (
    <svg className={cn('block h-2 w-full', className)} viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false">
      <Hatch id={hatch} size={3} />
      <rect className="fill-raised" x="0" y="0" width="100" height="8" rx="1" />
      {segments
        .filter((s) => s.share > 0)
        .map((s) => (
          <g key={s.key}>
            <rect className={fillClass(s.key)} x={s.offset * 100} y="0" width={s.share * 100} height="8" />
            {HATCHED.has(s.key) ? <rect fill={`url(#${hatch})`} x={s.offset * 100} y="0" width={s.share * 100} height="8" /> : null}
          </g>
        ))}
    </svg>
  );
}

export function Swatch({ name }: { name: string }) {
  const hatch = useHatchId();
  return (
    <svg className="inline-block size-2.5 shrink-0 align-middle" viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
      {HATCHED.has(name) ? <Hatch id={hatch} size={4} /> : null}
      <rect className={fillClass(name)} x="0" y="0" width="10" height="10" rx="1" />
      {HATCHED.has(name) ? <rect fill={`url(#${hatch})`} x="0" y="0" width="10" height="10" rx="1" /> : null}
    </svg>
  );
}
