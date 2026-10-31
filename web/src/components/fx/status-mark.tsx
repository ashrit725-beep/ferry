/**
 * StatusMark. Source: React Bits `StatusMark` (TS-TW registry, fetched
 * 2026-10-29, vetted 2026-10-30), rewritten by hand.
 * Purpose: the one animated state glyph: a ring that draws a check, a cross,
 * a warning bar or a dot, and spins while something runs.
 * Changes: no "use client", no runtime <style> (the breathe keyframes are in
 * index.css as --animate-mark-breathe); the console's six states instead of
 * five job states; colour comes from the parent through currentColor so the
 * state token is applied once beside the word; the mark is aria-hidden
 * unless given a label; under prefers-reduced-motion the glyph is drawn
 * without the stroke animation and the spinner keeps turning (it is the one
 * allowed loop).
 */

import { cn } from '@/lib/utils';

export type MarkState = 'confirmed' | 'pending' | 'failed' | 'warning' | 'info' | 'neutral' | 'running';

const GLYPH: Record<MarkState, string | null> = {
  confirmed: 'M7.5 12.25 10.5 15.25 16.75 8.75',
  failed: 'M8.5 8.5 15.5 15.5M15.5 8.5 8.5 15.5',
  warning: 'M12 7v6M12 16.5v.5',
  info: 'M12 11v6M12 7.5v.5',
  neutral: 'M8 12h8',
  pending: null,
  running: null,
};

const SPOKEN: Record<MarkState, string> = {
  confirmed: 'Confirmed',
  pending: 'Pending',
  failed: 'Failed',
  warning: 'Warning',
  info: 'Information',
  neutral: 'Not applicable',
  running: 'In progress',
};

export interface StatusMarkProps {
  state: MarkState;
  /** 0 to 1 for a determinate running mark. */
  progress?: number;
  size?: number;
  /** Announce the state: otherwise the mark is decoration beside its word. */
  label?: boolean;
  /** Draw the glyph's stroke in (240 ms). Off by default: marks render static on mount, route changes and table rows; a parent turns it on when its state changed after mount. */
  draw?: boolean;
  className?: string;
}

export function StatusMark({ state, progress, size = 16, label = false, draw = false, className }: StatusMarkProps) {
  const r = 9;
  const c = 2 * Math.PI * r;
  const determinate = state === 'running' && typeof progress === 'number' && Number.isFinite(progress);
  const indeterminate = state === 'running' && !determinate;
  const arc = determinate ? Math.min(1, Math.max(0, progress)) : indeterminate ? 0.68 : 1;
  const path = GLYPH[state];
  const spoken = SPOKEN[state] + (determinate ? `, ${Math.round(arc * 100)}%` : '');
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      role={label ? 'img' : undefined}
      aria-label={label ? spoken : undefined}
      aria-hidden={label ? undefined : 'true'}
      focusable="false"
      data-state={state}
      className={cn('shrink-0 overflow-visible', className)}
    >
      {state === 'confirmed' || state === 'failed' || state === 'warning' ? (
        <circle cx="12" cy="12" r={r} fill="currentColor" fillOpacity={0.12} />
      ) : null}
      <circle
        cx="12"
        cy="12"
        r={r}
        fill="none"
        stroke="currentColor"
        strokeWidth={2}
        strokeLinecap="round"
        strokeDasharray={state === 'pending' ? `${c / 8 * 0.5} ${c / 8 * 0.5}` : `${arc * c} ${(1 - arc) * c}`}
        className={cn(
          // transform-box fill-box keeps the origin at the circle's own centre whatever the rendered size.
          'origin-center -rotate-90 [transform-box:fill-box] [transition:stroke-dasharray_200ms_var(--ease-out-curve)]',
          indeterminate && 'animate-spin-slow motion-reduce:animate-spin-slow',
          state === 'pending' && 'opacity-60',
        )}
      />
      {path ? (
        <path
          d={path}
          pathLength={1}
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          className={cn('[stroke-dasharray:1_2] [stroke-dashoffset:0]', draw && '[animation:leader-draw_var(--dur-draw)_var(--ease-out-curve)_1] motion-reduce:[animation:none]')}
        />
      ) : null}
    </svg>
  );
}
