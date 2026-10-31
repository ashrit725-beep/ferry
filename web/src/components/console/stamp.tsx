/**
 * Stamp: the stamped response of a checklist line. Six states, each a glyph
 * shape plus a word, so the state reads without colour. The states map one
 * to one onto the existing `Tone` from status.ts so every badge in the
 * console speaks the same language.
 */

import type { ReactNode } from 'react';
import type { Tone } from '../../status.ts';
import { StatusMark, type MarkState } from '../fx/status-mark.tsx';
import { useChangedSinceMount } from '@/hooks/use-changed';
import { cn } from '@/lib/utils';

export type StampState = 'confirmed' | 'pending' | 'failed' | 'warning' | 'info' | 'neutral';

export const STAMP_WORD: Record<StampState, string> = {
  confirmed: 'Confirmed',
  pending: 'Pending',
  failed: 'Failed',
  warning: 'Warning',
  info: 'Info',
  neutral: 'Neutral',
};

export function toneToStamp(tone: Tone): StampState {
  switch (tone) {
    case 'ok':
      return 'confirmed';
    case 'bad':
      return 'failed';
    case 'warn':
      return 'warning';
    case 'info':
      return 'info';
    default:
      return 'neutral';
  }
}

export function stampToTone(state: StampState): Tone {
  switch (state) {
    case 'confirmed':
      return 'ok';
    case 'failed':
      return 'bad';
    case 'warning':
    case 'pending':
      return 'warn';
    case 'info':
      return 'info';
    default:
      return 'neutral';
  }
}

export const STAMP_CLASS: Record<StampState, string> = {
  confirmed: 'text-ok bg-ok-subtle border-ok/40',
  pending: 'text-amber bg-amber-subtle border-amber/40',
  failed: 'text-bad bg-bad-subtle border-bad/40',
  warning: 'text-amber bg-amber-subtle border-amber/40',
  info: 'text-info bg-info-subtle border-info/40',
  neutral: 'text-neutral bg-neutral-subtle border-neutral/40',
};

export interface StampProps {
  state: StampState;
  /** The word. Defaults to the state's own word; always rendered. */
  children?: ReactNode;
  title?: string | undefined;
  /** Show the running ring instead of the state glyph (a job in flight). */
  running?: boolean;
  /** Play the landing animation when the state changes after mount (never on mount; static under reduced motion). */
  land?: boolean;
  size?: 'sm' | 'md';
  /** False while the stamp stands in for data still loading (see useChangedSinceMount). */
  settled?: boolean;
  className?: string;
}

export function Stamp({ state, children, title, running = false, land = true, size = 'sm', settled = true, className }: StampProps) {
  const mark: MarkState = running ? 'running' : state;
  const landKey = `${state}-${running ? 'r' : 's'}`;
  const changed = useChangedSinceMount(landKey, settled);
  const landing = land && changed;
  return (
    <span
      key={landing ? landKey : undefined}
      data-stamp=""
      data-state={state}
      title={title}
      className={cn(
        'inline-flex shrink-0 items-center gap-1 rounded-sm border font-medium tracking-[0.06em] whitespace-nowrap uppercase',
        size === 'sm' ? 'h-5 px-1.5 text-2xs' : 'h-6 px-2 text-xs',
        landing && 'animate-stamp',
        STAMP_CLASS[state],
        className,
      )}
    >
      <StatusMark state={mark} size={size === 'sm' ? 12 : 14} draw={changed} />
      <span data-stamp-word="">{children ?? STAMP_WORD[state]}</span>
    </span>
  );
}
