/**
 * The signature move: a challenge/response line. ITEM ....... VALUE [STAMP].
 * The dotted leader draws left to right when the line's state changes after
 * mount (240 ms ease-out; static on mount, on route changes and under reduced
 * motion), and the stamp lands (180 ms). A Checklist groups lines under a section label.
 */

import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { useChangedSinceMount } from '@/hooks/use-changed';
import { cn } from '@/lib/utils';
import { Stamp, type StampState } from './stamp.tsx';

export interface ChecklistLineProps {
  /** The challenge: what is being confirmed. */
  label: ReactNode;
  state: StampState;
  /** The response's evidence: a count, a summary, a time (Archivo, tabular numerals); digests and ids bring their own mono. */
  value?: ReactNode;
  /** Replaces the stamp's default word ("Verified", "Intact", "Awaiting reviewer"). */
  stamp?: ReactNode;
  /** Second line under the label: what to do next, or why. */
  detail?: ReactNode;
  /** The label becomes a link to the record. */
  href?: string;
  /** The label becomes a button. */
  onClick?: () => void;
  /** A control that belongs to the line (the primary action on the first pending line). */
  action?: ReactNode;
  /** Something is running for this line. */
  pending?: boolean;
  /** Redraw the leader and re-land the stamp when this changes. */
  drawKey?: string | number;
  /** False for a loading placeholder: the first real state that replaces it does not count as a change. */
  settled?: boolean;
  as?: 'li' | 'div';
  className?: string;
  id?: string;
}

export function ChecklistLine({ label, state, value, stamp, detail, href, onClick, action, pending = false, drawKey, settled = true, as = 'li', className, id }: ChecklistLineProps) {
  const Tag = as;
  const key = `${state}:${drawKey ?? ''}`;
  const changed = useChangedSinceMount(key, settled);
  // The label is the line's link; its ::after stretches over the whole line so
  // the response and stamp (the evidence) open the record too. Controls inside
  // the line sit above that layer.
  const stretch = "after:absolute after:inset-0 after:content-['']";
  const labelNode = href ? (
    <a href={href} className={cn('rounded-sm text-bone underline-offset-3 group-hover/line:underline', stretch)}>
      {label}
    </a>
  ) : onClick ? (
    <button type="button" onClick={onClick} className={cn('rounded-sm text-left text-bone underline-offset-3 group-hover/line:underline', stretch)}>
      {label}
    </button>
  ) : (
    <span className="text-bone">{label}</span>
  );
  const linked = Boolean(href || onClick);
  return (
    <Tag id={id} data-state={state} className={cn('group/line relative min-h-8 py-1', linked && 'hover:bg-hover/40', className)}>
      {/* Item and leader, then the response; the response drops to its own line, right-aligned, only when it does not fit. */}
      <div className="flex min-h-6 flex-wrap items-center gap-x-2 gap-y-0.5">
        <span className="max-w-full min-w-0 shrink-0 text-sm text-pretty">{labelNode}</span>
        <span key={changed ? key : 'leader'} aria-hidden="true" className={cn('mb-1.5 min-w-4 flex-1 origin-left self-end border-b border-dotted border-leader [border-bottom-width:1.5px]', changed && 'animate-leader')} />
        <span className="ml-auto flex max-w-full min-w-0 flex-wrap items-center justify-end gap-x-2 gap-y-1">
          {value !== undefined && value !== null ? (
            <span className="min-w-0 font-sans text-xs break-words text-text-2 tabular-nums [&_a]:relative [&_a]:z-10 [&_button]:relative [&_button]:z-10">{value}</span>
          ) : null}
          {pending ? <Loader2 aria-hidden="true" className="size-3.5 shrink-0 animate-spin text-amber motion-reduce:animate-spin" /> : null}
          <Stamp key={changed ? `s-${key}` : 's'} state={state} running={pending} land={false} settled={settled} className={changed ? 'animate-stamp' : undefined}>
            {stamp}
          </Stamp>
          {action ? <span className="relative z-10 shrink-0">{action}</span> : null}
        </span>
      </div>
      {detail ? <div className="relative z-10 w-fit max-w-full pt-0.5 text-xs text-text-3 text-pretty">{detail}</div> : null}
    </Tag>
  );
}

export interface ChecklistProps {
  /** Section label, set in caps with wide tracking. */
  label?: ReactNode;
  /** The count or state summary at the end of the label row. */
  summary?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Use `div` when lines are not list items. */
  as?: 'ol' | 'ul' | 'div';
  ariaLabel?: string;
  /** Classes for the list itself (columns for a long list). */
  listClassName?: string;
}

export function Checklist({ label, summary, children, className, as = 'ol', ariaLabel, listClassName }: ChecklistProps) {
  const List = as;
  return (
    <section className={cn('min-w-0', className)} aria-label={ariaLabel}>
      {label || summary ? (
        <div className="mb-1 flex items-baseline justify-between gap-3">
          {label ? <h3 className="text-2xs font-medium tracking-[0.14em] text-text-3 uppercase">{label}</h3> : <span />}
          {summary ? <span className="text-2xs text-text-3 tabular-nums">{summary}</span> : null}
        </div>
      ) : null}
      <List className={cn('m-0 list-none divide-y divide-hairline p-0', as === 'div' && 'flex flex-col', listClassName)}>{children}</List>
    </section>
  );
}
