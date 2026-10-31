/**
 * Readout: a live monospace figure with its label. Numbers roll only when
 * `animated` is set and the value changes (never on mount or poll).
 */

import type { ReactNode } from 'react';
import { NumberTicker } from '../fx/number-ticker.tsx';
import { formatInt } from '../../format.ts';
import { cn } from '@/lib/utils';

export interface ReadoutProps {
  label: ReactNode;
  /** A number rolls through NumberTicker; anything else is rendered as given. */
  value: ReactNode;
  /** For numbers: how to print them (formatInt by default). */
  format?: (n: number) => string;
  /** Roll digits when the number changes after a user action. */
  animated?: boolean;
  hint?: ReactNode;
  /** Open the record behind the figure. */
  href?: string;
  /** Attention: the figure prints in amber. */
  attention?: boolean;
  size?: 'md' | 'lg';
  className?: string;
}

export function Readout({ label, value, format = formatInt, animated = false, hint, href, attention = false, size = 'md', className }: ReadoutProps) {
  const figure =
    typeof value === 'number' ? <NumberTicker value={value} format={format} animated={animated} /> : <span className="tabular-nums">{value === null || value === undefined ? '—' : value}</span>;
  const body = (
    <>
      <span className="block text-xs text-text-3">{label}</span>
      <span className={cn('mt-0.5 block font-mono leading-none tabular-nums', size === 'lg' ? 'text-2xl' : 'text-xl', attention ? 'text-amber' : 'text-bone')}>
        {figure}
      </span>
      {hint ? <span className="mt-1 block text-xs text-text-3">{hint}</span> : null}
    </>
  );
  return href ? (
    <a href={href} className={cn('block min-w-0 rounded-sm px-3 py-2 hover:bg-hover', className)}>
      {body}
    </a>
  ) : (
    <div className={cn('min-w-0 px-3 py-2', className)}>{body}</div>
  );
}

/** A row of readouts separated by hairlines. */
export function ReadoutRow({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('grid grid-cols-2 gap-px bg-hairline sm:grid-cols-4 2xl:grid-cols-8 *:bg-panel', className)}>{children}</div>;
}
