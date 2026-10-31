/**
 * Timestamps: relative time for scanning, the exact UTC time in the title,
 * and (with `exact`) also as visible text. A server clock ahead of the
 * browser's reads "just now" unless `future` is set. Logic unchanged.
 */

import { DASH, exactUtc, parseTime, relativeTime } from '../../format.ts';
import { useNow } from '../../now.tsx';
import { cn } from '@/lib/utils';

export function Time({
  value,
  fallback = DASH,
  exact = false,
  future = false,
  className,
}: {
  value: string | null | undefined;
  fallback?: string;
  exact?: boolean;
  future?: boolean;
  className?: string;
}) {
  const now = Math.max(useNow(), Date.now());
  if (!value) return <span className={cn('text-text-3', className)}>{fallback}</span>;
  const date = parseTime(value);
  if (!date) return <span className={className}>{value}</span>;
  const full = exactUtc(value);
  const text = !future && date.getTime() > now ? 'just now' : relativeTime(value, now);
  return (
    <time dateTime={date.toISOString()} title={full} className={cn('font-sans text-xs tabular-nums', className)}>
      {text}
      {exact ? <span className="text-text-3"> ({full})</span> : null}
    </time>
  );
}
