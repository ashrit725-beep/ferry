/**
 * Timestamps: relative time for scanning, the exact UTC time in the title,
 * and (with `exact`) also as visible text where the precise moment matters
 * and a hover is not enough, such as detail panels.
 *
 * Most timestamps record something that already happened. Disconnected
 * networks often lack NTP, so the server's clock can run ahead of the
 * browser's; such a value is shown as "just now" rather than "in 3 min".
 * Expiry and validity times pass `future` to show real future times.
 */

import { DASH, exactUtc, parseTime, relativeTime } from '../format.ts';
import { useNow } from '../now.tsx';

export function Time({
  value,
  fallback = DASH,
  exact = false,
  future = false,
}: {
  value: string | null | undefined;
  fallback?: string;
  exact?: boolean;
  future?: boolean;
}) {
  // The shared tick re-renders every few seconds; Date.now() keeps fresh values from reading as future.
  const now = Math.max(useNow(), Date.now());
  if (!value) return <span className="subtle">{fallback}</span>;
  const date = parseTime(value);
  if (!date) return <span>{value}</span>;
  const full = exactUtc(value);
  const text = !future && date.getTime() > now ? 'just now' : relativeTime(value, now);
  return (
    <time dateTime={date.toISOString()} title={full}>
      {text}
      {exact ? <span className="subtle"> ({full})</span> : null}
    </time>
  );
}
