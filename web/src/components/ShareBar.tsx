import type { Segment } from '../metrics.ts';

/**
 * One horizontal bar split into proportional segments. It is a visual
 * summary only (hidden from assistive technology); the numbers it shows are
 * always also in an adjacent table with text labels, and each table row
 * carries the same swatch so segments can be matched without relying on hue.
 */
export function ShareBar<K extends string>({ segments }: { segments: readonly Segment<K>[] }) {
  return (
    <svg className="share-bar" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true" focusable="false">
      <rect className="track" x="0" y="0" width="100" height="8" rx="2" />
      {segments
        .filter((s) => s.share > 0)
        .map((s) => (
          <rect key={s.key} className={`swatch-${s.key}`} x={s.offset * 100} y="0" width={s.share * 100} height="8" />
        ))}
    </svg>
  );
}

export function Swatch({ name }: { name: string }) {
  return (
    <svg className="swatch" viewBox="0 0 10 10" width="10" height="10" aria-hidden="true" focusable="false">
      <rect className={`swatch-${name}`} x="0" y="0" width="10" height="10" rx="2" />
    </svg>
  );
}
