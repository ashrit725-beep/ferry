/**
 * DotField. Source: Magic UI `dot-pattern` (fetched 2026-10-29, vetted
 * 2026-10-30), rewritten as two CSS gradients.
 * Purpose: the quiet ground behind the sign-in card, the only ambient motion
 * on that page: a dot field drifting diagonally, so slowly it reads as still.
 * Changes: no motion.circle per cell (5k nodes), no resize listener, no glow;
 * one radial-gradient tile on a layer twice the size moved by a 90 s
 * transform-only keyframe in index.css (--animate-dot-drift); a radial mask
 * fades the edges; `motion-reduce` stops the drift (static field); aria-hidden.
 * The parent needs `position: relative; overflow: hidden`.
 */

import { cn } from '@/lib/utils';

export interface DotFieldProps {
  /** Distance between dots in px. */
  spacing?: number;
  className?: string;
  /** Freeze the drift (for example while the tab is hidden). */
  still?: boolean;
}

export function DotField({ spacing = 24, className, still = false }: DotFieldProps) {
  return (
    <div
      aria-hidden="true"
      className={cn('pointer-events-none absolute inset-0 overflow-hidden text-rail-active [mask-image:radial-gradient(ellipse_at_center,#000_30%,transparent_75%)]', className)}
    >
      <div
        className={cn('absolute -top-6 -left-6 h-[calc(100%+48px)] w-[calc(100%+48px)]', still ? '' : 'animate-dot-drift motion-reduce:animate-none')}
        style={{
          backgroundImage: 'radial-gradient(currentColor 1px, transparent 1.6px)',
          backgroundSize: `${spacing}px ${spacing}px`,
        }}
      />
    </div>
  );
}
