/**
 * BorderBeam. Sources: Magic UI `border-beam` and Motion Primitives
 * `border-trail` (fetched 2026-10-29, vetted 2026-10-30), rewritten by hand.
 * Purpose: a short amber light circling a card while the job inside it runs.
 * Changes: no "use client"; amber token instead of the orange-to-purple
 * gradient; nothing is drawn under prefers-reduced-motion or where
 * `offset-path: rect()` is unsupported, so the running state must also be in
 * text; mount it only while something runs (the loop is endless by design).
 * The parent needs `position: relative` and a border radius.
 */

import { motion, useReducedMotionConfig, type Transition } from 'motion/react';
import { cn } from '@/lib/utils';

export interface BorderBeamProps {
  className?: string;
  /** Length of the light in px. */
  size?: number;
  /** Seconds per lap. */
  duration?: number;
  transition?: Transition;
}

export function BorderBeam({ className, size = 48, duration = 4, transition }: BorderBeamProps) {
  const reduce = useReducedMotionConfig();
  if (reduce) return null;
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 hidden rounded-[inherit] border border-transparent [mask-clip:padding-box,border-box] [mask-composite:intersect] [mask-image:linear-gradient(transparent,transparent),linear-gradient(#000,#000)] supports-[offset-path:rect(0_auto_auto_0)]:block"
    >
      <motion.div
        className={cn('absolute aspect-square bg-linear-to-l from-amber via-amber/60 to-transparent', className)}
        style={{ width: size, offsetPath: `rect(0 auto auto 0 round ${size}px)` }}
        initial={{ offsetDistance: '0%' }}
        animate={{ offsetDistance: ['0%', '100%'] }}
        transition={transition ?? { repeat: Infinity, duration, ease: 'linear' }}
      />
    </div>
  );
}
