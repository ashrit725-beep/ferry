/**
 * AnimatedBeam. Source: Magic UI `animated-beam` (registry JSON fetched
 * 2026-10-29, vetted 2026-10-30), rewritten by hand.
 * Purpose: a one-way light that runs once along the track between two
 * elements (the lifecycle strip, the sign-in card) to say "this way, forward".
 * Changes: no xmlns, no "use client"; one pass instead of an endless loop
 * (replay by changing `play`); token colours (amber) through the CSSOM; the
 * svg is aria-hidden; the path is recomputed when the container, the end
 * points or the fonts change; under prefers-reduced-motion only the static
 * track is drawn (MotionConfig does not cover SVG attribute animation).
 */

import { useEffect, useId, useState, type RefObject } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { cn } from '@/lib/utils';
import { ease } from '@/lib/motion';

export interface AnimatedBeamProps {
  className?: string;
  containerRef: RefObject<HTMLElement | null>;
  fromRef: RefObject<HTMLElement | null>;
  toRef: RefObject<HTMLElement | null>;
  /** Change this value to run the beam again (for example when a stage is reached). */
  play?: number | string;
  curvature?: number;
  pathWidth?: number;
  /** Seconds for one pass. */
  duration?: number;
  delay?: number;
  /** Draw the static track as well as the beam. */
  track?: boolean;
}

export function AnimatedBeam({
  className,
  containerRef,
  fromRef,
  toRef,
  play = 0,
  curvature = 0,
  pathWidth = 2,
  duration = 0.6,
  delay = 0,
  track = true,
}: AnimatedBeamProps) {
  const id = useId();
  const reduce = useReducedMotion();
  const [pathD, setPathD] = useState('');
  const [size, setSize] = useState({ width: 0, height: 0 });

  useEffect(() => {
    const update = (): void => {
      const container = containerRef.current;
      const from = fromRef.current;
      const to = toRef.current;
      if (!container || !from || !to) return;
      const c = container.getBoundingClientRect();
      const a = from.getBoundingClientRect();
      const b = to.getBoundingClientRect();
      setSize({ width: c.width, height: c.height });
      const startX = a.left - c.left + a.width / 2;
      const startY = a.top - c.top + a.height / 2;
      const endX = b.left - c.left + b.width / 2;
      const endY = b.top - c.top + b.height / 2;
      setPathD(`M ${startX},${startY} Q ${(startX + endX) / 2},${startY - curvature} ${endX},${endY}`);
    };
    const observer = new ResizeObserver(update);
    for (const ref of [containerRef, fromRef, toRef]) if (ref.current) observer.observe(ref.current);
    update();
    let cancelled = false;
    document.fonts.ready.then(() => {
      if (!cancelled) update();
    });
    return () => {
      cancelled = true;
      observer.disconnect();
    };
  }, [containerRef, fromRef, toRef, curvature]);

  return (
    <svg
      aria-hidden="true"
      focusable="false"
      fill="none"
      width={size.width}
      height={size.height}
      viewBox={`0 0 ${size.width} ${size.height}`}
      className={cn('pointer-events-none absolute top-0 left-0', className)}
    >
      {track ? <path d={pathD} className="stroke-hairline" strokeWidth={pathWidth} strokeLinecap="round" /> : null}
      {reduce ? null : (
        <>
          <path d={pathD} strokeWidth={pathWidth} stroke={`url(#${id})`} strokeLinecap="round" />
          <defs>
            <motion.linearGradient
              key={String(play)}
              id={id}
              gradientUnits="userSpaceOnUse"
              initial={{ x1: '0%', x2: '0%', y1: '0%', y2: '0%' }}
              animate={{ x1: ['10%', '110%'], x2: ['0%', '100%'], y1: ['0%', '0%'], y2: ['0%', '0%'] }}
              transition={{ delay, duration, ease: [...ease.out] }}
            >
              <stop className="[stop-color:var(--amber)]" stopOpacity="0" />
              <stop className="[stop-color:var(--amber)]" />
              <stop offset="32.5%" className="[stop-color:var(--amber)]" />
              <stop offset="100%" className="[stop-color:var(--amber)]" stopOpacity="0" />
            </motion.linearGradient>
          </defs>
        </>
      )}
    </svg>
  );
}
