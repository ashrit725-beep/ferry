/**
 * CrossingBeam. Source: Aceternity `tracing-beam` (fetched 2026-10-29, vetted
 * 2026-10-30): the technique only, written fresh.
 * Purpose: the one ambient moment on Overview. A short lit streak runs left
 * to right along the lifecycle baseline, from the first stage marker across
 * the air gap to the furthest stage reached, once on mount and once whenever
 * `runKey` changes; then it fades. It never runs backwards.
 * Changes: no useScroll, useVelocity or SVG gradient; the marker positions are
 * measured from `[data-stage-marker]` elements in the parent (ResizeObserver),
 * so the beam follows any layout; under reduced motion nothing is drawn (the
 * static baseline carries the state); decorative only (aria-hidden).
 */

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { animate, motion, useMotionValue, useReducedMotionConfig } from 'motion/react';
import { ease } from '@/lib/motion';

export interface CrossingBeamProps {
  /** Index (in document order of `[data-stage-marker]`) the streak runs to; null draws nothing. */
  to: number | null;
  /** The streak runs again whenever this changes. */
  runKey: string;
  /** Seconds for the streak to travel. */
  duration?: number;
}

interface Geometry {
  xs: number[];
  y: number;
}

export function CrossingBeam({ to, runKey, duration = 1.1 }: CrossingBeamProps) {
  const reduce = useReducedMotionConfig();
  const layer = useRef<HTMLSpanElement>(null);
  const [geo, setGeo] = useState<Geometry | null>(null);
  const x = useMotionValue(0);
  const opacity = useMotionValue(0);

  useLayoutEffect(() => {
    const host = layer.current?.parentElement;
    if (!host) return;
    const measure = (): void => {
      const box = host.getBoundingClientRect();
      const markers = Array.from(host.querySelectorAll<HTMLElement>('[data-stage-marker]')).filter((m) => m.offsetParent !== null);
      if (markers.length === 0) {
        setGeo(null);
        return;
      }
      const rects = markers.map((m) => m.getBoundingClientRect());
      const first = rects[0];
      setGeo({
        xs: rects.map((r) => r.left + r.width / 2 - box.left),
        y: first ? first.top + first.height / 2 - box.top : 0,
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(host);
    return () => observer.disconnect();
  }, []);

  const start = geo?.xs[0] ?? null;
  const end = to !== null && geo ? (geo.xs[to] ?? null) : null;

  useEffect(() => {
    if (reduce || start === null || end === null || end <= start) {
      opacity.set(0);
      return;
    }
    x.set(start);
    opacity.set(1);
    const travel = animate(x, end, { duration, ease: [...ease.out] });
    const fade = animate(opacity, 0, { duration: 0.25, delay: duration, ease: [...ease.out] });
    return () => {
      travel.stop();
      fade.stop();
    };
    // Run once per runKey (and when the layout first becomes measurable), not on every resize.
  }, [runKey, reduce, start === null, end === null]);

  return (
    <span ref={layer} aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      {geo && !reduce ? (
        <motion.span
          className="absolute h-1 w-16 -translate-x-full -translate-y-1/2 rounded-full bg-linear-to-r from-transparent to-bone"
          // Positioned once at the left edge; the travel is a transform (x), never layout.
          style={{ left: 0, top: geo.y, x, opacity }}
        />
      ) : null}
    </span>
  );
}
