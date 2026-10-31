/**
 * NumberTicker. Source: Magic UI `number-ticker` (fetched 2026-10-29, vetted
 * 2026-10-30), rewritten by hand.
 * Purpose: a live readout whose digits roll to the new value when the number
 * the operator is watching changes.
 * Changes: no "use client"; the formatted value is in the DOM from first
 * paint (no count-up on mount); digits tween only when `animated` is true and
 * the value changes, in 250 ms with the project ease-out instead of a 1.2 s
 * spring; `format` takes the console's own formatter; a hoisted formatter
 * instead of one per tick; the ticking span is aria-hidden and the final
 * value sits in an sr-only sibling; prefers-reduced-motion swaps instantly.
 */

import { useEffect, useRef } from 'react';
import { animate, useMotionValue, useReducedMotionConfig } from 'motion/react';
import { cn } from '@/lib/utils';
import { duration, ease } from '@/lib/motion';

const INT = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

export interface NumberTickerProps {
  value: number;
  /** Roll the digits when the value changes. Off by default: polled values swap instantly. */
  animated?: boolean;
  format?: (n: number) => string;
  className?: string;
}

export function NumberTicker({ value, animated = false, format = (n) => INT.format(n), className }: NumberTickerProps) {
  const reduce = useReducedMotionConfig();
  const ref = useRef<HTMLSpanElement>(null);
  const mv = useMotionValue(value);
  const shown = useRef(value);

  useEffect(() => {
    const write = (n: number): void => {
      if (ref.current) ref.current.textContent = format(n);
    };
    if (!animated || reduce || shown.current === value) {
      shown.current = value;
      mv.jump(value);
      write(value);
      return;
    }
    shown.current = value;
    const unsubscribe = mv.on('change', (latest) => write(Math.round(latest)));
    const controls = animate(mv, value, { duration: duration.pop + 0.05, ease: [...ease.out] });
    return () => {
      unsubscribe();
      controls.stop();
      mv.jump(value);
      write(value);
    };
  }, [value, animated, reduce, mv, format]);

  return (
    <>
      <span ref={ref} aria-hidden="true" className={cn('inline-block tabular-nums', className)}>
        {format(value)}
      </span>
      <span className="sr-only">{format(value)}</span>
    </>
  );
}
