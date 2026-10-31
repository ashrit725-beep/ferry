/**
 * ScrambleText and useScramble. Source: Motion Primitives `text-scramble`
 * (fetched 2026-10-29, vetted 2026-10-30), rewritten by hand.
 * Purpose: a digest a user action just produced reveals left to right out of
 * hex noise, so a changed value is seen to change; the final text is one
 * plain text node and copies as such.
 * Changes: no motion.create in render, no "use client"; re-runs when the text
 * changes and clears its interval on cleanup (StrictMode-safe); default
 * charset is hex and only [0-9a-z] characters are masked; no scramble on
 * first paint unless `scrambleOnMount`; role="img" with the final text while
 * running; prefers-reduced-motion returns the final text at once.
 */

import { useEffect, useRef, useState } from 'react';
import { useReducedMotionConfig } from 'motion/react';
import { cn } from '@/lib/utils';

const HEX = '0123456789abcdef';

export interface ScrambleOptions {
  /** Total reveal time in ms. Keep it under a second: people compare digests. */
  duration?: number;
  /** Frame spacing in ms. */
  interval?: number;
  charset?: string;
  /** Scramble on first render too. Off by default: only a changed value animates. */
  scrambleOnMount?: boolean;
}

function mask(text: string, settled: number, charset: string): string {
  let out = '';
  for (let i = 0; i < text.length; i += 1) {
    const ch = text.charAt(i);
    out += i < settled || !/[0-9a-z]/i.test(ch) ? ch : charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return out;
}

export function useScramble(
  text: string,
  { duration = 320, interval = 40, charset = HEX, scrambleOnMount = false }: ScrambleOptions = {},
): readonly [string, boolean] {
  const reduce = useReducedMotionConfig();
  const revealed = useRef<string | null>(scrambleOnMount ? null : text);
  const [shown, setShown] = useState(text);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    if (reduce || text === '' || text.length > 80 || revealed.current === text) {
      revealed.current = text;
      setShown(text);
      setRunning(false);
      return;
    }
    const steps = Math.max(1, Math.round(duration / interval));
    let step = 0;
    setRunning(true);
    setShown(mask(text, 0, charset));
    const id = window.setInterval(() => {
      step += 1;
      if (step >= steps) {
        window.clearInterval(id);
        revealed.current = text;
        setShown(text);
        setRunning(false);
        return;
      }
      setShown(mask(text, Math.floor((step / steps) * text.length), charset));
    }, interval);
    return () => window.clearInterval(id);
  }, [text, duration, interval, charset, reduce]);

  return [shown, running] as const;
}

export function ScrambleText({ text, className, ...options }: { text: string; className?: string } & ScrambleOptions) {
  const [shown, running] = useScramble(text, options);
  return (
    <span className={cn(className)} role={running ? 'img' : undefined} aria-label={running ? text : undefined}>
      {shown}
    </span>
  );
}
