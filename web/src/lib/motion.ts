/**
 * JS mirror of the motion tokens in index.css, for `motion/react` transitions.
 * Durations are seconds (motion's unit); the CSS tokens are milliseconds.
 */

import type { Transition } from 'motion/react';

export const duration = { fast: 0.125, base: 0.15, pop: 0.2, draw: 0.24, stamp: 0.18, sheet: 0.3 } as const;

export const ease = {
  out: [0.23, 1, 0.32, 1],
  inOut: [0.77, 0, 0.175, 1],
  drawer: [0.32, 0.72, 0, 1],
} as const satisfies Record<string, readonly [number, number, number, number]>;

/** The three presets page agents should reach for. */
export const presets = {
  /** State change, enter, exit, press: 150 ms exponential ease-out. */
  state: { duration: duration.base, ease: ease.out } satisfies Transition,
  /** Popover, dialog, toast content: 200 ms ease-out. */
  pop: { duration: duration.pop, ease: ease.out } satisfies Transition,
  /** A checklist line confirming: the leader draws in 240 ms, the stamp lands in 180 ms. */
  confirm: { duration: duration.draw, ease: ease.out } satisfies Transition,
} as const;

export const stagger = 0.03;
