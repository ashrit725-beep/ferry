/**
 * Derived figures for the overview. Everything here is arithmetic on numbers
 * the server reported; nothing is estimated or filled in.
 */

import { ENVIRONMENTS, TRAFFIC_OUTCOMES, type Environment, type Traffic, type TrafficByEnvironment, type TrafficOutcome } from './api.ts';

export interface Segment<K extends string> {
  key: K;
  count: number;
  /** Fraction of the sum of all segments, 0..1. */
  share: number;
  /** Sum of the shares of the segments before this one, 0..1. */
  offset: number;
}

function segments<K extends string>(keys: readonly K[], countOf: (key: K) => number): Segment<K>[] {
  const counts = keys.map((key) => {
    const raw = countOf(key);
    return Number.isFinite(raw) && raw > 0 ? raw : 0;
  });
  const sum = counts.reduce((a, b) => a + b, 0);
  let offset = 0;
  return keys.map((key, i) => {
    const count = counts[i] ?? 0;
    const share = sum > 0 ? count / sum : 0;
    const segment = { key, count, share, offset };
    offset += share;
    return segment;
  });
}

export function trafficSegments(traffic: Traffic): Segment<TrafficOutcome>[] {
  return segments(TRAFFIC_OUTCOMES, (o) => traffic[o]);
}

export function environmentSegments(byEnv: TrafficByEnvironment): Segment<Environment>[] {
  return segments(ENVIRONMENTS, (e) => byEnv[e]);
}

/** Labels follow the gateway outcomes in spec section 8; the hint says which responses they cover. */
export const OUTCOME_TEXT: Record<TrafficOutcome, { label: string; hint: string }> = {
  success: { label: 'Success', hint: 'answered by a backend' },
  denied: { label: 'Denied', hint: 'refused by the access policy' },
  error: { label: 'Error', hint: 'backend failed or timed out' },
  unavailable: { label: 'Unavailable', hint: 'route backend down or provenance not verified' },
  rejected: { label: 'Rejected', hint: 'invalid request, unknown model or limit exceeded' },
  unauthenticated: { label: 'Unauthenticated', hint: 'missing, unknown or revoked API key' },
};
