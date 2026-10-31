import { useState } from 'react';

/**
 * True once `key` has differed from its value on the first settled render.
 * Confirming motion (a leader draw, a stamp landing) plays only for a state
 * that changed while the operator watched, never on mount, on a route change
 * or when data first arrives: while `settled` is false (a loading
 * placeholder) the baseline is not taken yet.
 */
export function useChangedSinceMount(key: string, settled = true): boolean {
  const [initial, setInitial] = useState<string | null>(settled ? key : null);
  const [changed, setChanged] = useState(false);
  if (initial === null) {
    if (settled) setInitial(key);
    return false;
  }
  const differs = key !== initial;
  if (differs && !changed) setChanged(true);
  return changed || differs;
}
