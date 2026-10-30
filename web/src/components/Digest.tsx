/**
 * Digests and key ids: monospace, shortened for scanning, the full value in
 * the title and one click away on the clipboard.
 */

import { DASH, shortDigest, shortKeyId } from '../format.ts';
import { CopyButton } from './CopyButton.tsx';

export function Digest({
  value,
  label = 'digest',
  head,
  tail,
  full = false,
}: {
  value: string | null | undefined;
  label?: string;
  head?: number;
  tail?: number;
  /** Show the whole value, wrapping as needed (detail panels). */
  full?: boolean;
}) {
  if (!value) return <span className="subtle">{DASH}</span>;
  return (
    <span className={full ? 'digest digest--full' : 'digest'}>
      <code title={value}>{full ? value : shortDigest(value, head, tail)}</code>
      <CopyButton text={value} label={`Copy ${label}`} />
    </span>
  );
}

export function KeyId({ value, label = 'key id' }: { value: string; label?: string }) {
  return (
    <span className="digest">
      <code title={value}>{shortKeyId(value)}</code>
      <CopyButton text={value} label={`Copy ${label}`} />
    </span>
  );
}
