/**
 * Status badges on the Stamp. The value is always written out; the tone adds
 * a glyph shape and a colour, so an unknown or future value still reads.
 */

import type { ReactNode } from 'react';
import { statusLabel, toneFor, type StatusDomain, type Tone } from '../../status.ts';
import { StatusMark } from '../fx/status-mark.tsx';
import { Stamp, toneToStamp } from './stamp.tsx';

export function ToneGlyph({ tone, size = 14 }: { tone: Tone; size?: number }) {
  return <StatusMark state={toneToStamp(tone)} size={size} />;
}

export function Badge({ tone, children, title, land = false }: { tone: Tone; children: ReactNode; title?: string | undefined; land?: boolean }) {
  return (
    <Stamp state={toneToStamp(tone)} title={title} land={land}>
      {children}
    </Stamp>
  );
}

export function StatusBadge({
  domain,
  value,
  label,
  title,
}: {
  domain: StatusDomain;
  value: string | null | undefined;
  label?: string | undefined;
  title?: string | undefined;
}) {
  return (
    <Badge tone={toneFor(domain, value)} title={title}>
      {label ?? (value ? statusLabel(value) : 'unknown')}
    </Badge>
  );
}
