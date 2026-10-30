/**
 * Status badges. The value is always written out; tone adds colour and a
 * glyph whose shape differs per tone (check, cross, exclamation, i, dot), so
 * the badge still reads correctly without colour.
 */

import type { ReactNode } from 'react';
import { statusLabel, toneFor, type StatusDomain, type Tone } from '../status.ts';
import { IconCheck, IconCross, IconDot, IconExclaim, IconInfo } from './Icons.tsx';

export function ToneGlyph({ tone }: { tone: Tone }) {
  switch (tone) {
    case 'ok':
      return <IconCheck strokeWidth={2.25} />;
    case 'bad':
      return <IconCross strokeWidth={2.25} />;
    case 'warn':
      return <IconExclaim strokeWidth={2.5} />;
    case 'info':
      return <IconInfo strokeWidth={2} />;
    default:
      return <IconDot />;
  }
}

export function Badge({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string | undefined }) {
  return (
    <span className={tone === 'neutral' ? 'badge' : `badge badge--${tone}`} title={title}>
      <ToneGlyph tone={tone} />
      {children}
    </span>
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
