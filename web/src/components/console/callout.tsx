/**
 * Callout: a tinted, hairline-bordered note with the state glyph; Notice: a
 * polite one-line result; RefreshButton: never disabled while busy.
 */

import { useEffect, useRef, type ReactNode } from 'react';
import { RefreshCw } from 'lucide-react';
import type { Tone } from '../../status.ts';
import { StatusMark } from '../fx/status-mark.tsx';
import { Button } from '../ui/button.tsx';
import { STAMP_CLASS, toneToStamp } from './stamp.tsx';
import { cn } from '@/lib/utils';

const CALLOUT_CLASS: Record<Tone, string> = {
  ok: 'border-ok/40 bg-ok-subtle [&_[data-glyph]]:text-ok',
  warn: 'border-amber/40 bg-amber-subtle [&_[data-glyph]]:text-amber',
  bad: 'border-bad/40 bg-bad-subtle [&_[data-glyph]]:text-bad',
  info: 'border-info/40 bg-info-subtle [&_[data-glyph]]:text-info',
  neutral: 'border-hairline bg-raised [&_[data-glyph]]:text-neutral',
};

export function Callout({
  tone = 'neutral',
  title,
  children,
  role,
  className,
}: {
  tone?: Tone;
  title?: ReactNode;
  children?: ReactNode;
  role?: 'alert' | 'status';
  className?: string;
}) {
  return (
    <div role={role} className={cn('flex gap-2 rounded-sm border px-3 py-2 text-sm text-bone', CALLOUT_CLASS[tone], className)}>
      <span data-glyph className="mt-0.5 shrink-0">
        <StatusMark state={toneToStamp(tone)} size={16} />
      </span>
      <div className="min-w-0 flex-1 [&_ul]:mt-1 [&_ul]:list-disc [&_ul]:pl-4 [&_p+p]:mt-1 text-pretty">
        {title ? <p className="font-medium">{title}</p> : null}
        {children}
      </div>
    </div>
  );
}

export interface NoticeMessage {
  text: string;
  /** Move focus to the message (for actions that remove the control that triggered them). */
  focus?: boolean;
}

/** Result of an action, announced politely. A new object re-announces (and re-focuses) the same text. */
export function Notice({ notice, tone = 'ok' }: { notice: NoticeMessage | null; tone?: Tone }) {
  const ref = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (notice?.focus) ref.current?.focus();
  }, [notice]);
  if (!notice) return null;
  return (
    <p ref={ref} role="status" tabIndex={-1} className={cn('inline-flex items-center gap-1.5 rounded-sm border px-2 py-1 text-xs', STAMP_CLASS[toneToStamp(tone)])}>
      <StatusMark state={toneToStamp(tone)} size={12} />
      <span className="text-bone normal-case tracking-normal">{notice.text}</span>
    </p>
  );
}

/**
 * Not `disabled` while busy: disabling the focused button would drop keyboard
 * focus to the page body. Clicks during a refresh are ignored instead.
 */
export function RefreshButton({ onClick, busy, label = 'Refresh' }: { onClick: () => void; busy: boolean; label?: string }) {
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => {
        if (!busy) onClick();
      }}
      aria-busy={busy || undefined}
      data-busy={busy || undefined}
    >
      <RefreshCw aria-hidden="true" className={cn(busy && 'animate-spin motion-reduce:animate-spin')} />
      {label}
    </Button>
  );
}
