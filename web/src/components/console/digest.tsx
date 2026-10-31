/**
 * Digests and key ids: Azeret Mono, middle-truncated for scanning, the full
 * value in the title and one click away on the clipboard. `reveal` runs the
 * scramble reveal for a digest the operator's own action just produced.
 */

import { Fragment, useLayoutEffect, useRef } from 'react';
import { DASH, shortDigest, shortKeyId } from '../../format.ts';
import { ScrambleText } from '../fx/scramble-text.tsx';
import { CopyButton } from './copy-button.tsx';
import { cn } from '@/lib/utils';

export interface DigestProps {
  value: string | null | undefined;
  label?: string;
  head?: number;
  tail?: number;
  /** Show the whole value, wrapping as needed (detail panels). */
  full?: boolean;
  /** Reveal with a short scramble when the value changes (never in tables). */
  reveal?: boolean;
  /** Hide the copy button. */
  copy?: boolean;
  className?: string;
}

export function Digest({ value, label = 'digest', head, tail, full = false, reveal = false, copy = true, className }: DigestProps) {
  if (!value) return <span className="text-text-3">{DASH}</span>;
  const shown = full ? value : shortDigest(value, head, tail);
  // "sha256:" and the hash: on a phone the hash may drop under its prefix rather than run past the box.
  const split = !full && !reveal ? /^([a-z0-9]+:)(.+)$/i.exec(shown) : null;
  return (
    <span className={cn('inline-flex max-w-full items-center gap-1 align-baseline', className)}>
      <code
        title={value}
        className={cn(
          'font-mono text-xs text-bone select-all',
          full ? '[overflow-wrap:anywhere] whitespace-pre-wrap' : 'whitespace-nowrap',
          split && 'max-sm:inline-flex max-sm:min-w-0 max-sm:flex-wrap',
        )}
      >
        {reveal ? (
          <ScrambleText text={shown} />
        ) : split ? (
          <>
            <span>{split[1]}</span>
            <span>{split[2]}</span>
          </>
        ) : (
          shown
        )}
      </code>
      {copy ? <CopyButton text={value} label={`Copy ${label}`} /> : null}
    </span>
  );
}

export function KeyId({ value, label = 'key id', reveal = false }: { value: string; label?: string; reveal?: boolean }) {
  const shown = shortKeyId(value);
  return (
    <span className="inline-flex items-center gap-1 align-baseline">
      <code title={value} className="font-mono text-xs whitespace-nowrap text-bone select-all">
        {reveal ? <ScrambleText text={shown} /> : shown}
      </code>
      <CopyButton text={value} label={`Copy ${label}`} />
    </span>
  );
}

/**
 * A path or file name that wraps only after a "/" separator, never inside a
 * name. Long names stay whole; the cell grows or scrolls instead.
 */
export function PathText({ value, whole = false, className }: { value: string; whole?: boolean; className?: string }) {
  const parts = value.split('/');
  if (whole) {
    // Each segment stays whole and breaks only after its "/"; one wider than
    // the box is middle-truncated, the full path in the title.
    return (
      <code title={value} className={cn('font-mono', className)}>
        {parts.map((part, i) => (
          <Fragment key={i}>
            {i > 0 ? <wbr /> : null}
            <MonoId value={i < parts.length - 1 ? `${part}/` : part} tail={i < parts.length - 1 ? 8 : 14} title={value} />
          </Fragment>
        ))}
      </code>
    );
  }
  return (
    // Breaks after "/" first; a segment wider than its box falls back to its
    // hyphens, then (overflow-wrap) anywhere, rather than being clipped.
    <code className={cn('font-mono [overflow-wrap:break-word]', className)}>
      {parts.map((part, i) => (
        <span key={i}>
          <span>{part}</span>
          {i < parts.length - 1 ? (
            <>
              /<wbr />
            </>
          ) : null}
        </span>
      ))}
    </code>
  );
}

/**
 * A long path middle-truncated to its first segment and its last characters
 * ("/var/…/blobs/sha256-5b5a…"), the full value in the title and on the
 * clipboard.
 */
export function TruncatedPath({ value, label = 'path', tail = 24, copy = true, className }: { value: string; label?: string; tail?: number; copy?: boolean; className?: string }) {
  const first = value.startsWith('/') ? `/${value.slice(1).split('/')[0] ?? ''}` : (value.split('/')[0] ?? '');
  const shown = value.length <= first.length + tail + 2 ? value : `${first}/…${value.slice(-tail)}`;
  return (
    <span className={cn('inline-flex max-w-full items-center gap-1 align-baseline', className)}>
      <code title={value} className="min-w-0 truncate font-mono text-xs whitespace-nowrap text-text-2">
        {shown}
      </code>
      {copy ? <CopyButton text={value} label={`Copy ${label}`} /> : null}
    </span>
  );
}

/**
 * A model, backend or bundle name: one mono run that never wraps. When its box
 * is narrower than the name it is middle-truncated (the head ellipsised, the
 * last characters kept), with the whole name in the title and in a copy or
 * selection of the text.
 */
export function MonoId({ value, tail = 8, title, className }: { value: string; tail?: number; title?: string; className?: string }) {
  const headRef = useRef<HTMLSpanElement>(null);
  const tailRef = useRef<HTMLSpanElement>(null);
  const short = value.length <= tail + 4;
  // A truncated head is rarely a whole number of characters wide, so up to 1ch
  // of blank would sit between its "…" and the tail and read as two tokens.
  // The tail is shifted left by that remainder (a transform: layout is unchanged).
  useLayoutEffect(() => {
    const h = headRef.current;
    const t = tailRef.current;
    if (!h || !t) return;
    const update = (): void => {
      const chars = t.textContent?.length ?? 0;
      const ch = chars > 0 ? t.getBoundingClientRect().width / chars : 0;
      const w = h.getBoundingClientRect().width;
      const gap = ch > 0 && h.scrollWidth > h.clientWidth ? w - Math.floor(w / ch + 0.02) * ch : 0;
      t.style.setProperty('--mono-gap', `${gap > 0.25 ? gap.toFixed(2) : 0}px`);
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(h);
    observer.observe(t);
    return () => observer.disconnect();
  }, [value, short]);
  if (short) {
    return (
      <code title={title ?? value} className={cn('font-mono whitespace-nowrap', className)}>
        {value}
      </code>
    );
  }
  // Keep the tail from a separator when one is near ("…-instruct", not "…instruct").
  const cut = value.length - tail;
  const sep = Math.max(value.lastIndexOf('-', cut + 3), value.lastIndexOf('_', cut + 3), value.lastIndexOf(' ', cut + 3));
  const at = sep >= cut - 4 && sep > 0 ? sep : cut;
  return (
    <code title={title ?? value} className={cn('inline-flex max-w-full min-w-0 align-bottom font-mono whitespace-nowrap', className)}>
      <span ref={headRef} className="min-w-[3ch] truncate">
        {value.slice(0, at)}
      </span>
      <span ref={tailRef} className="shrink-0 whitespace-pre [translate:calc(var(--mono-gap,0px)*-1)_0]">
        {value.slice(at)}
      </span>
    </code>
  );
}
