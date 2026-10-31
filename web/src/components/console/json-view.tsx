/**
 * Read-only JSON with light highlighting. Tokens come from JSON.stringify
 * output and are rendered as text nodes, never as HTML. Focusable so keyboard
 * users can scroll it. Logic unchanged.
 */

import { useMemo } from 'react';
import { jsonTokens, type JsonTokenKind } from '../../json.ts';
import { CopyButton } from './copy-button.tsx';
import { cn } from '@/lib/utils';

const TOKEN_CLASS: Record<Exclude<JsonTokenKind, 'punct'>, string> = {
  key: 'text-text-2',
  string: 'text-bone',
  number: 'text-info',
  literal: 'text-info',
};

export function JsonView({ value, short = false, copyLabel, className }: { value: unknown; short?: boolean; copyLabel?: string; className?: string }) {
  const tokens = useMemo(() => jsonTokens(value), [value]);
  const text = useMemo(() => tokens.map((t) => t.text).join(''), [tokens]);
  return (
    <div className={cn('relative rounded-sm border border-hairline bg-inset', className)}>
      {copyLabel ? (
        <div className="absolute top-1 right-1 z-10">
          <CopyButton text={text} label={copyLabel} />
        </div>
      ) : null}
      <pre tabIndex={0} className={cn('m-0 overflow-auto px-3 py-2 font-mono text-xs leading-5 text-bone', short ? 'max-h-60' : 'max-h-[480px]')}>
        <code>
          {tokens.map((t, i) =>
            t.kind === 'punct' ? (
              t.text
            ) : (
              <span key={i} className={TOKEN_CLASS[t.kind]}>
                {t.text}
              </span>
            ),
          )}
        </code>
      </pre>
    </div>
  );
}
