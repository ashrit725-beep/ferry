import { useMemo } from 'react';
import { jsonTokens } from '../json.ts';
import { CopyButton } from './CopyButton.tsx';

/**
 * Read-only JSON with light highlighting. Tokens come from JSON.stringify
 * output and are rendered as text nodes, never as HTML. The block is
 * focusable so keyboard users can scroll it.
 */
export function JsonView({ value, short = false, copyLabel }: { value: unknown; short?: boolean; copyLabel?: string }) {
  const tokens = useMemo(() => jsonTokens(value), [value]);
  const text = useMemo(() => tokens.map((t) => t.text).join(''), [tokens]);
  return (
    <div className="json-view">
      {copyLabel ? (
        <div className="json-view__actions">
          <CopyButton text={text} label={copyLabel} withText />
        </div>
      ) : null}
      <pre className={short ? 'code-block code-block--short' : 'code-block'} tabIndex={0}>
        <code>
          {tokens.map((t, i) =>
            t.kind === 'punct' ? (
              t.text
            ) : (
              <span key={i} className={`json-${t.kind}`}>
                {t.text}
              </span>
            ),
          )}
        </code>
      </pre>
    </div>
  );
}
