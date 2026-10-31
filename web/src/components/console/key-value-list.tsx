/**
 * KeyValueList: term/value pairs as a definition list; values in Azeret Mono
 * when `mono`, with a copy affordance when `copy` names what is copied.
 * Tuple entries whose value is null or undefined are skipped.
 */

import type { ReactNode } from 'react';
import { CopyButton } from './copy-button.tsx';
import { cn } from '@/lib/utils';

export type KeyValueItem =
  | readonly [string, ReactNode]
  | {
      term: string;
      value: ReactNode;
      mono?: boolean;
      /** The text to copy; the button is named "Copy {term}". */
      copy?: string;
    };

export interface KeyValueListProps {
  items: ReadonlyArray<KeyValueItem>;
  /** Wider term column (180 px instead of 120 px). */
  wide?: boolean;
  /** Pairs flow inline, separated by hairlines (summaries). */
  inline?: boolean;
  /** Terms are identifiers (configuration keys): set in mono. */
  monoTerms?: boolean;
  className?: string;
}

function normalise(item: KeyValueItem): { term: string; value: ReactNode; mono: boolean; copy: string | undefined } | null {
  if (Array.isArray(item)) {
    const [term, value] = item as readonly [string, ReactNode];
    return value === null || value === undefined ? null : { term, value, mono: false, copy: undefined };
  }
  const o = item as { term: string; value: ReactNode; mono?: boolean; copy?: string };
  return o.value === null || o.value === undefined ? null : { term: o.term, value: o.value, mono: o.mono ?? false, copy: o.copy };
}

/** "Event id" → "event id" for use mid-sentence; acronyms ("SHA-256") keep their case. */
function sentenceCase(term: string): string {
  const second = term.charAt(1);
  return second && second === second.toUpperCase() && second !== second.toLowerCase() ? term : term.charAt(0).toLowerCase() + term.slice(1);
}

export function KeyValueList({ items, wide = false, inline = false, monoTerms = false, className }: KeyValueListProps) {
  const rows = items.map(normalise).filter((r): r is NonNullable<typeof r> => r !== null);
  if (inline) {
    return (
      <dl className={cn('m-0 flex flex-wrap gap-x-4 gap-y-1 text-xs', className)}>
        {rows.map((r) => (
          <div key={r.term} className="flex items-baseline gap-1.5">
            <dt className="text-text-3">{r.term}</dt>
            <dd className={cn('m-0 text-bone', r.mono && 'font-mono')}>{r.value}</dd>
          </div>
        ))}
      </dl>
    );
  }
  return (
    // Under 640 px the term stacks over its value, so long values get the full width.
    <dl className={cn('m-0 grid gap-x-4 gap-y-1 text-sm max-sm:grid-cols-1 max-sm:gap-y-0', wide ? 'sm:grid-cols-[minmax(180px,max-content)_1fr]' : 'sm:grid-cols-[minmax(120px,max-content)_1fr]', className)}>
      {rows.map((r) => (
        <div key={r.term} className="contents">
          <dt className={cn('py-0.5 text-text-3 max-sm:pt-1.5 max-sm:pb-0 max-sm:text-xs', monoTerms && 'font-mono text-xs text-text-2')}>{r.term}</dt>
          <dd className={cn('m-0 min-w-0 py-0.5 text-bone [overflow-wrap:anywhere]', r.mono && 'font-mono text-xs')}>
            {r.copy ? (
              <span className="inline-flex items-center gap-1">
                <span>{r.value}</span>
                <CopyButton text={r.copy} label={`Copy ${sentenceCase(r.term)}`} />
              </span>
            ) : (
              r.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
