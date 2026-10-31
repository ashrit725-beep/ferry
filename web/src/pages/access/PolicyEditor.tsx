/**
 * The policy JSON editor: a monospace textarea with a line-number gutter that
 * scrolls with it. Lines do not wrap, so the gutter stays aligned; the line
 * a syntax error points at is marked in the gutter. A parse error is
 * announced (role="alert") and the caller can place the caret at it.
 */

import { useId, useImperativeHandle, useRef, type ReactNode, type Ref } from 'react';
import { cn } from '@/lib/utils';

export interface EditorHandle {
  /** Focus the editor and, when given, put the caret at this offset. */
  focusAt: (offset: number | null) => void;
}

export interface EditorParseProblem {
  message: string;
  line: number | null;
  column: number | null;
}

export function PolicyEditor({
  ref,
  value,
  onChange,
  parseProblem,
  hint,
  rows = 24,
}: {
  ref?: Ref<EditorHandle>;
  value: string;
  onChange: (text: string) => void;
  parseProblem: EditorParseProblem | null;
  hint: ReactNode;
  rows?: number;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const parseId = `${id}-parse`;
  const areaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);

  useImperativeHandle(ref, () => ({
    focusAt: (offset) => {
      const el = areaRef.current;
      if (!el) return;
      el.focus();
      if (offset !== null) el.setSelectionRange(offset, offset);
    },
  }), []);

  const lineCount = Math.max(1, value.split('\n').length);
  const errorLine = parseProblem?.line ?? null;

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-text-2">
        Policy JSON <span className="font-normal text-text-3">(schema ferry.dev/access-policy/v1)</span>
      </label>
      <div
        className={cn(
          'flex overflow-hidden rounded-sm border bg-inset focus-within:border-amber focus-within:ring-2 focus-within:ring-amber/40',
          parseProblem ? 'border-bad' : 'border-line-control',
        )}
      >
        <div
          ref={gutterRef}
          aria-hidden="true"
          className="shrink-0 overflow-hidden border-r border-hairline py-2 pr-2 pl-3 text-right font-mono text-xs leading-5 text-text-3 tabular-nums select-none"
        >
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i} className={cn(errorLine === i + 1 && 'text-bad')}>
              {i + 1}
            </div>
          ))}
        </div>
        <textarea
          id={id}
          ref={areaRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onScroll={(e) => {
            if (gutterRef.current) gutterRef.current.scrollTop = e.currentTarget.scrollTop;
          }}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          autoCorrect="off"
          wrap="off"
          rows={rows}
          aria-describedby={parseProblem ? `${parseId} ${hintId}` : hintId}
          aria-invalid={parseProblem ? true : undefined}
          className="min-w-0 flex-1 resize-y bg-transparent px-3 py-2 font-mono text-xs leading-5 whitespace-pre text-bone outline-none"
        />
      </div>
      {parseProblem ? (
        <p id={parseId} className="text-xs text-bad" role="alert">
          Not valid JSON: {parseProblem.message}
          {parseProblem.line !== null ? ` (line ${parseProblem.line}, column ${parseProblem.column})` : ''}.
        </p>
      ) : null}
      <p id={hintId} className="text-xs text-text-3 text-pretty">
        {hint}
      </p>
    </div>
  );
}
