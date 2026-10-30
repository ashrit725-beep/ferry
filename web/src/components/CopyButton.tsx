import { useEffect, useRef, useState } from 'react';
import { copyText } from '../clipboard.ts';
import { IconCheck, IconCopy, IconCross } from './Icons.tsx';

type CopyState = 'idle' | 'copied' | 'failed';

/**
 * Button that copies `text`. `label` ("Copy API key") is the accessible name
 * for both variants, so several copy buttons on a page stay distinguishable.
 * The result is announced through a polite live region next to the button,
 * which keeps working inside modal dialogs (a page-level announcer would be
 * inert behind the modal).
 */
export function CopyButton({ text, label, withText = false }: { text: string; label: string; withText?: boolean }) {
  const [state, setState] = useState<CopyState>('idle');
  const ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (state === 'idle') return undefined;
    const id = window.setTimeout(() => setState('idle'), 2000);
    return () => window.clearTimeout(id);
  }, [state]);

  const onClick = async (): Promise<void> => {
    setState((await copyText(text, ref.current)) ? 'copied' : 'failed');
  };

  const hint = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed; select the text and copy it manually' : label;
  const icon = state === 'copied' ? <IconCheck /> : state === 'failed' ? <IconCross /> : <IconCopy />;

  return (
    <>
      <button
        ref={ref}
        type="button"
        className={withText ? 'button button--small' : 'copy-button'}
        data-state={state}
        aria-label={label}
        title={hint}
        onClick={() => void onClick()}
      >
        {icon}
        {withText ? (state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy') : null}
      </button>
      <span className="sr-only" role="status">
        {state === 'copied' ? 'Copied to clipboard.' : state === 'failed' ? 'Copy failed.' : ''}
      </span>
    </>
  );
}
