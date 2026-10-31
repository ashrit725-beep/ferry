/**
 * Copies `text`. `label` ("Copy API key") is the accessible name for both
 * variants, so several copy buttons on a page stay distinguishable. The
 * result is announced through a polite live region next to the button, which
 * keeps working inside modal dialogs. The icon-only variant draws at 24 px
 * with a 40 px hit area.
 */

import { useEffect, useRef, useState } from 'react';
import { Check, Copy, X } from 'lucide-react';
import { copyText } from '../../clipboard.ts';
import { Button } from '../ui/button.tsx';
import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip.tsx';
import { cn } from '@/lib/utils';

type CopyState = 'idle' | 'copied' | 'failed';

export function CopyButton({ text, label, withText = false, className }: { text: string; label: string; withText?: boolean; className?: string }) {
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
  const Icon = state === 'copied' ? Check : state === 'failed' ? X : Copy;
  const tone = state === 'copied' ? 'text-ok' : state === 'failed' ? 'text-bad' : '';

  return (
    <>
      {withText ? (
        <Button ref={ref} type="button" variant="outline" size="sm" data-state={state} aria-label={label} title={hint} onClick={() => void onClick()} className={cn(tone, className)}>
          <Icon aria-hidden="true" />
          {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy'}
        </Button>
      ) : (
        // The themed tooltip (shown on hover and on keyboard focus) carries the name, then the result.
        <Tooltip>
          <TooltipTrigger
            render={
              <button
                ref={ref}
                type="button"
                data-state={state}
                aria-label={label}
                onClick={() => void onClick()}
                className={cn(
                  'relative inline-flex size-6 shrink-0 items-center justify-center rounded-sm text-text-3 hover:bg-hover hover:text-bone after:absolute after:-inset-2 after:content-[""]',
                  tone,
                  className,
                )}
              >
                <Icon aria-hidden="true" className="size-3.5" />
              </button>
            }
          />
          <TooltipContent>{hint}</TooltipContent>
        </Tooltip>
      )}
      <span className="sr-only" role="status">
        {state === 'copied' ? 'Copied to clipboard.' : state === 'failed' ? 'Copy failed.' : ''}
      </span>
    </>
  );
}
