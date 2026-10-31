/**
 * Modal dialog on the Base UI dialog: focus trapped, Escape closes through
 * onClose (React state stays the source of truth), focus returns to the
 * opener, backdrop click does not close. Same props as the old Dialog.
 */

import { useRef, type ReactNode, type RefObject } from 'react';
import { X } from 'lucide-react';
import { Dialog as DialogRoot, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/dialog.tsx';
import { IconButton } from './icon-button.tsx';
import { cn } from '@/lib/utils';

export interface DialogProps {
  open: boolean;
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  /** Element to focus when the dialog opens; defaults to the first control in the body. */
  initialFocus?: RefObject<HTMLElement | null>;
  /** role="alertdialog": a confirmation that interrupts the current task. */
  alert?: boolean;
  /** Keep the dialog open on Escape and outside click (the one-time key view until copied). */
  locked?: boolean;
}

export function Dialog({ open, title, description, onClose, children, footer, wide = false, initialFocus, alert = false, locked = false }: DialogProps) {
  const bodyRef = useRef<HTMLDivElement>(null);
  return (
    <DialogRoot
      open={open}
      onOpenChange={(next) => {
        if (!next && !locked) onClose();
      }}
      disablePointerDismissal
    >
      <DialogContent
        // Spread only when alert: an explicit undefined would erase Base UI's role="dialog".
        {...(alert ? { role: 'alertdialog' } : {})}
        showCloseButton={false}
        initialFocus={initialFocus ?? ((): HTMLElement | null => bodyRef.current?.querySelector<HTMLElement>('a[href], button, input:not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])') ?? null)}
        // Header, body, footer: the body is the only row that scrolls, so the title and
        // the footer actions stay on screen on a phone (dvh follows the browser's toolbars).
        className={cn(
          'max-h-[calc(100dvh-2rem)] grid-rows-[auto_minmax(0,1fr)_auto] gap-0 overflow-hidden rounded-lg bg-raised p-0 ring-hairline shadow-float',
          wide ? 'sm:max-w-[880px]' : 'sm:max-w-[560px]',
        )}
      >
        <DialogHeader className="flex-row items-start justify-between gap-3 border-b border-hairline px-4 py-3">
          <div className="min-w-0">
            <DialogTitle className="text-base font-medium text-bone">{title}</DialogTitle>
            {description ? <DialogDescription className="mt-1 text-sm text-text-2">{description}</DialogDescription> : <DialogDescription className="sr-only">{title}</DialogDescription>}
          </div>
          {locked ? null : (
            <IconButton label="Close dialog" size="sm" onClick={onClose} className="-mt-1 -mr-1">
              <X aria-hidden="true" />
            </IconButton>
          )}
        </DialogHeader>
        <div ref={bodyRef} className="min-h-0 overflow-auto overscroll-contain px-4 py-3 text-sm text-bone">
          {children}
        </div>
        {footer ? <div className="flex flex-wrap items-center justify-end gap-2 border-t border-hairline px-4 py-3">{footer}</div> : null}
      </DialogContent>
    </DialogRoot>
  );
}
