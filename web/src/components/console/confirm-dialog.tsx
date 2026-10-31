/**
 * Confirmation for consequential actions, on the alert dialog. Focus starts
 * on Cancel so a stray Enter does not confirm. While the action runs the
 * buttons are aria-disabled rather than disabled, so focus stays in the
 * dialog if the action fails; the error is shown inline and the dialog stays.
 */

import { useRef, type ReactNode } from 'react';
import {
  AlertDialog,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '../ui/alert-dialog.tsx';
import { Button } from '../ui/button.tsx';
import { Callout } from './callout.tsx';
import { Spinner } from './states.tsx';

export interface ConfirmDialogProps {
  open: boolean;
  title: string;
  /** The consequence and the recovery, in the console's words. */
  description?: ReactNode;
  children?: ReactNode;
  /** Repeats the verb and names the object: "Revoke key". */
  confirmLabel: string;
  busyLabel?: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  description,
  children,
  confirmLabel,
  busyLabel = 'Working…',
  danger = false,
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!next && !busy) onCancel();
      }}
    >
      <AlertDialogContent initialFocus={cancelRef} className="max-h-[calc(100dvh-2rem)] overflow-y-auto overscroll-contain rounded-lg bg-raised p-4 ring-hairline shadow-float sm:max-w-md">
        <AlertDialogHeader className="place-items-start text-left">
          <AlertDialogTitle className="text-base font-medium text-bone">{title}</AlertDialogTitle>
          {description ? <AlertDialogDescription className="text-sm text-text-2 text-pretty">{description}</AlertDialogDescription> : null}
        </AlertDialogHeader>
        {children ? (
          description ? (
            <div className="text-sm text-bone [&_p+p]:mt-2">{children}</div>
          ) : (
            // The consequence sentence is the dialog's description, announced with the title.
            <AlertDialogDescription render={<div />} className="text-sm text-balance text-bone md:text-pretty [&_p+p]:mt-2">
              {children}
            </AlertDialogDescription>
          )
        ) : null}
        {error ? (
          <Callout tone="bad" role="alert">
            {error}
          </Callout>
        ) : null}
        <AlertDialogFooter className="rounded-b-lg border-hairline bg-raised px-4 py-3">
          <Button
            ref={cancelRef}
            type="button"
            variant="outline"
            aria-disabled={busy || undefined}
            onClick={() => {
              if (!busy) onCancel();
            }}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant={danger ? 'danger' : 'default'}
            aria-busy={busy || undefined}
            aria-disabled={busy || undefined}
            onClick={() => {
              if (!busy) onConfirm();
            }}
          >
            {busy ? <Spinner className="text-current" /> : null}
            {busy ? busyLabel : confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
