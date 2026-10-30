/**
 * Modal dialogs on the native <dialog> element: showModal() makes the rest of
 * the page inert, Escape closes (through the cancel event, so React state
 * stays the source of truth), Tab is kept inside the dialog, and focus goes
 * back to whatever opened it.
 */

import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode, type RefObject, type SyntheticEvent } from 'react';
import { Callout } from './Panel.tsx';
import { IconCross } from './Icons.tsx';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => el.getClientRects().length > 0 || el === document.activeElement,
  );
}

export interface DialogProps {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
  /** Element to focus when the dialog opens; defaults to the first control in the body. */
  initialFocus?: RefObject<HTMLElement | null>;
  /** role="alertdialog": a confirmation that interrupts the current task. */
  alert?: boolean;
}

export function Dialog(props: DialogProps) {
  if (!props.open) return null;
  return <OpenDialog {...props} />;
}

function OpenDialog({ title, onClose, children, footer, wide = false, initialFocus, alert = false }: DialogProps) {
  const ref = useRef<HTMLDialogElement>(null);
  const bodyRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const titleId = useId();

  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return undefined;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (!dialog.open) dialog.showModal();
    const target = initialFocus?.current ?? (bodyRef.current ? focusables(bodyRef.current)[0] : undefined);
    (target ?? dialog).focus();
    return () => {
      if (dialog.open) dialog.close();
      if (opener?.isConnected) opener.focus();
    };
    // Runs once per opening (this component mounts on open); `initialFocus` is read at that moment only.
  }, []);

  const onCancel = (event: SyntheticEvent<HTMLDialogElement>): void => {
    event.preventDefault();
    onCloseRef.current();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDialogElement>): void => {
    if (event.key !== 'Tab' || !ref.current) return;
    const items = focusables(ref.current);
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) {
      event.preventDefault();
      return;
    }
    if (event.shiftKey && (document.activeElement === first || document.activeElement === ref.current)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <dialog
      ref={ref}
      className={wide ? 'dialog dialog--wide' : 'dialog'}
      aria-labelledby={titleId}
      role={alert ? 'alertdialog' : undefined}
      onCancel={onCancel}
      onKeyDown={onKeyDown}
      tabIndex={-1}
    >
      <div className="dialog__inner">
        <div className="dialog__header">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="button button--ghost button--icon" aria-label="Close dialog" onClick={onClose}>
            <IconCross />
          </button>
        </div>
        <div className="dialog__body" ref={bodyRef}>
          {children}
        </div>
        {footer ? <div className="dialog__footer">{footer}</div> : null}
      </div>
    </dialog>
  );
}

/**
 * Confirmation for consequential actions. Focus starts on Cancel so a stray
 * Enter does not confirm. While the action runs the buttons are aria-disabled
 * rather than disabled, so focus stays in the dialog if the action fails.
 */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  busyLabel = 'Working…',
  danger = false,
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  busyLabel?: string;
  danger?: boolean;
  busy?: boolean;
  error?: string | null;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  return (
    <Dialog
      open={open}
      title={title}
      onClose={() => {
        if (!busy) onCancel();
      }}
      initialFocus={cancelRef}
      alert
      footer={
        <>
          <button
            ref={cancelRef}
            type="button"
            className="button"
            aria-disabled={busy || undefined}
            onClick={() => {
              if (!busy) onCancel();
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            className={danger ? 'button button--danger' : 'button button--primary'}
            aria-disabled={busy || undefined}
            onClick={() => {
              if (!busy) onConfirm();
            }}
          >
            {busy ? busyLabel : confirmLabel}
          </button>
        </>
      }
    >
      {children}
      {error ? (
        <Callout tone="bad" role="alert">
          {error}
        </Callout>
      ) : null}
    </Dialog>
  );
}
