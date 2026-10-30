import { useId, type ReactNode } from 'react';

export interface ControlProps {
  id: string;
  'aria-describedby': string | undefined;
  'aria-invalid': true | undefined;
}

/**
 * A labelled form field. The control is rendered by the caller with the
 * props given, so the label, hint and (server or client) error are always
 * wired to it through id, aria-describedby and aria-invalid.
 */
export function Field({
  label,
  hint,
  error,
  optional = false,
  wide = false,
  children,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null | undefined;
  optional?: boolean;
  wide?: boolean;
  children: (props: ControlProps) => ReactNode;
}) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [errorId, hintId].filter(Boolean).join(' ') || undefined;
  return (
    <div className={wide ? 'field field--wide' : 'field'}>
      <label className="field__label" htmlFor={id}>
        {label}
        {optional ? <span className="field__optional"> (optional)</span> : null}
      </label>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {error ? (
        <p className="field__error" id={errorId}>
          {error}
        </p>
      ) : null}
      {hint ? (
        <p className="field__hint" id={hintId}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** Errors that do not belong to one field, shown above the form's buttons. */
export function FormErrorList({ messages }: { messages: string[] }) {
  if (messages.length === 0) return null;
  return (
    <div className="callout callout--bad" role="alert">
      <div className="callout__body">
        {messages.length === 1 ? (
          <p>{messages[0]}</p>
        ) : (
          <ul>
            {messages.map((m, i) => (
              <li key={i}>{m}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
