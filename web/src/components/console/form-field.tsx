/**
 * Form fields on the shadcn field primitives: label above, description and
 * error below, wired through id, aria-describedby and aria-invalid. `Field`
 * keeps the old render-prop contract; TextField, SelectField and
 * TextareaField render the control for the common cases.
 */

import { useId, type ComponentProps, type ReactNode } from 'react';
import { Field as FieldRoot, FieldDescription, FieldError, FieldLabel } from '../ui/field.tsx';
import { Input } from '../ui/input.tsx';
import { NativeSelect } from '../ui/native-select.tsx';
import { Textarea } from '../ui/textarea.tsx';
import { Callout } from './callout.tsx';
import { cn } from '@/lib/utils';

export interface ControlProps {
  id: string;
  'aria-describedby': string | undefined;
  'aria-invalid': true | undefined;
}

export interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string | null | undefined;
  optional?: boolean;
  /** Spans both columns of a two-column form grid. */
  wide?: boolean;
  className?: string;
  children: (props: ControlProps) => ReactNode;
}

function useFieldIds(hint: ReactNode, error: string | null | undefined): { id: string; hintId: string | undefined; errorId: string | undefined; describedBy: string | undefined } {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [errorId, hintId].filter(Boolean).join(' ') || undefined;
  return { id, hintId, errorId, describedBy };
}

export function Field({ label, hint, error, optional = false, wide = false, className, children }: FieldProps) {
  const { id, hintId, errorId, describedBy } = useFieldIds(hint, error);
  return (
    <FieldRoot data-invalid={error ? true : undefined} className={cn('gap-1', wide && 'sm:col-span-2', className)}>
      <FieldLabel htmlFor={id} className="text-xs font-medium text-text-2">
        {label}
        {optional ? <span className="font-normal text-text-3"> (optional)</span> : null}
      </FieldLabel>
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {error ? (
        <FieldError id={errorId} className="text-xs text-bad">
          {error}
        </FieldError>
      ) : null}
      {hint ? (
        <FieldDescription id={hintId} className="text-xs text-text-3">
          {hint}
        </FieldDescription>
      ) : null}
    </FieldRoot>
  );
}

type Common = Omit<FieldProps, 'children'>;

export function TextField({ label, hint, error, optional, wide, className, controlClassName, mono = false, ...input }: Common & Omit<ComponentProps<typeof Input>, 'id' | 'className'> & { mono?: boolean; controlClassName?: string }) {
  return (
    <Field label={label} hint={hint} error={error} optional={optional} wide={wide} className={className}>
      {(props) => <Input {...props} {...input} className={cn('h-8 rounded-sm border-line-control bg-inset text-sm', mono && 'font-mono text-xs', controlClassName)} />}
    </Field>
  );
}

export function SelectField({ label, hint, error, optional, wide, className, controlClassName, children, ...select }: Common & Omit<ComponentProps<typeof NativeSelect>, 'id' | 'className'> & { controlClassName?: string }) {
  return (
    <Field label={label} hint={hint} error={error} optional={optional} wide={wide} className={className}>
      {(props) => (
        <NativeSelect {...props} {...select} className={cn('w-full [&_select]:h-8 [&_select]:rounded-sm [&_select]:border-line-control [&_select]:bg-inset', controlClassName)}>
          {children}
        </NativeSelect>
      )}
    </Field>
  );
}

export function TextareaField({ label, hint, error, optional, wide, className, controlClassName, mono = false, ...textarea }: Common & Omit<ComponentProps<typeof Textarea>, 'id' | 'className'> & { mono?: boolean; controlClassName?: string }) {
  return (
    <Field label={label} hint={hint} error={error} optional={optional} wide={wide} className={className}>
      {(props) => <Textarea {...props} {...textarea} className={cn('rounded-sm border-line-control bg-inset text-sm', mono && 'font-mono text-xs leading-5', controlClassName)} />}
    </Field>
  );
}

/** Errors that do not belong to one field, shown above the form's buttons. */
export function FormErrorList({ messages }: { messages: string[] }) {
  if (messages.length === 0) return null;
  return (
    <Callout tone="bad" role="alert">
      {messages.length === 1 ? (
        <p>{messages[0]}</p>
      ) : (
        <ul>
          {messages.map((m, i) => (
            <li key={i}>{m}</li>
          ))}
        </ul>
      )}
    </Callout>
  );
}

/** Two-column form grid; wide fields span both columns. */
export function FormGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('grid grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2', className)}>{children}</div>;
}

/** The row of buttons under a form. */
export function FormActions({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('flex flex-wrap items-center gap-2 pt-1', className)}>{children}</div>;
}
