/**
 * Loading, empty and error states. Every fetch on every page goes through
 * `Async`, so none of them can forget one of the three.
 */

import type { ReactNode } from 'react';
import { describeError } from '../errors.ts';
import type { Resource } from '../hooks.ts';
import { useRole } from '../session.tsx';

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="state state--loading" role="status">
      <span className="row">
        <Spinner />
        {label}
      </span>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="state">
      <p className="state__title">{title}</p>
      {children ? <div className="state__body">{children}</div> : null}
      {action}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  title = 'Could not load this data.',
}: {
  error: unknown;
  onRetry?: () => void;
  title?: string | undefined;
}) {
  const role = useRole();
  return (
    <div className="state state--error" role="alert">
      <p className="state__title">{title}</p>
      <p className="state__body">{describeError(error, role)}</p>
      {onRetry ? (
        <button type="button" className="button" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

/** A failed action or reload shown above content that is still valid. */
export function InlineError({ error, prefix, onRetry }: { error: unknown; prefix?: string; onRetry?: () => void }) {
  const role = useRole();
  return (
    <div className="callout callout--bad inline-error" role="alert">
      <div className="callout__body">
        <p>
          {prefix ? <span className="strong">{prefix} </span> : null}
          {describeError(error, role)}
        </p>
      </div>
      {onRetry ? (
        <button type="button" className="button button--small" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function Async<T>({
  resource,
  children,
  loadingLabel,
  errorTitle,
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
  loadingLabel?: string;
  errorTitle?: string;
}) {
  if (resource.data !== null) {
    return (
      <>
        {resource.error ? (
          <InlineError error={resource.error} prefix="Could not refresh; showing the last data loaded." onRetry={resource.reload} />
        ) : null}
        {children(resource.data)}
      </>
    );
  }
  if (resource.error) return <ErrorState error={resource.error} onRetry={resource.reload} title={errorTitle} />;
  return <Loading label={loadingLabel} />;
}
