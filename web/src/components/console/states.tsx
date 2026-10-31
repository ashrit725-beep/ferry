/**
 * Loading, empty and error states, and the skeletons that hold a panel's
 * shape while it loads. Every fetch on every page goes through `Async`, so
 * none of them can forget one of the three.
 */

import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { describeError } from '../../errors.ts';
import type { Resource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { Button } from '../ui/button.tsx';
import { Skeleton } from '../ui/skeleton.tsx';
import { Callout } from './callout.tsx';
import { cn } from '@/lib/utils';

export function Spinner({ className }: { className?: string }) {
  return <Loader2 aria-hidden="true" data-spinner className={cn('size-3.5 shrink-0 animate-spin text-amber motion-reduce:animate-spin', className)} />;
}

export function Loading({ label = 'Loading…', className }: { label?: string; className?: string }) {
  return (
    <div role="status" className={cn('flex items-center gap-2 px-3 py-4 text-sm text-text-2', className)}>
      <Spinner />
      {label}
    </div>
  );
}

export function PanelSkeleton({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div aria-busy="true" aria-live="polite" className={cn('flex flex-col gap-2 px-3 py-3', className)}>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={cn('h-4 rounded-sm bg-raised', i % 3 === 0 ? 'w-2/3' : i % 3 === 1 ? 'w-full' : 'w-1/2')} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5, columns = 4, className }: { rows?: number; columns?: number; className?: string }) {
  return (
    <div aria-busy="true" aria-live="polite" className={cn('flex flex-col', className)}>
      <div className="flex h-8 items-center gap-4 border-b border-hairline px-3">
        {Array.from({ length: columns }, (_, c) => (
          <Skeleton key={c} className="h-3 w-16 rounded-sm bg-raised" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex h-8 items-center gap-4 border-b border-hairline px-3 last:border-0">
          {Array.from({ length: columns }, (_, c) => (
            <Skeleton key={c} className={cn('h-3 rounded-sm bg-raised', c === 0 ? 'w-32' : 'w-20')} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function EmptyState({ title, children, action, icon, className }: { title: string; children?: ReactNode; action?: ReactNode; icon?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-start gap-2 px-3 py-6', className)}>
      {icon ? <span className="text-text-3">{icon}</span> : null}
      <p className="text-sm font-medium text-bone">{title}</p>
      {children ? <div className="max-w-[72ch] text-sm text-text-2 text-pretty [&_code]:text-xs [&_code]:text-bone">{children}</div> : null}
      {action ? <div className="mt-1">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ error, onRetry, title = 'Could not load this data.', className }: { error: unknown; onRetry?: () => void; title?: string | undefined; className?: string }) {
  const role = useRole();
  return (
    <div role="alert" className={cn('flex flex-col items-start gap-2 px-3 py-6', className)}>
      <p className="text-sm font-medium text-bad">{title}</p>
      <p className="max-w-[72ch] text-sm text-text-2 text-pretty">{describeError(error, role)}</p>
      {onRetry ? (
        <Button type="button" variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

/** A failed action or reload shown above content that is still valid. */
export function InlineError({ error, prefix, onRetry }: { error: unknown; prefix?: string; onRetry?: () => void }) {
  const role = useRole();
  return (
    <Callout tone="bad" role="alert" className="items-center">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p>
          {prefix ? <span className="font-medium">{prefix} </span> : null}
          {describeError(error, role)}
        </p>
        {onRetry ? (
          <Button type="button" variant="outline" size="sm" onClick={onRetry}>
            Try again
          </Button>
        ) : null}
      </div>
    </Callout>
  );
}

export function Async<T>({
  resource,
  children,
  loadingLabel,
  errorTitle,
  skeleton,
}: {
  resource: Resource<T>;
  children: (data: T) => ReactNode;
  loadingLabel?: string;
  errorTitle?: string;
  /** Final-shape skeleton instead of the spinner row. */
  skeleton?: ReactNode;
}) {
  if (resource.data !== null) {
    return (
      <>
        {resource.error ? <InlineError error={resource.error} prefix="Could not refresh; showing the last data loaded." onRetry={resource.reload} /> : null}
        {children(resource.data)}
      </>
    );
  }
  if (resource.error) return <ErrorState error={resource.error} onRetry={resource.reload} title={errorTitle} />;
  return skeleton ?? <Loading label={loadingLabel} />;
}
