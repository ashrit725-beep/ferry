/**
 * Toolbar: the filters row above a table. Controls on the left, counts and
 * secondary actions on the right; wraps on narrow screens.
 */

import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function Toolbar({ children, end, label, className, id }: { children: ReactNode; end?: ReactNode; label?: string; className?: string; id?: string }) {
  return (
    <div id={id} role={label ? 'group' : undefined} aria-label={label} className={cn('flex flex-wrap items-end gap-2', className)}>
      <div className="flex min-w-0 flex-1 flex-wrap items-end gap-2 max-sm:flex-col max-sm:items-stretch">{children}</div>
      {end ? <div className="flex items-center gap-2">{end}</div> : null}
    </div>
  );
}
