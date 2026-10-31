/**
 * Page header: the one h1 per page (focused by the shell after navigation),
 * a meta line, optional breadcrumb and an actions slot.
 */

import type { ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { useDocumentTitle } from '../../hooks.ts';
import { cn } from '@/lib/utils';

export interface Crumb {
  label: string;
  href: string;
}

export interface PageHeaderProps {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  breadcrumb?: Crumb[];
  className?: string;
}

export function PageHeader({ title, description, actions, meta, breadcrumb, className }: PageHeaderProps) {
  useDocumentTitle(title);
  return (
    <header className={cn('mb-4 flex flex-wrap items-end justify-between gap-x-6 gap-y-2', className)}>
      <div className="min-w-0">
        {breadcrumb?.length ? (
          <nav aria-label="Breadcrumb" className="mb-1">
            <ol className="m-0 flex list-none flex-wrap items-center gap-1 p-0 text-xs text-text-3">
              {breadcrumb.map((c, i) => (
                <li key={c.href} className="flex items-center gap-1">
                  {i > 0 ? <ChevronRight aria-hidden="true" className="size-3" /> : null}
                  <a href={c.href} className="hover:text-bone hover:underline">
                    {c.label}
                  </a>
                </li>
              ))}
            </ol>
          </nav>
        ) : null}
        <h1 tabIndex={-1} className="text-[1.75rem] leading-9 font-semibold tracking-[-0.01em] text-bone font-stretch-[112%] sm:text-[1.875rem]">
          {title}
        </h1>
        {description ? <p className="mt-1 max-w-[72ch] text-sm text-text-2 text-pretty">{description}</p> : null}
        {meta ? <p className="mt-1 text-xs text-text-2 tabular-nums">{meta}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}
