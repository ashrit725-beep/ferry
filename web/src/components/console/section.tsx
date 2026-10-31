/**
 * Section: a hairline-bordered panel on the Card primitive, with a title,
 * an optional description, actions and an "open" link to the full page.
 */

import { useId, type ReactNode } from 'react';
import { ArrowRight } from 'lucide-react';
import { CardContent, CardFooter, CardHeader } from '../ui/card.tsx';
import { cn } from '@/lib/utils';

export interface SectionProps {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** No body padding: tables and lists run edge to edge. */
  flush?: boolean;
  id?: string;
  /** Link to the page that holds the full record. */
  open?: { href: string; label: string };
  headingLevel?: 2 | 3;
  className?: string;
  /** Amber hairline: this section needs a human. */
  attention?: boolean;
}

export function Section({ title, description, actions, children, footer, flush = false, id, open, headingLevel = 2, className, attention = false }: SectionProps) {
  const headingId = useId();
  const Heading = `h${headingLevel}` as const;
  return (
    <section
      aria-labelledby={headingId}
      id={id}
      data-slot="card"
      className={cn('group/card flex flex-col gap-0 overflow-hidden rounded-lg bg-panel text-sm text-bone ring-1 ring-hairline scroll-mt-16', attention && 'ring-amber/50', className)}
    >
      {/* An "open" link alone stays on the title row (it never wraps under the description, inset by its own padding). */}
      <CardHeader className={cn('flex min-h-10 flex-row items-center justify-between gap-x-3 gap-y-1 border-b border-hairline px-3 py-2', open && !actions ? 'flex-nowrap' : 'flex-wrap')}>
        <div className="min-w-0 flex-1">
          <Heading id={headingId} className="text-[0.875rem] leading-5 font-semibold text-bone">
            {title}
          </Heading>
          {description ? <p className="text-xs text-text-2 text-pretty">{description}</p> : null}
        </div>
        {actions || open ? (
          <div className="flex shrink-0 items-center gap-2">
            {actions}
            {open ? (
              <a href={open.href} className="-mr-1.5 inline-flex h-7 items-center gap-1 rounded-sm px-1.5 text-xs whitespace-nowrap text-text-2 hover:bg-hover hover:text-bone">
                {open.label}
                <ArrowRight aria-hidden="true" className="size-3.5" />
              </a>
            ) : null}
          </div>
        ) : null}
      </CardHeader>
      <CardContent className={cn(flush ? 'p-0' : 'px-3 py-3')}>{children}</CardContent>
      {footer ? <CardFooter className="rounded-b-lg border-t border-hairline bg-panel px-3 py-2 text-xs text-text-3">{footer}</CardFooter> : null}
    </section>
  );
}
