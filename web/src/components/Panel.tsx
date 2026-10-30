/**
 * Page and section scaffolding: page header (whose h1 receives focus after
 * navigation), panels, callouts, definition lists and figures.
 */

import { Fragment, useEffect, useId, useRef, type ReactNode } from 'react';
import { useDocumentTitle } from '../hooks.ts';
import type { Tone } from '../status.ts';
import { IconAlert, IconCheck, IconInfo, IconRefresh } from './Icons.tsx';

export interface Crumb {
  label: string;
  href: string;
}

export function PageHeader({
  title,
  description,
  actions,
  meta,
  breadcrumb,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  breadcrumb?: Crumb[];
}) {
  useDocumentTitle(title);
  return (
    <header className="page-header">
      <div className="page-header__text">
        {breadcrumb?.length ? (
          <nav aria-label="Breadcrumb">
            <ol className="breadcrumb">
              {breadcrumb.map((c) => (
                <li key={c.href}>
                  <a href={c.href}>{c.label}</a>
                </li>
              ))}
            </ol>
          </nav>
        ) : null}
        <h1 tabIndex={-1}>{title}</h1>
        {description ? <p className="page-header__desc">{description}</p> : null}
        {meta ? <p className="page-header__meta">{meta}</p> : null}
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({
  title,
  description,
  actions,
  children,
  footer,
  flush = false,
  id,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  /** No body padding: for tables and lists that run edge to edge. */
  flush?: boolean;
  id?: string;
}) {
  const headingId = useId();
  return (
    <section className="panel" aria-labelledby={headingId} id={id}>
      <div className="panel__header">
        <div className="panel__heading">
          <h2 id={headingId}>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {actions ? <div className="row">{actions}</div> : null}
      </div>
      <div className={flush ? 'panel__body panel__body--flush' : 'panel__body'}>{children}</div>
      {footer ? <div className="panel__footer">{footer}</div> : null}
    </section>
  );
}

function CalloutIcon({ tone }: { tone: Tone }) {
  if (tone === 'ok') return <IconCheck />;
  if (tone === 'bad' || tone === 'warn') return <IconAlert />;
  return <IconInfo />;
}

export function Callout({
  tone = 'neutral',
  title,
  children,
  role,
}: {
  tone?: Tone;
  title?: ReactNode;
  children?: ReactNode;
  role?: 'alert' | 'status';
}) {
  return (
    <div className={`callout callout--${tone}`} role={role}>
      <CalloutIcon tone={tone} />
      <div className="callout__body">
        {title ? <p className="callout__title">{title}</p> : null}
        {children}
      </div>
    </div>
  );
}

/** Term/description pairs; entries with a null value are skipped. */
export function DefList({ items, wide = false }: { items: ReadonlyArray<readonly [string, ReactNode]>; wide?: boolean }) {
  return (
    <dl className={wide ? 'kv kv--wide' : 'kv'}>
      {items.map(([term, value]) =>
        value === null || value === undefined ? null : (
          <Fragment key={term}>
            <dt>{term}</dt>
            <dd>{value}</dd>
          </Fragment>
        ),
      )}
    </dl>
  );
}

export interface NoticeMessage {
  text: string;
  /**
   * Move focus to the message. For actions that remove the control that
   * triggered them (revoke, delete): otherwise focus would fall to the page
   * body once the list reloads without that control.
   */
  focus?: boolean;
}

/** Result of an action, announced politely. A new object re-announces (and re-focuses) the same text. */
export function Notice({ notice }: { notice: NoticeMessage | null }) {
  const ref = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (notice?.focus) ref.current?.focus();
  }, [notice]);
  if (!notice) return null;
  return (
    <p ref={ref} className="panel-note" role="status" tabIndex={-1}>
      {notice.text}
    </p>
  );
}

export function Figure({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="figure">
      <div className="figure__label">{label}</div>
      <div className="figure__value">{value}</div>
      {hint ? <div className="figure__hint">{hint}</div> : null}
    </div>
  );
}

/**
 * Not `disabled` while busy: disabling the focused button would drop keyboard
 * focus to the page body. Clicks during a refresh are ignored instead, and the
 * label stays put so periodic refreshes do not make it flicker.
 */
export function RefreshButton({ onClick, busy, label = 'Refresh' }: { onClick: () => void; busy: boolean; label?: string }) {
  return (
    <button
      type="button"
      className="button"
      onClick={() => {
        if (!busy) onClick();
      }}
      aria-busy={busy || undefined}
      data-busy={busy || undefined}
    >
      <IconRefresh />
      {label}
    </button>
  );
}
