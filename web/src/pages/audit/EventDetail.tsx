/**
 * One audit event in a side panel: its fields, its place in the
 * hash chain (hash, prev_hash, and whether prev_hash matches the previous
 * event when that event is loaded), and the complete event as stored. The
 * table behind stays live: Up and Down on the event buttons move the panel
 * with the focused row, and Up and Down inside the panel step to the
 * neighbouring loaded event. The title takes focus when the panel opens and
 * stays put (sticky header) while the body scrolls. Escape or Close returns
 * focus to the row. Events not among the loaded rows (a bad sequence number
 * from a chain check, say) are fetched by number.
 *
 * At 1280 px and wider the panel is non-modal and sits in the page grid beside
 * the table (the page reserves its column, so nothing focusable is under it).
 * Narrower, it is a modal sheet: focus trapped, the page inert, Escape returns
 * focus to the row.
 */

import { useEffect, useRef, type KeyboardEvent } from 'react';
import { X } from 'lucide-react';
import { api, type AuditEvent } from '../../api.ts';
import { useResource } from '../../hooks.ts';
import { paths, toHash } from '../../router.ts';
import { Checklist, ChecklistLine } from '../../components/console/checklist.tsx';
import { Digest } from '../../components/console/digest.tsx';
import { IconButton } from '../../components/console/icon-button.tsx';
import { JsonView } from '../../components/console/json-view.tsx';
import { KeyValueList } from '../../components/console/key-value-list.tsx';
import { Async } from '../../components/console/states.tsx';
import { StatusBadge } from '../../components/console/status-badge.tsx';
import { Time } from '../../components/console/time.tsx';
import { Button } from '../../components/ui/button.tsx';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '../../components/ui/sheet.tsx';
import { useMediaQuery } from '@/hooks/use-media';

/** The width from which the panel sits beside the table instead of over it. */
export const SPLIT_QUERY = '(min-width: 1280px)';

export interface EventDetailProps {
  /** The event to show; null keeps the panel closed. */
  seq: number | null;
  /** The event when it is among the loaded rows. */
  known: AuditEvent | null;
  /** The event before it (seq - 1) when that one is loaded, for the chain link check. */
  previous: AuditEvent | null;
  onOpen: (seq: number) => void;
  /** Step to the neighbouring loaded event (Up: newer, Down: older). */
  onStep: (direction: 1 | -1) => void;
  onClose: () => void;
}

export function EventDetail({ seq, known, previous, onOpen, onStep, onClose }: EventDetailProps) {
  const titleRef = useRef<HTMLHeadingElement>(null);
  const wasOpen = useRef(false);
  const open = seq !== null;
  const split = useMediaQuery(SPLIT_QUERY);

  useEffect(() => {
    if (open && !wasOpen.current && split) titleRef.current?.focus({ preventScroll: true });
    wasOpen.current = open;
  }, [open, split]);

  if (seq === null) return null;

  const onKeyDown = (event: KeyboardEvent<HTMLElement>): void => {
    if (event.key === 'Escape' && split) {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const target = event.target as HTMLElement;
    if (target.closest('input, textarea, select, [contenteditable="true"]')) return;
    event.preventDefault();
    onStep(event.key === 'ArrowDown' ? 1 : -1);
  };

  const description = 'Stored fields, the hash links to the chain, and the event as stored. Up and Down step through events.';
  const titleText = (
    <>
      Event <span className="font-mono tabular-nums">#{seq}</span>
    </>
  );
  const closeButton = (
    <IconButton label="Close event detail" noTooltip className="-mt-1 -mr-2 size-10" onClick={onClose}>
      <X aria-hidden="true" />
    </IconButton>
  );
  const body = (
    <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 py-4">
      {known ? <EventBody event={known} previous={previous} onOpen={onOpen} /> : <RemoteEvent seq={seq} previous={previous} onOpen={onOpen} />}
    </div>
  );
  const headerClass = 'sticky top-0 z-10 flex shrink-0 items-start justify-between gap-3 border-b border-hairline bg-raised px-4 py-3';
  const titleClass = 'mb-1 rounded-sm text-base font-medium text-bone';

  if (!split) {
    return (
      <Sheet
        open
        onOpenChange={(next) => {
          if (!next) onClose();
        }}
      >
        <SheetContent
          side="right"
          showCloseButton={false}
          initialFocus={titleRef}
          onKeyDown={onKeyDown}
          className="gap-0 bg-raised data-[side=right]:w-full data-[side=right]:sm:max-w-xl"
        >
          <header className={headerClass}>
            <div className="min-w-0">
              <SheetTitle ref={titleRef} tabIndex={-1} className={titleClass}>
                {titleText}
              </SheetTitle>
              <SheetDescription className="text-xs text-text-3 text-pretty">{description}</SheetDescription>
            </div>
            {closeButton}
          </header>
          {body}
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <aside
      aria-labelledby="event-detail-title"
      onKeyDown={onKeyDown}
      className="sticky top-16 flex max-h-[calc(100vh-5rem)] min-w-0 flex-col overflow-hidden rounded-md border border-hairline bg-raised"
    >
      <header className={headerClass}>
        <div className="min-w-0">
          <h2 id="event-detail-title" ref={titleRef} tabIndex={-1} className={titleClass}>
            {titleText}
          </h2>
          <p className="text-xs text-text-3 text-pretty">{description}</p>
        </div>
        {closeButton}
      </header>
      {body}
    </aside>
  );
}

function RemoteEvent({ seq, previous, onOpen }: { seq: number; previous: AuditEvent | null; onOpen: (seq: number) => void }) {
  const event = useResource((s) => api.auditEvent(seq, s), [seq]);
  return (
    <Async resource={event} loadingLabel="Loading the event…" errorTitle={`Could not load event #${seq}.`}>
      {(e) => <EventBody event={e} previous={previous} onOpen={onOpen} />}
    </Async>
  );
}

function EventBody({ event, previous, onOpen }: { event: AuditEvent; previous: AuditEvent | null; onOpen: (seq: number) => void }) {
  const prevSeq = event.seq - 1;
  const first = prevSeq < 1;
  const linked = previous !== null && previous.seq === prevSeq ? previous.hash === event.prev_hash : null;
  return (
    <>
      <KeyValueList
        items={[
          ['Time', <Time value={event.ts} exact />],
          [
            'Actor',
            <span className="inline-flex flex-wrap items-center gap-1.5">
              <span className="rounded-sm bg-neutral-subtle px-1 text-2xs text-text-2">{event.actor_type}</span>
              <code className="font-mono text-xs [overflow-wrap:anywhere]">{event.actor_id}</code>
            </span>,
          ],
          { term: 'Action', value: event.action, mono: true },
          { term: 'Resource', value: event.resource, mono: true, copy: event.resource },
          ['Outcome', <StatusBadge domain="outcome" value={event.outcome} />],
          [
            'Correlation id',
            event.correlation_id ? (
              <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5">
                <code className="font-mono text-xs [overflow-wrap:anywhere]">{event.correlation_id}</code>
                <a href={toHash(paths.audit({ correlation_id: event.correlation_id }))} className="text-xs rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone">
                  all events with this id
                </a>
              </span>
            ) : null,
          ],
          ['Policy version', event.policy_version !== null ? <span className="font-mono text-xs tabular-nums">v{event.policy_version}</span> : null],
          { term: 'Event id', value: event.event_id, mono: true, copy: event.event_id },
        ]}
      />

      <section aria-labelledby={`event-${event.seq}-chain`} className="flex flex-col gap-2">
        <h3 id={`event-${event.seq}-chain`} className="text-xs font-medium text-text-2">
          Hash chain
        </h3>
        <dl className="m-0 grid grid-cols-[minmax(96px,max-content)_1fr] gap-x-4 gap-y-1 text-sm">
          <dt className="py-0.5 font-mono text-xs text-text-3">hash</dt>
          <dd className="m-0 min-w-0 py-0.5">
            <Digest value={event.hash} label="event hash" full />
          </dd>
          <dt className="py-0.5 font-mono text-xs text-text-3">prev_hash</dt>
          <dd className="m-0 min-w-0 py-0.5">
            <Digest value={event.prev_hash} label="previous event hash" full />
          </dd>
        </dl>
        <Checklist as="div" ariaLabel="Chain link to the previous event">
          <ChecklistLine
            as="div"
            label={first ? 'Previous event' : `Previous event #${prevSeq}`}
            state={first ? 'neutral' : linked === null ? 'neutral' : linked ? 'confirmed' : 'failed'}
            stamp={first ? 'None' : linked === null ? 'Not compared' : linked ? 'Linked' : 'Differs'}
            drawKey={event.seq}
            action={
              first ? null : (
                <Button type="button" variant="outline" size="xs" className="max-w-full" onClick={() => onOpen(prevSeq)}>
                  Open event #{prevSeq}
                </Button>
              )
            }
            detail={
              first
                ? 'The first event in the log: prev_hash is the genesis value.'
                : linked === null
                  ? `Event #${prevSeq} is not among the loaded rows, so its hash was not compared with this prev_hash. Open it, or run Verify chain for the whole log.`
                  : linked
                    ? `prev_hash equals the hash of event #${prevSeq} as loaded.`
                    : `prev_hash does not equal the hash of event #${prevSeq} as loaded. Run Verify chain to confirm.`
            }
          />
        </Checklist>
      </section>

      {Object.keys(event.details).length ? (
        <section aria-labelledby={`event-${event.seq}-details`} className="flex flex-col gap-1">
          <h3 id={`event-${event.seq}-details`} className="text-xs font-medium text-text-2">
            Details
          </h3>
          <JsonView value={event.details} short copyLabel="Copy event details" />
        </section>
      ) : null}

      <section aria-labelledby={`event-${event.seq}-stored`} className="flex flex-col gap-1">
        <h3 id={`event-${event.seq}-stored`} className="text-xs font-medium text-text-2">
          Event as stored
        </h3>
        <JsonView value={event} copyLabel="Copy event JSON" />
      </section>
    </>
  );
}
