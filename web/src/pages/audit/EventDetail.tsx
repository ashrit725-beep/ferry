import { api, type AuditEvent } from '../../api.ts';
import { useResource } from '../../hooks.ts';
import { paths, toHash } from '../../router.ts';
import { Digest } from '../../components/Digest.tsx';
import { IconCross } from '../../components/Icons.tsx';
import { JsonView } from '../../components/JsonView.tsx';
import { DefList, Panel } from '../../components/Panel.tsx';
import { Async } from '../../components/States.tsx';
import { StatusBadge } from '../../components/StatusBadge.tsx';
import { Time } from '../../components/Time.tsx';

/**
 * One audit event: its fields, its place in the hash chain, and the complete
 * event as stored. Events not among the loaded rows (a bad sequence number
 * from a chain check, say) are fetched by number.
 */
export function EventDetail({ seq, known, onClose }: { seq: number; known: AuditEvent | null; onClose: () => void }) {
  const close = (
    <button type="button" className="button button--ghost button--small" onClick={onClose} aria-label={`Close event ${seq}`}>
      <IconCross />
      Close
    </button>
  );
  return (
    <Panel title={`Event #${seq}`} actions={close}>
      {known ? <EventBody event={known} /> : <RemoteEvent seq={seq} />}
    </Panel>
  );
}

function RemoteEvent({ seq }: { seq: number }) {
  const event = useResource((s) => api.auditEvent(seq, s), [seq]);
  return (
    <Async resource={event} loadingLabel="Loading the event…" errorTitle={`Could not load event #${seq}.`}>
      {(e) => <EventBody event={e} />}
    </Async>
  );
}

function EventBody({ event }: { event: AuditEvent }) {
  return (
    <div className="stack stack--tight">
      <DefList
        items={[
          ['Time', <Time value={event.ts} exact />],
          [
            'Actor',
            <span>
              <span className="tag">{event.actor_type}</span> <code className="break">{event.actor_id}</code>
            </span>,
          ],
          ['Action', <code>{event.action}</code>],
          ['Resource', <code className="break">{event.resource}</code>],
          ['Outcome', <StatusBadge domain="outcome" value={event.outcome} />],
          [
            'Correlation id',
            event.correlation_id ? (
              <span>
                <code className="break">{event.correlation_id}</code>{' '}
                <a href={toHash(paths.audit({ correlation_id: event.correlation_id }))}>all events with this id</a>
              </span>
            ) : null,
          ],
          ['Policy version', event.policy_version !== null ? `v${event.policy_version}` : null],
          ['Event id', <code className="break">{event.event_id}</code>],
        ]}
      />
      <div className="hash-list">
        <div>
          <h3 className="label-heading">hash</h3>
          <Digest value={event.hash} label="event hash" full />
        </div>
        <div>
          <h3 className="label-heading">prev_hash</h3>
          <Digest value={event.prev_hash} label="previous event hash" full />
        </div>
      </div>
      <div>
        <h3 className="label-heading">Event as stored</h3>
        <JsonView value={event} copyLabel="Copy event JSON" />
      </div>
    </div>
  );
}
