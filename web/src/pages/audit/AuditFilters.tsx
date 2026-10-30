/**
 * Audit filters. The applied filters live in the URL (#/audit?outcome=denied),
 * so a filtered view can be linked to and survives a reload; this form edits
 * a draft and applies it in one step.
 */

import { useEffect, useState, type FormEvent } from 'react';
import { AUDIT_ACTOR_TYPES, AUDIT_OUTCOMES, type AuditFacets, type AuditQuery } from '../../api.ts';
import { rfc3339ToUtcInput, utcInputToRfc3339 } from '../../format.ts';
import { actionGroups, auditParams } from '../../router.ts';
import { Field } from '../../components/Field.tsx';
import { IconCross } from '../../components/Icons.tsx';

interface Draft {
  action: string;
  outcome: string;
  actor_type: string;
  q: string;
  since: string;
  until: string;
}

function toDraft(f: AuditQuery): Draft {
  return {
    action: f.action ?? '',
    outcome: f.outcome ?? '',
    actor_type: f.actor_type ?? '',
    q: f.q ?? '',
    since: f.since ? rfc3339ToUtcInput(f.since) : '',
    until: f.until ? rfc3339ToUtcInput(f.until) : '',
  };
}

const EXTRA: ReadonlyArray<{ key: 'actor_id' | 'resource' | 'correlation_id'; label: string }> = [
  { key: 'actor_id', label: 'Actor' },
  { key: 'resource', label: 'Resource' },
  { key: 'correlation_id', label: 'Correlation id' },
];

export function AuditFilters({
  filters,
  facets,
  onApply,
}: {
  filters: AuditQuery;
  facets: AuditFacets | null;
  onApply: (filters: AuditQuery) => void;
}) {
  const key = auditParams(filters).toString();
  const [draft, setDraft] = useState<Draft>(() => toDraft(filters));
  const [timeError, setTimeError] = useState<string | null>(null);

  // Follow the URL when it changes (back/forward, links), keeping the same DOM so focus is not lost.
  useEffect(() => {
    setDraft(toDraft(filters));
    setTimeError(null);
    // `key` captures every filter value, so it is the only dependency needed.
  }, [key]);

  const set = (field: keyof Draft) => (value: string) => setDraft((d) => ({ ...d, [field]: value }));

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const since = draft.since ? utcInputToRfc3339(draft.since) : '';
    const until = draft.until ? utcInputToRfc3339(draft.until) : '';
    if ((draft.since && !since) || (draft.until && !until)) {
      setTimeError('Enter a complete date and time.');
      return;
    }
    if (since && until && since > until) {
      setTimeError('"Since" is later than "until".');
      return;
    }
    setTimeError(null);
    const next: AuditQuery = { ...filters, action: draft.action, outcome: draft.outcome, actor_type: draft.actor_type, q: draft.q, since, until };
    onApply(next);
  };

  const actions = facets?.actions ?? [];
  const groups = actionGroups(actions);
  const outcomes = facets?.outcomes.length ? facets.outcomes : [...AUDIT_OUTCOMES];
  const actorTypes = facets?.actor_types.length ? facets.actor_types : [...AUDIT_ACTOR_TYPES];
  const knownAction = draft.action === '' || actions.includes(draft.action) || groups.includes(draft.action);
  const extras = EXTRA.filter((e) => filters[e.key]);

  return (
    <form className="form" onSubmit={submit} aria-label="Filter audit events">
      <div className="filters">
        <Field label="Action">
          {(p) => (
            <select {...p} className="select" value={draft.action} onChange={(e) => set('action')(e.target.value)}>
              <option value="">Any action</option>
              {knownAction ? null : <option value={draft.action}>{draft.action}</option>}
              {groups.length ? (
                <optgroup label="Groups">
                  {groups.map((g) => (
                    <option key={g} value={g}>
                      {g}
                    </option>
                  ))}
                </optgroup>
              ) : null}
              {actions.length ? (
                <optgroup label="Actions">
                  {actions.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </select>
          )}
        </Field>
        <Field label="Outcome">
          {(p) => (
            <select {...p} className="select" value={draft.outcome} onChange={(e) => set('outcome')(e.target.value)}>
              <option value="">Any outcome</option>
              {draft.outcome && !outcomes.includes(draft.outcome) ? <option value={draft.outcome}>{draft.outcome}</option> : null}
              {outcomes.map((o) => (
                <option key={o} value={o}>
                  {o}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Actor type">
          {(p) => (
            <select {...p} className="select" value={draft.actor_type} onChange={(e) => set('actor_type')(e.target.value)}>
              <option value="">Any actor</option>
              {draft.actor_type && !actorTypes.includes(draft.actor_type) ? (
                <option value={draft.actor_type}>{draft.actor_type}</option>
              ) : null}
              {actorTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Search" hint="Action, resource, actor, correlation id or details.">
          {(p) => <input {...p} className="input" type="search" value={draft.q} onChange={(e) => set('q')(e.target.value)} maxLength={512} />}
        </Field>
        <Field label="Since (UTC)" error={timeError}>
          {(p) => (
            <input {...p} className="input" type="datetime-local" step={1} value={draft.since} onChange={(e) => set('since')(e.target.value)} />
          )}
        </Field>
        <Field label="Until (UTC)">
          {(p) => <input {...p} className="input" type="datetime-local" step={1} value={draft.until} onChange={(e) => set('until')(e.target.value)} />}
        </Field>
      </div>
      <div className="form-actions">
        <button type="submit" className="button button--primary">
          Apply filters
        </button>
        {key ? (
          <button type="button" className="button button--ghost" onClick={() => onApply({})}>
            Clear all
          </button>
        ) : null}
        {extras.map((e) => (
          <span key={e.key} className="chip">
            <span>
              {e.label}: <code>{filters[e.key]}</code>
            </span>
            <button
              type="button"
              className="copy-button"
              aria-label={`Remove the ${e.label.toLowerCase()} filter`}
              onClick={() => onApply({ ...filters, [e.key]: '' })}
            >
              <IconCross />
            </button>
          </span>
        ))}
      </div>
    </form>
  );
}
