/**
 * Audit filters. The applied filters live in the URL (#/audit?outcome=denied),
 * so a filtered view can be linked to and survives a reload; this toolbar
 * edits a draft and applies it in one step. Filters that only arrive through
 * links (actor, resource, correlation id) show as removable chips.
 */

import { useEffect, useState, type FormEvent } from 'react';
import { SlidersHorizontal, X } from 'lucide-react';
import { AUDIT_ACTOR_TYPES, AUDIT_OUTCOMES, type AuditFacets, type AuditQuery } from '../../api.ts';
import { rfc3339ToUtcInput, utcInputToRfc3339 } from '../../format.ts';
import { actionGroups, auditParams } from '../../router.ts';
import { SelectField, TextField } from '../../components/console/form-field.tsx';
import { IconButton } from '../../components/console/icon-button.tsx';
import { Toolbar } from '../../components/console/toolbar.tsx';
import { Button } from '../../components/ui/button.tsx';
import { cn } from '@/lib/utils';

interface Draft {
  action: string;
  outcome: string;
  actor_type: string;
  q: string;
  since: string;
  until: string;
}

/** The Since/Until fields take ISO 8601 in UTC as text: no browser picker chrome or 12-hour mask. */
const UTC_PLACEHOLDER = 'YYYY-MM-DDTHH:MMZ';
const UTC_EXAMPLE = '2026-10-30T09:00Z';
const UTC_TEXT = /^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?))?(?:Z|\+00:?00)?$/i;

/** "2026-10-30", "2026-10-30 08:15", "2026-10-30T08:15:30Z" to RFC 3339 (UTC); anything else gives ''. */
function utcTextToRfc3339(value: string): string {
  const m = UTC_TEXT.exec(value.trim());
  if (!m) return '';
  return utcInputToRfc3339(`${m[1]}T${m[2] ?? '00:00'}`);
}

function toUtcText(iso: string | undefined): string {
  const v = iso ? rfc3339ToUtcInput(iso) : '';
  return v ? `${v}Z` : '';
}

function toDraft(f: AuditQuery): Draft {
  return {
    action: f.action ?? '',
    outcome: f.outcome ?? '',
    actor_type: f.actor_type ?? '',
    q: f.q ?? '',
    since: toUtcText(f.since),
    until: toUtcText(f.until),
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
  const [timeError, setTimeError] = useState<{ message: string; since: boolean; until: boolean } | null>(null);
  // Under 640 px the fields fold behind one "Filters (n)" control so the first event stays near the top.
  const [expanded, setExpanded] = useState(false);
  const activeCount = [...auditParams(filters).keys()].length;

  // Follow the URL when it changes (back/forward, links), keeping the same DOM so focus is not lost.
  useEffect(() => {
    setDraft(toDraft(filters));
    setTimeError(null);
    // `key` captures every filter value, so it is the only dependency needed.
  }, [key]);

  const set = (field: keyof Draft) => (value: string) => setDraft((d) => ({ ...d, [field]: value }));

  const submit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const since = draft.since.trim() ? utcTextToRfc3339(draft.since) : '';
    const until = draft.until.trim() ? utcTextToRfc3339(draft.until) : '';
    const badSince = Boolean(draft.since.trim() && !since);
    const badUntil = Boolean(draft.until.trim() && !until);
    if (badSince || badUntil) {
      setTimeError({ message: `Enter a UTC date and time such as ${UTC_EXAMPLE} (the time is optional).`, since: badSince, until: badUntil });
      return;
    }
    if (since && until && since > until) {
      setTimeError({ message: '"Since" is later than "until".', since: true, until: true });
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
    <form onSubmit={submit} aria-label="Filter audit events" className="flex flex-col gap-2">
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="self-start sm:hidden"
        aria-expanded={expanded}
        aria-controls="audit-filter-fields"
        onClick={() => setExpanded((v) => !v)}
      >
        <SlidersHorizontal aria-hidden="true" />
        Filters{activeCount ? ` (${activeCount})` : ''}
      </Button>
      <Toolbar
        id="audit-filter-fields"
        className={cn(expanded ? 'max-sm:flex' : 'max-sm:hidden', 'max-sm:flex-col max-sm:items-stretch')}
        end={
          <Button type="submit" variant="outline" className="max-sm:w-full">
            Apply filters
          </Button>
        }
      >
        <SelectField label="Action" className="w-36 max-sm:w-full" value={draft.action} onChange={(e) => set('action')(e.target.value)}>
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
        </SelectField>
        <SelectField label="Outcome" className="w-32 max-sm:w-full" value={draft.outcome} onChange={(e) => set('outcome')(e.target.value)}>
          <option value="">Any outcome</option>
          {draft.outcome && !outcomes.includes(draft.outcome) ? <option value={draft.outcome}>{draft.outcome}</option> : null}
          {outcomes.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </SelectField>
        <SelectField label="Actor type" className="w-28 max-sm:w-full" value={draft.actor_type} onChange={(e) => set('actor_type')(e.target.value)}>
          <option value="">Any actor</option>
          {draft.actor_type && !actorTypes.includes(draft.actor_type) ? <option value={draft.actor_type}>{draft.actor_type}</option> : null}
          {actorTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Search"
          className="w-48 max-sm:w-full"
          type="search"
          name="q"
          value={draft.q}
          onChange={(e) => set('q')(e.target.value)}
          maxLength={512}
          spellCheck={false}
          autoComplete="off"
          placeholder="Search events"
          aria-describedby="audit-search-hint"
        />
        <TextField
          label="Since (UTC)"
          className="w-48 max-sm:w-full"
          mono
          type="text"
          name="since"
          spellCheck={false}
          autoComplete="off"
          placeholder={UTC_PLACEHOLDER}
          controlClassName="placeholder:font-mono"
          value={draft.since}
          onChange={(e) => set('since')(e.target.value)}
          aria-invalid={timeError?.since || undefined}
          aria-describedby={timeError ? 'audit-time-error' : 'audit-time-hint'}
        />
        <TextField
          label="Until (UTC)"
          className="w-48 max-sm:w-full"
          mono
          type="text"
          name="until"
          spellCheck={false}
          autoComplete="off"
          placeholder={UTC_PLACEHOLDER}
          controlClassName="placeholder:font-mono"
          value={draft.until}
          onChange={(e) => set('until')(e.target.value)}
          aria-invalid={timeError?.until || undefined}
          aria-describedby={timeError ? 'audit-time-error' : 'audit-time-hint'}
        />
      </Toolbar>
      {/* Below the row, so a validation message never moves the fields out of line. */}
      {timeError ? (
        <p id="audit-time-error" role="alert" className={cn('text-xs text-bad', !expanded && 'max-sm:hidden')}>
          {timeError.message}
        </p>
      ) : null}
      <div className={cn('flex flex-wrap items-center gap-x-3 gap-y-1', !expanded && 'max-sm:hidden')}>
        <p id="audit-search-hint" className="text-xs text-text-3">
          Search matches action, resource, actor, correlation id or details.
        </p>
        <p id="audit-time-hint" className="text-xs text-text-3">
          Times are UTC, such as <code className="font-mono">{UTC_EXAMPLE}</code>.
        </p>
        {key ? (
          <Button type="button" variant="ghost" size="sm" onClick={() => onApply({})}>
            Clear all
          </Button>
        ) : null}
      </div>
      {extras.length ? (
        <ul className="m-0 flex list-none flex-wrap items-center gap-2 p-0" aria-label="Filters set from links">
          {extras.map((e) => (
            <li key={e.key} className="inline-flex h-7 max-w-full items-center gap-1 rounded-sm border border-hairline bg-raised pl-2 text-xs text-text-2">
              <span className="min-w-0 truncate">
                {e.label}: <code className="font-mono text-bone">{filters[e.key]}</code>
              </span>
              <IconButton size="sm" label={`Remove the ${e.label.toLowerCase()} filter`} onClick={() => onApply({ ...filters, [e.key]: '' })}>
                <X aria-hidden="true" className="size-3.5" />
              </IconButton>
            </li>
          ))}
        </ul>
      ) : null}
    </form>
  );
}
