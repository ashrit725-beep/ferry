/**
 * "What would happen if this app asked for this model now?" The server
 * evaluates the active policy (and the app's own status) without sending
 * anything to a backend; this page only displays the decision, as a
 * checklist: one line per rule in document order, ending in the verdict.
 */

import { useId, useState, type FormEvent } from 'react';
import { api, POLICY_ACTIONS, type App, type Decision, type ModelRoute, type PolicyAction } from '../../api.ts';
import { formErrors, type FormErrors } from '../../errors.ts';
import { MODEL_NAME } from '../../forms.ts';
import { formatInt, plural } from '../../format.ts';
import { useResource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { Checklist, ChecklistLine } from '../../components/console/checklist.tsx';
import { Digest } from '../../components/console/digest.tsx';
import { Field, FormActions, FormErrorList, FormGrid, SelectField } from '../../components/console/form-field.tsx';
import { KeyValueList } from '../../components/console/key-value-list.tsx';
import { Section } from '../../components/console/section.tsx';
import { Async, EmptyState, PanelSkeleton, Spinner } from '../../components/console/states.tsx';
import { Button } from '../../components/ui/button.tsx';
import { Input } from '../../components/ui/input.tsx';

const NO_ERRORS: FormErrors = { fields: {}, general: [] };
const FIELDS = ['app', 'model', 'action'] as const;

interface Asked {
  app: string;
  model: string;
  action: PolicyAction;
  decision: Decision;
  serial: number;
}

export function ExplainTab() {
  const apps = useResource((s) => api.apps(s), []);
  const routes = useResource((s) => api.routes(s), []);
  return (
    <Section title="Explain a decision" description="Evaluates the active policy for one app, model and action. Nothing is sent to a backend.">
      <Async resource={apps} loadingLabel="Loading apps…" skeleton={<PanelSkeleton lines={3} />}>
        {(items) =>
          items.length === 0 ? (
            <EmptyState title="No apps to explain.">Create an app on the Apps and keys tab first.</EmptyState>
          ) : (
            <ExplainForm apps={items} routes={routes.data ?? []} />
          )
        }
      </Async>
    </Section>
  );
}

function ExplainForm({ apps, routes }: { apps: readonly App[]; routes: readonly ModelRoute[] }) {
  const role = useRole();
  const listId = useId();
  const [app, setApp] = useState(apps[0]?.name ?? '');
  // Until the operator types, the field follows the first routed model, so routes
  // that resolve after the apps still fill it.
  const [typed, setTyped] = useState<string | null>(null);
  const model = typed ?? routes[0]?.model ?? '';
  const setModel = (value: string): void => setTyped(value);
  const [action, setAction] = useState<PolicyAction>('chat.completions');
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);
  const [asked, setAsked] = useState<Asked | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const m = model.trim();
    if (!m || !MODEL_NAME.test(m)) {
      setErrors({ fields: { model: m ? 'Enter a single model name, not a pattern.' : 'Enter a model name.' }, general: [] });
      return;
    }
    setBusy(true);
    setErrors(NO_ERRORS);
    try {
      const decision = await api.explain({ app, action, model: m });
      setAsked((prev) => ({ app, model: m, action, decision, serial: (prev?.serial ?? 0) + 1 }));
    } catch (err) {
      setErrors(formErrors(err, FIELDS, role));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)} noValidate aria-label="Explain a decision">
        <FormGrid className="min-[1181px]:grid-cols-3">
          <SelectField label="App" error={errors.fields['app']} value={app} onChange={(e) => setApp(e.target.value)}>
            {apps.map((a) => (
              <option key={a.id} value={a.name}>
                {a.name} ({a.environment}
                {a.disabled ? ', disabled' : ''})
              </option>
            ))}
          </SelectField>
          <Field label="Model" error={errors.fields['model']} hint={routes.length ? 'Routed models are suggested; any model name can be checked.' : undefined}>
            {(p) => (
              <>
                <Input
                  {...p}
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  list={routes.length ? listId : undefined}
                  autoComplete="off"
                  spellCheck={false}
                  className="h-8 rounded-sm border-line-control bg-inset font-mono text-xs"
                />
                {routes.length ? (
                  <datalist id={listId}>
                    {routes.map((r) => (
                      <option key={r.id} value={r.model} />
                    ))}
                  </datalist>
                ) : null}
              </>
            )}
          </Field>
          <SelectField label="Action" error={errors.fields['action']} value={action} onChange={(e) => setAction(e.target.value as PolicyAction)}>
            {POLICY_ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </SelectField>
        </FormGrid>
        <FormErrorList messages={errors.general} />
        <FormActions>
          <Button type="submit" aria-busy={busy || undefined} aria-disabled={busy || undefined}>
            {busy ? <Spinner className="text-current" /> : null}
            {busy ? 'Evaluating…' : 'Explain'}
          </Button>
        </FormActions>
      </form>
      {/* One sentence is announced; the stamp and the trace are read on demand. */}
      <p className="sr-only" aria-live="polite">
        {asked ? announce(asked) : ''}
      </p>
      {asked ? <DecisionView asked={asked} /> : null}
    </div>
  );
}

function mark(value: boolean | null): string {
  if (value === null) return 'n/a';
  return value ? 'matches' : 'no match';
}

/** The server's reason as a sentence: capital first letter, closing full stop. */
function sentence(text: string): string {
  const t = text.trim();
  if (!t) return '';
  const s = t.charAt(0).toUpperCase() + t.slice(1);
  return /[.!?]$/.test(s) ? s : `${s}.`;
}

function announce(asked: Asked): string {
  const d = asked.decision;
  const principal = d.principal ?? `app:${asked.app}`;
  return `${d.allowed ? 'Allowed' : 'Denied'}: ${principal} to ${asked.model} (${asked.action}). ${sentence(d.reason || '')}`.trim();
}

function DecisionView({ asked }: { asked: Asked }) {
  const d = asked.decision;
  const limits = d.limits;
  const appBlocked = d.principal_status !== null && d.principal_status !== 'active';
  const principal = d.principal ?? `app:${asked.app}`;
  const matched = d.trace.filter((t) => t.matched).length;
  return (
    <section aria-label="Decision" className="flex flex-col gap-4 border-t border-hairline pt-3">
      {/* The answer first, then the trace that led to it. */}
      <Checklist ariaLabel="Decision">
        <ChecklistLine
          label={<span className="font-medium">Decision</span>}
          state={d.allowed ? 'confirmed' : 'failed'}
          stamp={d.allowed ? 'Allowed' : 'Denied'}
          drawKey={asked.serial}
          detail={
            <span className="flex flex-col gap-0.5 text-text-2">
              <span className="break-words text-bone">
                {d.allowed ? 'Allowed' : 'Denied'}: <code className="code-inline font-mono">{principal}</code> → <code className="code-inline font-mono">{asked.model}</code> ({asked.action})
              </span>
              <span>{sentence(d.reason || (d.allowed ? 'allowed' : 'denied'))}</span>
              {appBlocked && d.policy_allowed !== null ? (
                <span>
                  The app is {d.principal_status}, so it is rejected before policy. The policy on its own would {d.policy_allowed ? 'allow' : 'deny'} this
                  request.
                </span>
              ) : null}
            </span>
          }
        />
      </Checklist>
      <Checklist
        label="Rule by rule"
        summary={d.trace.length ? `${plural(d.trace.length, 'rule')} · ${formatInt(matched)} applied` : 'no rules evaluated'}
        ariaLabel="How each rule matched this request, in document order"
      >
        {d.trace.map((t) => {
          const decisive = t.id === d.decisive_rule;
          return (
            <ChecklistLine
              key={t.id}
              className={decisive ? '-mx-3 bg-hover px-3 shadow-[inset_1px_0_0_0_var(--amber)]' : undefined}
              label={
                <span className="inline-flex items-center gap-2">
                  <code className="font-mono text-xs">{t.id}</code>
                  {/* The rule's effect is a fact about the rule, not a state: a neutral tag. The stamp says whether it applied. */}
                  <span className="inline-flex h-5 items-center rounded-sm border border-line-control/50 px-1.5 text-2xs text-text-2">effect {t.effect}</span>
                </span>
              }
              value={decisive ? 'decisive' : undefined}
              state={t.matched ? (t.effect === 'deny' ? 'failed' : 'confirmed') : 'neutral'}
              stamp={t.matched ? 'Applies' : 'Does not apply'}
              drawKey={asked.serial}
              detail={`Principal ${mark(t.principal_matched)} · Action ${mark(t.action_matched)} · Model ${mark(t.model_matched)}`}
            />
          );
        })}
      </Checklist>
      <KeyValueList
        wide
        items={[
          ['Decisive rule', d.decisive_rule ? <code className="font-mono text-xs">{d.decisive_rule}</code> : <span className="text-text-3">none (no rule allows)</span>],
          [
            'Matched rules',
            d.matched_rules.length ? (
              <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                {d.matched_rules.map((r) => (
                  <span key={r.id} className="inline-flex items-center gap-1.5">
                    <code className="font-mono text-xs">{r.id}</code>
                    <span className="inline-flex h-5 items-center rounded-sm border border-line-control/50 px-1.5 text-2xs text-text-2">effect {r.effect}</span>
                  </span>
                ))}
              </span>
            ) : (
              <span className="text-text-3">none</span>
            ),
          ],
          [
            'Max tokens',
            d.allowed && limits ? (
              limits.max_tokens !== null ? (
                <span className="font-mono">{formatInt(limits.max_tokens)}</span>
              ) : (
                'no policy cap (the gateway ceiling still applies)'
              )
            ) : null,
          ],
          ['Streaming', d.allowed && limits ? (limits.allow_stream ? 'allowed' : 'not allowed') : null],
          ['App status', d.principal_status],
          [
            'Policy',
            d.policy_version !== null ? (
              <span className="inline-flex flex-wrap items-center gap-1.5">
                <span className="font-mono">v{d.policy_version}</span>
                {d.policy_sha256 ? <Digest value={d.policy_sha256} label="policy sha256" /> : null}
              </span>
            ) : (
              <span className="text-text-3">no active policy</span>
            ),
          ],
        ]}
      />
    </section>
  );
}
