/**
 * "What would happen if this app asked for this model now?" The server
 * evaluates the active policy (and the app's own status) without sending
 * anything to a backend; this page only displays the decision.
 */

import { useId, useState, type FormEvent } from 'react';
import { api, POLICY_ACTIONS, type App, type Decision, type ModelRoute, type PolicyAction } from '../../api.ts';
import { formErrors, type FormErrors } from '../../errors.ts';
import { MODEL_NAME } from '../../forms.ts';
import { formatInt } from '../../format.ts';
import { useResource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { Digest } from '../../components/Digest.tsx';
import { Field, FormErrorList } from '../../components/Field.tsx';
import { Callout, DefList, Panel } from '../../components/Panel.tsx';
import { Async, EmptyState } from '../../components/States.tsx';
import { Badge, StatusBadge } from '../../components/StatusBadge.tsx';

const NO_ERRORS: FormErrors = { fields: {}, general: [] };
const FIELDS = ['app', 'model', 'action'] as const;

interface Asked {
  app: string;
  model: string;
  action: PolicyAction;
  decision: Decision;
}

export function ExplainTab() {
  const apps = useResource((s) => api.apps(s), []);
  const routes = useResource((s) => api.routes(s), []);
  return (
    <Panel title="Explain a decision" description="Evaluates the active policy for one app, model and action. Nothing is sent to a backend.">
      <Async resource={apps} loadingLabel="Loading apps…">
        {(items) =>
          items.length === 0 ? (
            <EmptyState title="No apps to explain.">Create an app on the Apps and keys tab first.</EmptyState>
          ) : (
            <ExplainForm apps={items} routes={routes.data ?? []} />
          )
        }
      </Async>
    </Panel>
  );
}

function ExplainForm({ apps, routes }: { apps: readonly App[]; routes: readonly ModelRoute[] }) {
  const role = useRole();
  const listId = useId();
  const [app, setApp] = useState(apps[0]?.name ?? '');
  const [model, setModel] = useState(routes[0]?.model ?? '');
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
      setAsked({ app, model: m, action, decision });
    } catch (err) {
      setErrors(formErrors(err, FIELDS, role));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      <form className="form" onSubmit={(e) => void submit(e)} noValidate aria-label="Explain a decision">
        <div className="form-grid">
          <Field label="App" error={errors.fields['app']}>
            {(p) => (
              <select {...p} className="select" value={app} onChange={(e) => setApp(e.target.value)}>
                {apps.map((a) => (
                  <option key={a.id} value={a.name}>
                    {a.name} ({a.environment}
                    {a.disabled ? ', disabled' : ''})
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field label="Model" error={errors.fields['model']} hint={routes.length ? 'Routed models are suggested; any model name can be checked.' : undefined}>
            {(p) => (
              <>
                <input
                  {...p}
                  className="input input--mono"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  list={routes.length ? listId : undefined}
                  autoComplete="off"
                  spellCheck={false}
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
          <Field label="Action" error={errors.fields['action']}>
            {(p) => (
              <select {...p} className="select" value={action} onChange={(e) => setAction(e.target.value as PolicyAction)}>
                {POLICY_ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            )}
          </Field>
        </div>
        <FormErrorList messages={errors.general} />
        <div className="form-actions">
          <button type="submit" className="button button--primary" aria-disabled={busy || undefined}>
            {busy ? 'Evaluating…' : 'Explain'}
          </button>
        </div>
      </form>
      <div aria-live="polite">{asked ? <DecisionView asked={asked} /> : null}</div>
    </div>
  );
}

function Mark({ value }: { value: boolean | null }) {
  if (value === null) return <span className="subtle">n/a</span>;
  return <Badge tone={value ? 'ok' : 'neutral'}>{value ? 'matches' : 'no match'}</Badge>;
}

function DecisionView({ asked }: { asked: Asked }) {
  const d = asked.decision;
  const limits = d.limits;
  const appBlocked = d.principal_status !== null && d.principal_status !== 'active';
  return (
    <section className="decision" aria-label="Decision">
      <Callout
        tone={d.allowed ? 'ok' : 'bad'}
        title={
          <>
            {d.allowed ? 'Allowed' : 'Denied'}: <code>{d.principal ?? `app:${asked.app}`}</code> → <code>{asked.model}</code> (
            {asked.action})
          </>
        }
      >
        <p>{d.reason || (d.allowed ? 'allowed' : 'denied')}</p>
        {appBlocked && d.policy_allowed !== null ? (
          <p>
            The app is {d.principal_status}, so it is rejected before policy. The policy on its own would{' '}
            {d.policy_allowed ? 'allow' : 'deny'} this request.
          </p>
        ) : null}
      </Callout>
      <DefList
        wide
        items={[
          ['Decisive rule', d.decisive_rule ? <code>{d.decisive_rule}</code> : <span className="subtle">none (no rule allows)</span>],
          [
            'Matched rules',
            d.matched_rules.length ? (
              <span className="inline-list inline-list--loose">
                {d.matched_rules.map((r) => (
                  <span key={r.id} className="inline-list">
                    <code>{r.id}</code>
                    <StatusBadge domain="decision" value={r.effect} />
                  </span>
                ))}
              </span>
            ) : (
              <span className="subtle">none</span>
            ),
          ],
          [
            'Max tokens',
            d.allowed && limits ? (
              limits.max_tokens !== null ? (
                <span className="num">{formatInt(limits.max_tokens)}</span>
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
              <span>
                v{d.policy_version} {d.policy_sha256 ? <Digest value={d.policy_sha256} label="policy sha256" /> : null}
              </span>
            ) : (
              <span className="subtle">no active policy</span>
            ),
          ],
        ]}
      />
      {d.trace.length ? (
        <div className="subsection">
          <h3>Rule by rule</h3>
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="sr-only">How each rule matched this request, in document order</caption>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Effect</th>
                  <th scope="col">Principal</th>
                  <th scope="col">Action</th>
                  <th scope="col">Model</th>
                  <th scope="col">Applies</th>
                </tr>
              </thead>
              <tbody>
                {d.trace.map((t) => (
                  <tr key={t.id} className={t.id === d.decisive_rule ? 'is-selected' : undefined}>
                    <td>
                      <code>{t.id}</code>
                      {t.id === d.decisive_rule ? <span className="cell-note"> decisive</span> : null}
                    </td>
                    <td>
                      <StatusBadge domain="decision" value={t.effect} />
                    </td>
                    <td>
                      <Mark value={t.principal_matched} />
                    </td>
                    <td>
                      <Mark value={t.action_matched} />
                    </td>
                    <td>
                      <Mark value={t.model_matched} />
                    </td>
                    <td>{t.matched ? <span className="strong">yes</span> : 'no'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </section>
  );
}
