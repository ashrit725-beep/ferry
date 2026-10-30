/**
 * Policy editor: a JSON document checked locally for syntax, validated by the
 * server (errors with paths, warnings by rule), and activated as a new,
 * immutable version. Rolling back means loading an old version and
 * activating it again.
 */

import { useId, useRef, useState } from 'react';
import {
  ApiError,
  activationValidation,
  api,
  type Activation,
  type PolicyHistoryItem,
  type PolicyState,
  type PolicyValidation,
  type PolicyVersion,
} from '../../api.ts';
import { isObject } from '../../decode.ts';
import { appliedDespiteBody, describeError } from '../../errors.ts';
import { EMPTY_POLICY } from '../../forms.ts';
import { formatInt, plural } from '../../format.ts';
import { useResource } from '../../hooks.ts';
import { offsetOf, parseJson, prettyJson, sameDocument } from '../../json.ts';
import { useRole, useSession } from '../../session.tsx';
import { ConfirmDialog, Dialog } from '../../components/Dialog.tsx';
import { Digest } from '../../components/Digest.tsx';
import { Field } from '../../components/Field.tsx';
import { JsonView } from '../../components/JsonView.tsx';
import { Callout, DefList, Panel } from '../../components/Panel.tsx';
import { Async, EmptyState, InlineError } from '../../components/States.tsx';
import { Badge } from '../../components/StatusBadge.tsx';
import { Time } from '../../components/Time.tsx';

interface Source {
  label: string;
  text: string;
}

interface Checked {
  text: string;
  result: PolicyValidation;
  /** Came back from a refused activation rather than from Validate. */
  fromActivation: boolean;
}

interface ParseProblem {
  text: string;
  message: string;
  line: number | null;
  column: number | null;
}

function activeSource(state: PolicyState): Source {
  const active = state.active;
  return active
    ? { label: `active version ${active.version}`, text: prettyJson(active.document) }
    : { label: 'the empty policy (no policy is active yet)', text: prettyJson(EMPTY_POLICY) };
}

export function PolicyTab() {
  const { isAdmin } = useSession();
  const role = useRole();
  const policy = useResource((s) => api.policy(s), []);
  const [loaded, setLoaded] = useState<Source | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [checked, setChecked] = useState<Checked | null>(null);
  const [parseProblem, setParseProblem] = useState<ParseProblem | null>(null);
  const [validating, setValidating] = useState(false);
  const [requestError, setRequestError] = useState<unknown>(null);
  const [comment, setComment] = useState('');
  const [commentError, setCommentError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ document: unknown; text: string; rules: number | null } | null>(null);
  const [activating, setActivating] = useState(false);
  const [activateError, setActivateError] = useState<string | null>(null);
  const [activated, setActivated] = useState<Activation | null>(null);
  const [viewing, setViewing] = useState<number | null>(null);
  const editorRef = useRef<HTMLTextAreaElement>(null);
  const editorId = useId();
  const hintId = useId();
  const parseId = useId();

  const source = loaded ?? (policy.data ? activeSource(policy.data) : null);
  const text = draft ?? source?.text ?? '';
  const dirty = source !== null && draft !== null && !sameDocument(draft, source.text);
  const currentCheck = checked && checked.text === text ? checked : null;
  const currentParse = parseProblem && parseProblem.text === text ? parseProblem : null;

  const parseOrReport = (): { value: unknown } | null => {
    const parsed = parseJson(text);
    if (parsed.ok) {
      setParseProblem(null);
      return { value: parsed.value };
    }
    setParseProblem({ text, message: parsed.message, line: parsed.line, column: parsed.column });
    const el = editorRef.current;
    if (el) {
      el.focus();
      if (parsed.line !== null && parsed.column !== null) {
        const pos = offsetOf(text, parsed.line, parsed.column);
        el.setSelectionRange(pos, pos);
      }
    }
    return null;
  };

  const validate = async (): Promise<void> => {
    if (validating) return;
    const parsed = parseOrReport();
    if (!parsed) return;
    setValidating(true);
    setRequestError(null);
    try {
      setChecked({ text, result: await api.validatePolicy(parsed.value), fromActivation: false });
    } catch (err) {
      setRequestError(err);
    } finally {
      setValidating(false);
    }
  };

  const format = (): void => {
    const parsed = parseOrReport();
    if (parsed) setDraft(prettyJson(parsed.value));
  };

  const startActivate = (): void => {
    setActivateError(null);
    const parsed = parseOrReport();
    if (!parsed) return;
    if (!comment.trim()) {
      setCommentError('Say why this policy is being activated. The comment is stored with the version and in the audit log.');
      return;
    }
    setCommentError(null);
    const doc = parsed.value;
    const rules = isObject(doc) && Array.isArray(doc['rules']) ? doc['rules'].length : null;
    setConfirm({ document: doc, text, rules });
  };

  const activate = async (): Promise<void> => {
    if (!confirm || activating) return;
    setActivating(true);
    setActivateError(null);
    try {
      const result = await api.activatePolicy(confirm.document, comment.trim());
      setActivated(result);
      setLoaded({ label: `version ${result.version}, just activated`, text: confirm.text });
      setDraft(null);
      setComment('');
      setChecked(null);
      setConfirm(null);
      policy.reload();
    } catch (err) {
      const validation = err instanceof ApiError ? activationValidation(err) : null;
      if (validation) {
        setChecked({ text: confirm.text, result: validation, fromActivation: true });
        setConfirm(null);
      } else if (appliedDespiteBody(err)) {
        setConfirm(null);
        setLoaded(null);
        setDraft(null);
        policy.reload();
      } else {
        setActivateError(describeError(err, role));
      }
    } finally {
      setActivating(false);
    }
  };

  const loadVersion = (pv: PolicyVersion): void => {
    setLoaded({ label: `version ${pv.version}`, text: prettyJson(pv.document) });
    setDraft(null);
    setViewing(null);
    setActivated(null);
  };

  return (
    <div className="grid grid--split">
      <Panel
        title="Policy document"
        description={source ? <>Started from {source.label}.</> : null}
        actions={dirty ? <span className="tag tag--attention">unsaved changes</span> : null}
      >
        {policy.data === null ? (
          <Async resource={policy} loadingLabel="Loading the policy…">
            {() => null}
          </Async>
        ) : (
          <div className="form">
            <div className="field">
              <label className="field__label" htmlFor={editorId}>
                Policy JSON <span className="field__optional">(schema ferry.dev/access-policy/v1)</span>
              </label>
              <textarea
                id={editorId}
                ref={editorRef}
                className="textarea editor"
                value={text}
                onChange={(e) => setDraft(e.target.value)}
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                autoCorrect="off"
                rows={24}
                aria-describedby={currentParse ? `${parseId} ${hintId}` : hintId}
                aria-invalid={currentParse ? true : undefined}
              />
              {currentParse ? (
                <p id={parseId} className="field__error" role="alert">
                  Not valid JSON: {currentParse.message}
                  {currentParse.line !== null ? ` (line ${currentParse.line}, column ${currentParse.column})` : ''}.
                </p>
              ) : null}
              <p id={hintId} className="field__hint">
                A matching deny always wins; otherwise a matching allow allows; anything else is denied. Principals are{' '}
                <code>app:NAME</code>, <code>app:*</code> or <code>*</code>; models an exact name, <code>*</code>, or a prefix such
                as <code>qwen-*</code>.
              </p>
            </div>
            <div className="form-actions">
              <button type="button" className="button" onClick={() => void validate()} aria-disabled={validating || undefined}>
                {validating ? 'Validating…' : 'Validate'}
              </button>
              <button type="button" className="button button--ghost" onClick={format}>
                Format JSON
              </button>
              {dirty ? (
                <button type="button" className="button button--ghost" onClick={() => setDraft(null)}>
                  Discard changes
                </button>
              ) : null}
              {loaded ? (
                <button
                  type="button"
                  className="button button--ghost"
                  onClick={() => {
                    setLoaded(null);
                    setDraft(null);
                  }}
                >
                  Start from the active policy
                </button>
              ) : null}
            </div>
            <div className="validation-area">
              {currentCheck ? (
                <ValidationResult check={currentCheck} />
              ) : checked ? (
                <p className="field__hint">The document has changed since it was last checked.</p>
              ) : null}
              {requestError ? <InlineError error={requestError} prefix="Validation did not run." /> : null}
            </div>
            {isAdmin ? (
              <div className="activate-box">
                <h3>Activate</h3>
                <Field label="Comment" error={commentError} hint="Why this change is being made. Stored with the version and in the audit log.">
                  {(p) => (
                    <input {...p} className="input" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={1000} autoComplete="off" />
                  )}
                </Field>
                <div className="form-actions">
                  <button type="button" className="button button--primary" onClick={startActivate}>
                    Activate as a new version
                  </button>
                </div>
                {activated ? (
                  <Callout tone="ok" role="status" title={`Activated version ${activated.version}`}>
                    <p>
                      It applies from the next gateway request. SHA-256 <Digest value={activated.sha256} label="policy sha256" />
                    </p>
                    {activated.warnings.length ? (
                      <ul>
                        {activated.warnings.map((w, i) => (
                          <li key={i}>
                            {w.rule_id ? <code>{w.rule_id}</code> : null} {w.message}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </Callout>
                ) : null}
              </div>
            ) : (
              <p className="field__hint">Validation is open to every role. Activating a policy requires the admin role.</p>
            )}
          </div>
        )}
      </Panel>

      <div className="stack">
        <Panel title="Active policy">
          <Async resource={policy} loadingLabel="Loading…">
            {(state) =>
              state.active ? (
                <DefList
                  items={[
                    ['Version', <span className="num">v{state.active.version}</span>],
                    ['Activated', <Time value={state.active.activated_at} exact />],
                    ['Activated by', state.active.activated_by],
                    ['Comment', state.active.comment || <span className="subtle">none</span>],
                    ['Rules', <span className="num">{formatInt(ruleCount(state.active.document))}</span>],
                    ['SHA-256', <Digest value={state.active.sha256} label="active policy sha256" />],
                  ]}
                />
              ) : (
                <Callout tone="bad" title="No active policy">
                  <p>Every gateway request is denied until a policy is activated.</p>
                </Callout>
              )
            }
          </Async>
        </Panel>
        <Panel title="Version history" flush>
          <Async resource={policy} loadingLabel="Loading…">
            {(state) => <History items={state.history} onView={setViewing} />}
          </Async>
        </Panel>
      </div>

      <ConfirmDialog
        open={confirm !== null}
        title="Activate this policy?"
        confirmLabel="Activate"
        busyLabel="Activating…"
        busy={activating}
        error={activateError}
        onConfirm={() => void activate()}
        onCancel={() => setConfirm(null)}
      >
        <p>
          The document {confirm?.rules !== null && confirm?.rules !== undefined ? `(${plural(confirm.rules, 'rule')}) ` : ''}is
          stored as a new version and decides the next gateway request.
          {policy.data?.active ? ` Version ${policy.data.active.version} stays in the history and can be activated again.` : ''}
        </p>
        <p>
          Comment: <q>{comment.trim()}</q>
        </p>
      </ConfirmDialog>

      {viewing !== null ? (
        <VersionDialog version={viewing} dirty={dirty} onClose={() => setViewing(null)} onLoad={loadVersion} />
      ) : null}
    </div>
  );
}

function ruleCount(doc: unknown): number {
  return isObject(doc) && Array.isArray(doc['rules']) ? doc['rules'].length : 0;
}

function ValidationResult({ check }: { check: Checked }) {
  const { result, fromActivation } = check;
  const warnings = result.warnings.length ? (
    <ul>
      {result.warnings.map((w, i) => (
        <li key={i}>
          {w.rule_id ? (
            <>
              <code>{w.rule_id}</code>:{' '}
            </>
          ) : null}
          {w.message}
        </li>
      ))}
    </ul>
  ) : null;
  if (result.valid) {
    return (
      <Callout
        tone={result.warnings.length ? 'warn' : 'ok'}
        role="status"
        title={result.warnings.length ? `Valid, with ${plural(result.warnings.length, 'warning')}` : 'Valid, no warnings'}
      >
        {warnings}
      </Callout>
    );
  }
  return (
    <Callout
      tone="bad"
      role="alert"
      title={`${fromActivation ? 'Not activated: ' : ''}${plural(result.errors.length, 'error')}`}
    >
      <ul>
        {result.errors.map((e, i) => (
          <li key={i}>
            <code>{e.path || 'document'}</code> {e.message}
          </li>
        ))}
      </ul>
      {warnings}
    </Callout>
  );
}

function History({ items, onView }: { items: readonly PolicyHistoryItem[]; onView: (version: number) => void }) {
  if (items.length === 0) {
    return <EmptyState title="No policy has been activated yet.">Until one is, every gateway request is denied.</EmptyState>;
  }
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Policy versions, newest first</caption>
        <thead>
          <tr>
            <th scope="col" className="num">
              Version
            </th>
            <th scope="col">Created</th>
            <th scope="col">Comment</th>
            <th scope="col" className="actions">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((h) => (
            <tr key={h.version}>
              <td className="num">
                v{h.version}
                {h.active ? (
                  <div>
                    <Badge tone="ok">active</Badge>
                  </div>
                ) : null}
              </td>
              <td>
                <Time value={h.created_at} />
                <div className="cell-note">{h.created_by}</div>
              </td>
              <td className="break">{h.comment || <span className="subtle">none</span>}</td>
              <td className="actions">
                <button type="button" className="button button--small" onClick={() => onView(h.version)} aria-label={`View policy version ${h.version}`}>
                  View
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Any role may load a version into the editor: auditors can validate it, only admins can activate. */
function VersionDialog({
  version,
  dirty,
  onClose,
  onLoad,
}: {
  version: number;
  dirty: boolean;
  onClose: () => void;
  onLoad: (pv: PolicyVersion) => void;
}) {
  const pv = useResource((s) => api.policyVersion(version, s), [version]);
  const data = pv.data;
  return (
    <Dialog
      open
      wide
      title={`Policy version ${version}`}
      onClose={onClose}
      footer={
        <>
          {data ? (
            <button type="button" className="button" onClick={() => onLoad(data)}>
              Load into editor
            </button>
          ) : null}
          <button type="button" className="button button--primary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <Async resource={pv} loadingLabel="Loading the version…">
        {(v) => (
          <>
            <DefList
              items={[
                ['Status', v.active ? <Badge tone="ok">active</Badge> : 'not active'],
                ['Created', <Time value={v.created_at} exact />],
                ['Created by', v.created_by],
                ['Comment', v.comment || <span className="subtle">none</span>],
                ['SHA-256', <Digest value={v.sha256} label="policy sha256" />],
              ]}
            />
            {dirty ? <Callout tone="warn">Loading this version replaces the unsaved text in the editor.</Callout> : null}
            <JsonView value={v.document} copyLabel="Copy policy JSON" />
            <p className="field__hint">To roll back, load this version into the editor and activate it. It is stored as a new version.</p>
          </>
        )}
      </Async>
    </Dialog>
  );
}
