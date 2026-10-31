/**
 * Policy editor: a JSON document checked locally for syntax, validated by the
 * server (errors with paths, warnings by rule), and activated as a new,
 * immutable version. Rolling back means loading an old version and
 * activating it again. Findings are read as a checklist: the document line
 * first, then one line per error and warning.
 */

import { useRef, useState } from 'react';
import { toast } from 'sonner';
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
import { Callout } from '../../components/console/callout.tsx';
import { Checklist, ChecklistLine } from '../../components/console/checklist.tsx';
import { ConfirmDialog } from '../../components/console/confirm-dialog.tsx';
import { DataTable } from '../../components/console/data-table.tsx';
import { Dialog } from '../../components/console/dialog.tsx';
import { Digest } from '../../components/console/digest.tsx';
import { FormActions, TextField } from '../../components/console/form-field.tsx';
import { JsonView } from '../../components/console/json-view.tsx';
import { KeyValueList } from '../../components/console/key-value-list.tsx';
import { Section } from '../../components/console/section.tsx';
import { Stamp } from '../../components/console/stamp.tsx';
import { Async, EmptyState, InlineError, PanelSkeleton, Spinner } from '../../components/console/states.tsx';
import { Time } from '../../components/console/time.tsx';
import { Button } from '../../components/ui/button.tsx';
import { PolicyEditor, type EditorHandle } from './PolicyEditor.tsx';

interface Source {
  label: string;
  text: string;
}

interface Checked {
  text: string;
  result: PolicyValidation;
  /** Came back from a refused activation rather than from Validate. */
  fromActivation: boolean;
  /** Redraws the checklist when the same document is checked again. */
  serial: number;
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

function ruleCount(doc: unknown): number {
  return isObject(doc) && Array.isArray(doc['rules']) ? doc['rules'].length : 0;
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
  const editorRef = useRef<EditorHandle>(null);
  const commentRef = useRef<HTMLInputElement>(null);

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
    editorRef.current?.focusAt(parsed.line !== null && parsed.column !== null ? offsetOf(text, parsed.line, parsed.column) : null);
    return null;
  };

  const validate = async (): Promise<void> => {
    if (validating) return;
    const parsed = parseOrReport();
    if (!parsed) return;
    setValidating(true);
    setRequestError(null);
    try {
      const result = await api.validatePolicy(parsed.value);
      setChecked((prev) => ({ text, result, fromActivation: false, serial: (prev?.serial ?? 0) + 1 }));
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
      commentRef.current?.focus();
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
      toast.success(`Policy v${result.version} activated`, { description: `SHA-256 ${result.sha256}` });
    } catch (err) {
      const validation = err instanceof ApiError ? activationValidation(err) : null;
      if (validation) {
        setChecked((prev) => ({ text: confirm.text, result: validation, fromActivation: true, serial: (prev?.serial ?? 0) + 1 }));
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
    <div className="grid grid-cols-1 items-start gap-4 min-[1181px]:grid-cols-[minmax(0,1fr)_minmax(320px,400px)]">
      <Section
        title="Policy document"
        description={source ? <>Started from {source.label}.</> : null}
        actions={dirty ? <Stamp state="pending">Unsaved changes</Stamp> : null}
      >
        {policy.data === null ? (
          <Async resource={policy} skeleton={<PanelSkeleton lines={12} />}>
            {() => null}
          </Async>
        ) : (
          <div className="flex flex-col gap-3">
            <PolicyEditor
              ref={editorRef}
              value={text}
              onChange={setDraft}
              parseProblem={currentParse}
              hint={
                <>
                  A matching deny always wins; otherwise a matching allow allows; anything else is denied. Principals are{' '}
                  <code className="code-inline font-mono text-text-2">app:NAME</code>, <code className="code-inline font-mono text-text-2">app:*</code> or <code className="code-inline font-mono text-text-2">*</code>; models
                  an exact name, <code className="code-inline font-mono text-text-2">*</code>, or a prefix such as <code className="code-inline font-mono text-text-2">qwen-*</code>.
                </>
              }
            />
            <FormActions>
              <Button type="button" variant="outline" onClick={() => void validate()} aria-busy={validating || undefined} aria-disabled={validating || undefined}>
                {validating ? <Spinner className="text-current" /> : null}
                {validating ? 'Validating…' : 'Validate'}
              </Button>
              <Button type="button" variant="ghost" onClick={format}>
                Format JSON
              </Button>
              {dirty ? (
                <Button type="button" variant="ghost" onClick={() => setDraft(null)}>
                  Discard changes
                </Button>
              ) : null}
              {loaded ? (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => {
                    setLoaded(null);
                    setDraft(null);
                  }}
                >
                  Start from the active policy
                </Button>
              ) : null}
            </FormActions>

            {currentCheck || checked || requestError ? (
              <div className="flex flex-col gap-2">
                {currentCheck ? (
                  <ValidationResult check={currentCheck} />
                ) : checked ? (
                  <p className="text-xs text-text-3">The document has changed since it was last checked.</p>
                ) : null}
                {requestError ? <InlineError error={requestError} prefix="Validation did not run." /> : null}
              </div>
            ) : null}

            {isAdmin ? (
              <div className="mt-1 flex flex-col gap-3 border-t border-hairline pt-3">
                <h3 className="text-2xs font-medium tracking-[0.14em] text-text-3 uppercase">Activate</h3>
                <TextField
                  ref={commentRef}
                  label="Comment"
                  error={commentError}
                  hint="Why this change is being made. Stored with the version and in the audit log."
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  maxLength={1000}
                  autoComplete="off"
                />
                <FormActions>
                  <Button type="button" onClick={startActivate}>
                    Activate as a new version
                  </Button>
                </FormActions>
                {activated ? <ActivatedResult activated={activated} /> : null}
              </div>
            ) : (
              <p className="border-t border-hairline pt-3 text-xs text-text-3">Validation is open to every role. Activating a policy requires the admin role.</p>
            )}
          </div>
        )}
      </Section>

      <div className="flex min-w-0 flex-col gap-4">
        <Section title="Active policy">
          <Async resource={policy} skeleton={<PanelSkeleton lines={6} />}>
            {(state) =>
              state.active ? (
                <div className="flex flex-col gap-3">
                  <Checklist as="div" ariaLabel="Policy in force">
                    <ChecklistLine as="div" label="Policy in force" state="confirmed" value={`v${state.active.version}`} stamp="Active" drawKey={state.active.version} />
                  </Checklist>
                  <KeyValueList
                    items={[
                      { term: 'Version', value: `v${state.active.version}`, mono: true },
                      ['Activated', <Time value={state.active.activated_at} exact />],
                      ['Activated by', state.active.activated_by],
                      ['Comment', state.active.comment || <span className="text-text-3">none</span>],
                      { term: 'Rules', value: formatInt(ruleCount(state.active.document)), mono: true },
                      ['SHA-256', <Digest value={state.active.sha256} label="active policy sha256" />],
                    ]}
                  />
                </div>
              ) : (
                <Callout tone="bad" title="No active policy">
                  <p>Every gateway request is denied until a policy is activated.</p>
                </Callout>
              )
            }
          </Async>
        </Section>
        <Section
          title="Version history"
          flush
          actions={
            policy.refreshing ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-text-3" role="status">
                <Spinner />
                Refreshing…
              </span>
            ) : null
          }
        >
          <History policy={policy.data} loading={policy.loading} error={policy.error} onRetry={policy.reload} onView={setViewing} />
        </Section>
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
          The document {confirm?.rules !== null && confirm?.rules !== undefined ? `(${plural(confirm.rules, 'rule')}) ` : ''}is stored as a new
          version and decides the next gateway request.
          {policy.data?.active ? ` Version ${policy.data.active.version} stays in the history and can be activated again.` : ''}
        </p>
        <p>
          Comment: <q>{comment.trim()}</q>
        </p>
      </ConfirmDialog>

      {viewing !== null ? <VersionDialog version={viewing} dirty={dirty} onClose={() => setViewing(null)} onLoad={loadVersion} /> : null}
    </div>
  );
}

function ValidationResult({ check }: { check: Checked }) {
  const { result, fromActivation, serial } = check;
  const warnings = result.warnings.length;
  const title = result.valid
    ? warnings
      ? `Valid, with ${plural(warnings, 'warning')}`
      : 'Valid, no warnings'
    : `${fromActivation ? 'Not activated: ' : ''}${plural(result.errors.length, 'error')}`;
  return (
    <div role={result.valid ? 'status' : 'alert'}>
      <Checklist label="Validation" summary={`${plural(result.errors.length, 'error')} · ${plural(warnings, 'warning')}`} ariaLabel="Validation findings">
        <ChecklistLine
          label={title}
          state={result.valid ? (warnings ? 'warning' : 'confirmed') : 'failed'}
          stamp={result.valid ? 'Valid' : fromActivation ? 'Not activated' : 'Invalid'}
          drawKey={serial}
        />
        {result.errors.map((e, i) => (
          <ChecklistLine
            key={`e${i}`}
            label={<code className="font-mono text-xs">{e.path || 'document'}</code>}
            state="failed"
            stamp="Error"
            detail={<span className="text-text-2">{e.message}</span>}
            drawKey={serial}
          />
        ))}
        {result.warnings.map((w, i) => (
          <ChecklistLine
            key={`w${i}`}
            label={w.rule_id ? <code className="font-mono text-xs">{w.rule_id}</code> : 'document'}
            state="warning"
            stamp="Warning"
            detail={<span className="text-text-2">{w.message}</span>}
            drawKey={serial}
          />
        ))}
      </Checklist>
    </div>
  );
}

function ActivatedResult({ activated }: { activated: Activation }) {
  return (
    <div role="status">
      <Checklist ariaLabel="Activation result">
        <ChecklistLine
          label={`Activated version ${activated.version}`}
          state="confirmed"
          value={`v${activated.version}`}
          stamp="Active"
          drawKey={activated.version}
          detail={
            <span className="inline-flex flex-wrap items-center gap-x-1.5">
              It applies from the next gateway request. SHA-256 <Digest value={activated.sha256} label="policy sha256" reveal />
            </span>
          }
        />
        {activated.warnings.map((w, i) => (
          <ChecklistLine
            key={i}
            label={w.rule_id ? <code className="font-mono text-xs">{w.rule_id}</code> : 'document'}
            state="warning"
            stamp="Warning"
            detail={<span className="text-text-2">{w.message}</span>}
          />
        ))}
      </Checklist>
    </div>
  );
}

function History({
  policy,
  loading,
  error,
  onRetry,
  onView,
}: {
  policy: PolicyState | null;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  onView: (version: number) => void;
}) {
  const rows: readonly PolicyHistoryItem[] | null = policy ? policy.history : null;
  return (
    <DataTable
      caption="Policy versions, newest first"
      rows={rows}
      rowKey={(h) => String(h.version)}
      loading={loading}
      error={error}
      onRetry={onRetry}
      skeletonRows={4}
      maxHeight="max-h-[60vh]"
      minWidth="min-w-0"
      empty={<EmptyState title="No policy has been activated yet.">Until one is, every gateway request is denied.</EmptyState>}
      columns={[
        {
          id: 'version',
          header: 'Version',
          nowrap: true,
          cell: (h) => (
            <span className="inline-flex items-center gap-1.5">
              <span className="font-mono">v{h.version}</span>
              {h.active ? <Stamp state="confirmed" land={false}>Active</Stamp> : null}
            </span>
          ),
        },
        {
          id: 'created',
          header: 'Created',
          nowrap: true,
          cell: (h) => (
            <div className="py-0.5">
              <Time value={h.created_at} />
              <div className="max-w-28 truncate text-text-3" title={h.created_by}>
                {h.created_by}
              </div>
            </div>
          ),
        },
        { id: 'comment', header: 'Comment', cell: (h) => h.comment || <span className="text-text-3">none</span> },
        {
          id: 'actions',
          header: 'Actions',
          srOnlyHeader: true,
          align: 'right',
          nowrap: true,
          width: 'w-px',
          cell: (h) => (
            <Button type="button" variant="outline" size="sm" onClick={() => onView(h.version)} aria-label={`View policy version ${h.version}`}>
              View
            </Button>
          ),
        },
      ]}
    />
  );
}

/** Any role may load a version into the editor: auditors can validate it, only admins can activate. */
function VersionDialog({ version, dirty, onClose, onLoad }: { version: number; dirty: boolean; onClose: () => void; onLoad: (pv: PolicyVersion) => void }) {
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
            <Button type="button" variant="outline" onClick={() => onLoad(data)}>
              Load into editor
            </Button>
          ) : null}
          <Button type="button" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <Async resource={pv} loadingLabel="Loading the version…" skeleton={<PanelSkeleton lines={8} />}>
        {(v) => (
          <div className="flex flex-col gap-3">
            <KeyValueList
              items={[
                ['Status', v.active ? <Stamp state="confirmed" land={false}>Active</Stamp> : <Stamp state="neutral" land={false}>Not active</Stamp>],
                ['Created', <Time value={v.created_at} exact />],
                ['Created by', v.created_by],
                ['Comment', v.comment || <span className="text-text-3">none</span>],
                ['SHA-256', <Digest value={v.sha256} label="policy sha256" />],
              ]}
            />
            {dirty ? <Callout tone="warn">Loading this version replaces the unsaved text in the editor.</Callout> : null}
            <JsonView value={v.document} copyLabel="Copy policy JSON" />
            <p className="text-xs text-text-3">To roll back, load this version into the editor and activate it. It is stored as a new version.</p>
          </div>
        )}
      </Async>
    </Dialog>
  );
}
