/**
 * Inference backends: health as last checked, what each one serves, and the
 * admin controls (check now, enable or disable, delete, add).
 */

import { useState, type FormEvent } from 'react';
import { api, BACKEND_KINDS, type Backend, type BackendInput, type BackendKind } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { joinBaseUrl, optionalNumber, optionalText, SCHEMES, splitBaseUrl, type Scheme } from '../../forms.ts';
import { formatMs } from '../../format.ts';
import type { Resource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { ConfirmDialog } from '../../components/Dialog.tsx';
import { Digest } from '../../components/Digest.tsx';
import { Field, FormErrorList } from '../../components/Field.tsx';
import { IconPlus } from '../../components/Icons.tsx';
import { Notice, Panel, type NoticeMessage } from '../../components/Panel.tsx';
import { Async, EmptyState, InlineError } from '../../components/States.tsx';
import { StatusBadge } from '../../components/StatusBadge.tsx';
import { Time } from '../../components/Time.tsx';

const BACKEND_FIELDS = ['name', 'kind', 'base_url', 'auth_token_file', 'timeout_s', 'max_concurrency'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

const KIND_LABELS: Record<BackendKind, string> = {
  llamacpp: 'llama.cpp (llama-server)',
  ollama: 'Ollama',
  openai: 'OpenAI-compatible (vLLM and others)',
};

export function BackendsPanel({
  backends,
  isAdmin,
  onChanged,
}: {
  backends: Resource<Backend[]>;
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const role = useRole();
  const [adding, setAdding] = useState(false);
  const [notice, setNotice] = useState<NoticeMessage | null>(null);
  const [actionError, setActionError] = useState<{ name: string; error: unknown } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [toDelete, setToDelete] = useState<Backend | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const act = async (backend: Backend, what: 'check' | 'toggle'): Promise<void> => {
    setBusy(`${what}:${backend.id}`);
    setActionError(null);
    setNotice(null);
    try {
      if (what === 'check') {
        const result = await api.checkBackend(backend.id);
        setNotice({ text: `Checked ${backend.name}: ${result.status.state}.` });
      } else {
        await api.updateBackend(backend.id, { enabled: !backend.enabled });
        setNotice({ text: `Backend ${backend.name} ${backend.enabled ? 'disabled' : 'enabled'}.` });
      }
      onChanged();
    } catch (err) {
      if (appliedDespiteBody(err)) onChanged();
      else setActionError({ name: backend.name, error: err });
    } finally {
      setBusy(null);
    }
  };

  const confirmDelete = async (): Promise<void> => {
    if (!toDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteBackend(toDelete.id);
      setNotice({ text: `Backend ${toDelete.name} deleted.`, focus: true });
      setToDelete(null);
      onChanged();
    } catch (err) {
      setDeleteError(describeError(err, role));
    } finally {
      setDeleting(false);
    }
  };

  return (
    <Panel
      title="Backends"
      description="Inference servers on loopback or private addresses. Health is checked in the background and on demand."
      actions={
        isAdmin ? (
          <button type="button" className="button" aria-expanded={adding} onClick={() => setAdding((a) => !a)}>
            <IconPlus />
            Add backend
          </button>
        ) : null
      }
      flush
    >
      {adding ? (
        <BackendForm
          onCancel={() => setAdding(false)}
          onCreated={(name) => {
            setAdding(false);
            setNotice({ text: `Backend ${name} added. Use Check now to see its state.` });
            onChanged();
          }}
        />
      ) : null}
      <Notice notice={notice} />
      {actionError ? (
        <div className="panel-inset">
          <InlineError error={actionError.error} prefix={`${actionError.name}:`} />
        </div>
      ) : null}
      <Async resource={backends} loadingLabel="Loading backends…">
        {(items) => (
          <BackendsTable
            backends={items}
            isAdmin={isAdmin}
            busy={busy}
            onCheck={(b) => void act(b, 'check')}
            onToggle={(b) => void act(b, 'toggle')}
            onDelete={(b) => {
              setDeleteError(null);
              setToDelete(b);
            }}
          />
        )}
      </Async>
      <ConfirmDialog
        open={toDelete !== null}
        title={`Delete backend ${toDelete?.name ?? ''}?`}
        confirmLabel="Delete backend"
        busyLabel="Deleting…"
        danger
        busy={deleting}
        error={deleteError}
        onConfirm={() => void confirmDelete()}
        onCancel={() => setToDelete(null)}
      >
        <p>
          The server refuses while routes still use this backend; delete or move those routes first. The inference server itself
          is not touched.
        </p>
      </ConfirmDialog>
    </Panel>
  );
}

function BackendsTable({
  backends,
  isAdmin,
  busy,
  onCheck,
  onToggle,
  onDelete,
}: {
  backends: readonly Backend[];
  isAdmin: boolean;
  busy: string | null;
  onCheck: (backend: Backend) => void;
  onToggle: (backend: Backend) => void;
  onDelete: (backend: Backend) => void;
}) {
  if (backends.length === 0) {
    return (
      <EmptyState title="No backends configured.">
        {isAdmin ? 'Add a backend' : 'An admin can add a backend'} here, or on the host with{' '}
        <code>ferry backend add NAME --kind llamacpp --url URL</code>. For an imported GGUF model,{' '}
        <code>ferry runtime llamacpp MODEL</code> prints a llama-server command and registers the backend and route.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Backends</caption>
        <thead>
          <tr>
            <th scope="col">Backend</th>
            <th scope="col">Base URL</th>
            <th scope="col">State</th>
            <th scope="col">Last check</th>
            <th scope="col">Serving</th>
            <th scope="col" className="num">
              Limits
            </th>
            {isAdmin ? (
              <th scope="col" className="actions">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {backends.map((b) => {
            const status = b.last_status;
            const checking = busy === `check:${b.id}`;
            const toggling = busy === `toggle:${b.id}`;
            return (
              <tr key={b.id}>
                <td className="top">
                  <span className="strong">{b.name}</span>
                  <div className="inline-list cell-note">
                    <span className="tag tag--mono">{b.kind}</span>
                    {b.has_token ? <span className="tag">token file</span> : null}
                    {b.enabled ? null : <span className="tag">disabled</span>}
                  </div>
                </td>
                <td className="top nowrap">
                  <code>{b.base_url}</code>
                </td>
                <td className="top">
                  <StatusBadge domain="backend" value={status?.state ?? null} label={status?.state ?? 'not checked'} />
                  {status?.error ? <div className="cell-note text-bad">{status.error}</div> : null}
                  {status?.version ? <div className="cell-note">version {status.version}</div> : null}
                </td>
                <td className="top">
                  <Time value={status?.checked_at ?? b.last_checked_at} fallback="never" />
                  {status ? (
                    <div className="cell-note">
                      {status.latency_ms !== null ? formatMs(status.latency_ms) : null}
                      {status.http_status !== null ? ` · HTTP ${status.http_status}` : null}
                    </div>
                  ) : null}
                </td>
                <td className="top">
                  <Serving backend={b} />
                </td>
                <td className="top num">
                  <div>{b.timeout_s} s timeout</div>
                  <div className="cell-note">{b.max_concurrency} concurrent</div>
                </td>
                {isAdmin ? (
                  <td className="top actions">
                    <div className="row">
                      <button
                        type="button"
                        className="button button--small"
                        aria-disabled={busy !== null || undefined}
                        aria-label={`Check ${b.name} now`}
                        onClick={() => {
                          if (busy === null) onCheck(b);
                        }}
                      >
                        {checking ? 'Checking…' : 'Check now'}
                      </button>
                      <button
                        type="button"
                        className="button button--small"
                        aria-disabled={busy !== null || undefined}
                        aria-label={`${b.enabled ? 'Disable' : 'Enable'} backend ${b.name}`}
                        onClick={() => {
                          if (busy === null) onToggle(b);
                        }}
                      >
                        {toggling ? 'Saving…' : b.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        type="button"
                        className="button button--small button--ghost text-bad"
                        aria-label={`Delete backend ${b.name}`}
                        onClick={() => onDelete(b)}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Serving({ backend }: { backend: Backend }) {
  const status = backend.last_status;
  if (!status) return <span className="subtle">unknown until checked</span>;
  if (status.served.length === 0 && status.models.length === 0) return <span className="subtle">nothing reported</span>;
  return (
    <div className="stack-xs">
      {status.models.length ? (
        <span className="inline-list">
          {status.models.map((m) => (
            <span key={m} className="tag tag--mono">
              {m}
            </span>
          ))}
        </span>
      ) : null}
      {status.served.map((f, i) => (
        <div key={`${f.path ?? ''}-${i}`} className="cell-note">
          {f.path ? <code className="break">{f.path}</code> : <span>{f.model_id ?? 'file'}</span>}
          {f.digest ? (
            <>
              {' '}
              <Digest value={f.digest} label="served file digest" />
            </>
          ) : (
            <span> · not a store file</span>
          )}
        </div>
      ))}
    </div>
  );
}

function BackendForm({ onCreated, onCancel }: { onCreated: (name: string) => void; onCancel: () => void }) {
  const role = useRole();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<BackendKind>('llamacpp');
  const [scheme, setScheme] = useState<Scheme>('http');
  const [address, setAddress] = useState('');
  const [tokenFile, setTokenFile] = useState('');
  const [timeout, setTimeoutText] = useState('');
  const [concurrency, setConcurrency] = useState('');
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);

  const onAddress = (value: string): void => {
    const split = splitBaseUrl(value);
    if (split.scheme) {
      setScheme(split.scheme);
      setAddress(split.address);
    } else {
      setAddress(value);
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const fields: Record<string, string> = {};
    const timeoutValue = optionalNumber(timeout, { min: 0 });
    const concurrencyValue = optionalNumber(concurrency, { integer: true, min: 1 });
    if (!name.trim()) fields['name'] = 'Enter a name for this backend.';
    if (!address.trim()) fields['base_url'] = 'Enter the host and port, for example 127.0.0.1:8080.';
    if (!timeoutValue.ok) fields['timeout_s'] = timeoutValue.error;
    if (!concurrencyValue.ok) fields['max_concurrency'] = concurrencyValue.error;
    if (Object.keys(fields).length || !timeoutValue.ok || !concurrencyValue.ok) {
      setErrors({ fields, general: [] });
      return;
    }
    const tokenPath = optionalText(tokenFile);
    const input: BackendInput = {
      name: name.trim(),
      kind,
      base_url: joinBaseUrl(scheme, address),
      ...(tokenPath ? { auth_token_file: tokenPath } : {}),
      ...(timeoutValue.value !== undefined ? { timeout_s: timeoutValue.value } : {}),
      ...(concurrencyValue.value !== undefined ? { max_concurrency: concurrencyValue.value } : {}),
    };
    setBusy(true);
    setErrors(NO_ERRORS);
    try {
      await api.createBackend(input);
      onCreated(input.name);
    } catch (err) {
      if (appliedDespiteBody(err)) onCreated(input.name);
      else setErrors(formErrors(err, BACKEND_FIELDS, role));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form form-panel" onSubmit={(e) => void submit(e)} noValidate aria-label="Add backend">
      <div className="form-grid">
        <Field label="Name" error={errors.fields['name']}>
          {(p) => <input {...p} className="input" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" spellCheck={false} />}
        </Field>
        <Field label="Kind" error={errors.fields['kind']}>
          {(p) => (
            <select {...p} className="select" value={kind} onChange={(e) => setKind(e.target.value as BackendKind)}>
              {BACKEND_KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Scheme">
          {(p) => (
            <select {...p} className="select" value={scheme} onChange={(e) => setScheme(e.target.value as Scheme)}>
              {SCHEMES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field
          label="Host and port"
          error={errors.fields['base_url']}
          hint="Must resolve to a loopback or private address unless allow_public_backends is set in ferry.toml. A pasted full URL is split automatically."
        >
          {(p) => (
            <input
              {...p}
              className="input input--mono"
              value={address}
              onChange={(e) => onAddress(e.target.value)}
              placeholder="127.0.0.1:8080"
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </Field>
        <Field
          label="Token file"
          optional
          error={errors.fields['auth_token_file']}
          hint="Absolute path on the server to a file whose first line is the backend's bearer token. Set from the console, it must be inside Ferry's secrets directory and not readable by group or others. The token is never shown."
        >
          {(p) => (
            <input {...p} className="input input--mono" value={tokenFile} onChange={(e) => setTokenFile(e.target.value)} autoComplete="off" spellCheck={false} />
          )}
        </Field>
        <Field label="Read timeout (seconds)" optional error={errors.fields['timeout_s']}>
          {(p) => <input {...p} className="input" inputMode="decimal" value={timeout} onChange={(e) => setTimeoutText(e.target.value)} autoComplete="off" />}
        </Field>
        <Field label="Max concurrent requests" optional error={errors.fields['max_concurrency']}>
          {(p) => <input {...p} className="input" inputMode="numeric" value={concurrency} onChange={(e) => setConcurrency(e.target.value)} autoComplete="off" />}
        </Field>
      </div>
      <FormErrorList messages={errors.general} />
      <div className="form-actions">
        <button type="submit" className="button button--primary" aria-disabled={busy || undefined}>
          {busy ? 'Adding…' : 'Add backend'}
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
