/**
 * Routes: public model name -> backend, upstream id and pinned artifact, with
 * provenance and availability as the server computes them.
 */

import { useId, useState, type FormEvent } from 'react';
import { api, type Backend, type ModelArtifact, type ModelRoute, type RouteInput } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { MODEL_NAME } from '../../forms.ts';
import { shortDigest } from '../../format.ts';
import type { Resource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { ConfirmDialog } from '../../components/Dialog.tsx';
import { Digest } from '../../components/Digest.tsx';
import { Field, FormErrorList } from '../../components/Field.tsx';
import { IconPlus } from '../../components/Icons.tsx';
import { Notice, Panel, type NoticeMessage } from '../../components/Panel.tsx';
import { Async, EmptyState, InlineError } from '../../components/States.tsx';
import { StatusBadge } from '../../components/StatusBadge.tsx';

const ROUTE_FIELDS = ['model', 'backend_id', 'upstream_model', 'artifact_digest', 'require_verified'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

export function RoutesPanel({
  routes,
  backends,
  models,
  isAdmin,
  onChanged,
}: {
  routes: Resource<ModelRoute[]>;
  backends: readonly Backend[];
  models: readonly ModelArtifact[];
  isAdmin: boolean;
  onChanged: () => void;
}) {
  const role = useRole();
  const [adding, setAdding] = useState(false);
  const [notice, setNotice] = useState<NoticeMessage | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [toDelete, setToDelete] = useState<ModelRoute | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const toggle = async (route: ModelRoute): Promise<void> => {
    setBusyId(route.id);
    setActionError(null);
    setNotice(null);
    try {
      await api.updateRoute(route.id, { enabled: !route.enabled });
      setNotice({ text: `Route ${route.model} ${route.enabled ? 'disabled' : 'enabled'}.` });
      onChanged();
    } catch (err) {
      if (appliedDespiteBody(err)) onChanged();
      else setActionError(err);
    } finally {
      setBusyId(null);
    }
  };

  const confirmDelete = async (): Promise<void> => {
    if (!toDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteRoute(toDelete.id);
      setNotice({ text: `Route ${toDelete.model} deleted.`, focus: true });
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
      title="Routes"
      description="The model names apps can request through the gateway."
      actions={
        isAdmin ? (
          <button type="button" className="button" aria-expanded={adding} onClick={() => setAdding((a) => !a)}>
            <IconPlus />
            Add route
          </button>
        ) : null
      }
      flush
    >
      {adding ? (
        <RouteForm
          backends={backends}
          models={models}
          onCancel={() => setAdding(false)}
          onCreated={(name) => {
            setAdding(false);
            setNotice({ text: `Route ${name} added.` });
            onChanged();
          }}
        />
      ) : null}
      <Notice notice={notice} />
      {actionError ? (
        <div className="panel-inset">
          <InlineError error={actionError} prefix="The route was not changed." />
        </div>
      ) : null}
      <Async resource={routes} loadingLabel="Loading routes…">
        {(items) => (
          <RoutesTable
            routes={items}
            isAdmin={isAdmin}
            busyId={busyId}
            onToggle={(r) => void toggle(r)}
            onDelete={(r) => {
              setDeleteError(null);
              setToDelete(r);
            }}
          />
        )}
      </Async>
      <ConfirmDialog
        open={toDelete !== null}
        title={`Delete route ${toDelete?.model ?? ''}?`}
        confirmLabel="Delete route"
        busyLabel="Deleting…"
        danger
        busy={deleting}
        error={deleteError}
        onConfirm={() => void confirmDelete()}
        onCancel={() => setToDelete(null)}
      >
        <p>
          Apps requesting <code>{toDelete?.model}</code> get a model-not-found error from then on. The backend and the imported
          artifact are not affected.
        </p>
      </ConfirmDialog>
    </Panel>
  );
}

function RoutesTable({
  routes,
  isAdmin,
  busyId,
  onToggle,
  onDelete,
}: {
  routes: readonly ModelRoute[];
  isAdmin: boolean;
  busyId: number | null;
  onToggle: (route: ModelRoute) => void;
  onDelete: (route: ModelRoute) => void;
}) {
  if (routes.length === 0) {
    return (
      <EmptyState title="No routes.">
        {isAdmin ? 'Add a route' : 'An admin can add a route'} to expose an imported model, or on the host:{' '}
        <code>ferry route add MODEL --backend NAME --artifact DIGEST</code>.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Routes</caption>
        <thead>
          <tr>
            <th scope="col">Model</th>
            <th scope="col">Backend</th>
            <th scope="col">Upstream model</th>
            <th scope="col">Pinned artifact</th>
            <th scope="col">Provenance</th>
            <th scope="col">Availability</th>
            {isAdmin ? (
              <th scope="col" className="actions">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {routes.map((r) => {
            const busy = busyId === r.id;
            return (
              <tr key={r.id}>
                <td>
                  <code>{r.model}</code>
                </td>
                <td>{r.backend_name || <span className="mono">#{r.backend_id}</span>}</td>
                <td className="break">
                  <code>{r.upstream_model}</code>
                </td>
                <td>
                  {r.artifact_digest ? <Digest value={r.artifact_digest} label={`pinned digest of ${r.model}`} /> : <span className="tag">not pinned</span>}
                  <div className="cell-note">{r.require_verified ? 'requires verified provenance' : 'serves without verification'}</div>
                </td>
                <td>
                  <StatusBadge domain="provenance" value={r.provenance.state} />
                  {r.provenance.detail ? <div className="cell-note">{r.provenance.detail}</div> : null}
                  {r.provenance.state === 'mismatch' && r.provenance.served_digest ? (
                    <div className="cell-note">
                      serving <Digest value={r.provenance.served_digest} label="served digest" />
                    </div>
                  ) : null}
                </td>
                <td>
                  {r.enabled ? (
                    <StatusBadge domain="availability" value={r.available ? 'available' : 'unavailable'} />
                  ) : (
                    <StatusBadge domain="availability" value="disabled" />
                  )}
                  {!r.available && r.reason ? <div className="cell-note">{r.reason}</div> : null}
                </td>
                {isAdmin ? (
                  <td className="actions">
                    <div className="row">
                      <button
                        type="button"
                        className="button button--small"
                        aria-disabled={busy || undefined}
                        aria-label={`${r.enabled ? 'Disable' : 'Enable'} route ${r.model}`}
                        onClick={() => {
                          if (!busy) onToggle(r);
                        }}
                      >
                        {busy ? 'Saving…' : r.enabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        type="button"
                        className="button button--small button--ghost text-bad"
                        aria-label={`Delete route ${r.model}`}
                        onClick={() => onDelete(r)}
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

function RouteForm({
  backends,
  models,
  onCreated,
  onCancel,
}: {
  backends: readonly Backend[];
  models: readonly ModelArtifact[];
  onCreated: (model: string) => void;
  onCancel: () => void;
}) {
  const role = useRole();
  const [model, setModel] = useState('');
  const [backendId, setBackendId] = useState(backends[0] ? String(backends[0].id) : '');
  const [upstream, setUpstream] = useState('');
  const [digest, setDigest] = useState('');
  const [requireVerified, setRequireVerified] = useState(true);
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);
  const backend = backends.find((b) => String(b.id) === backendId);
  const offered = backend?.last_status?.models ?? [];
  const listId = useId();

  if (backends.length === 0) {
    return (
      <div className="form-panel">
        <p>
          Add a backend first: a route needs somewhere to send requests. <button type="button" className="link-button" onClick={onCancel}>Close</button>
        </p>
      </div>
    );
  }

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const name = model.trim();
    const fields: Record<string, string> = {};
    if (!name) fields['model'] = 'Enter the public model name apps will request.';
    else if (!MODEL_NAME.test(name)) fields['model'] = 'Use letters, digits, ".", "_", ":" or "-", starting with a letter or digit (at most 128).';
    if (!backendId) fields['backend_id'] = 'Choose a backend.';
    if (!upstream.trim()) fields['upstream_model'] = 'Enter the model id the backend expects.';
    if (Object.keys(fields).length) {
      setErrors({ fields, general: [] });
      return;
    }
    const input: RouteInput = {
      model: name,
      backend_id: Number(backendId),
      upstream_model: upstream.trim(),
      require_verified: requireVerified,
      ...(digest ? { artifact_digest: digest } : {}),
    };
    setBusy(true);
    setErrors(NO_ERRORS);
    try {
      await api.createRoute(input);
      onCreated(name);
    } catch (err) {
      if (appliedDespiteBody(err)) onCreated(name);
      else setErrors(formErrors(err, ROUTE_FIELDS, role));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form form-panel" onSubmit={(e) => void submit(e)} noValidate aria-label="Add route">
      <div className="form-grid">
        <Field label="Public model name" error={errors.fields['model']} hint="What apps put in the request's model field.">
          {(p) => (
            <input {...p} className="input input--mono" value={model} onChange={(e) => setModel(e.target.value)} autoComplete="off" spellCheck={false} />
          )}
        </Field>
        <Field label="Backend" error={errors.fields['backend_id']}>
          {(p) => (
            <select {...p} className="select" value={backendId} onChange={(e) => setBackendId(e.target.value)}>
              {backends.map((b) => (
                <option key={b.id} value={String(b.id)}>
                  {b.name} ({b.kind})
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field
          label="Upstream model id"
          error={errors.fields['upstream_model']}
          hint={
            offered.length
              ? 'Suggestions come from the backend’s last health check.'
              : 'The id the backend expects. For llama-server started with ferry runtime it is the --alias, usually the public name.'
          }
        >
          {(p) => (
            <>
              <input
                {...p}
                className="input input--mono"
                value={upstream}
                onChange={(e) => setUpstream(e.target.value)}
                list={offered.length ? listId : undefined}
                autoComplete="off"
                spellCheck={false}
              />
              {offered.length ? (
                <datalist id={listId}>
                  {offered.map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              ) : null}
            </>
          )}
        </Field>
        <Field
          label="Pinned artifact"
          error={errors.fields['artifact_digest']}
          hint="Pinning lets the gateway check that the backend serves exactly this imported file."
        >
          {(p) => (
            <select {...p} className="select" value={digest} onChange={(e) => setDigest(e.target.value)}>
              <option value="">Not pinned</option>
              {models.map((m) => (
                <option key={m.digest} value={m.digest}>
                  {(m.model_name ?? 'unnamed') + ' · ' + m.format + ' · ' + shortDigest(m.digest, 10, 4)}
                </option>
              ))}
            </select>
          )}
        </Field>
        <div className="field field--wide">
          <label className="checkbox">
            <input type="checkbox" checked={requireVerified} onChange={(e) => setRequireVerified(e.target.checked)} />
            Serve only when provenance is verified
          </label>
          <p className="field__hint">
            The backend must report that it serves the pinned file from the store (llama.cpp can). Without a pin such a route is
            never available.
          </p>
          {requireVerified && !digest ? (
            <p className="field__warning" role="status">
              No artifact is pinned, so this route would never be available.
            </p>
          ) : null}
          {errors.fields['require_verified'] ? <p className="field__error">{errors.fields['require_verified']}</p> : null}
        </div>
      </div>
      <FormErrorList messages={errors.general} />
      <div className="form-actions">
        <button type="submit" className="button button--primary" aria-disabled={busy || undefined}>
          {busy ? 'Adding…' : 'Add route'}
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
