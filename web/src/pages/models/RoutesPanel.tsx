/**
 * Routes: public model name -> backend, upstream id and pinned artifact, with
 * provenance and availability as the server computes them. Admins add a
 * route in a side sheet, enable or disable it, and delete it after a
 * confirmation that names it.
 */

import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { api, type Backend, type ModelArtifact, type ModelRoute, type RouteInput } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { MODEL_NAME } from '../../forms.ts';
import { shortDigest } from '../../format.ts';
import type { Resource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { Callout, Notice, type NoticeMessage } from '../../components/console/callout.tsx';
import { ConfirmDialog } from '../../components/console/confirm-dialog.tsx';
import { DataTable, type Column } from '../../components/console/data-table.tsx';
import { Digest, MonoId } from '../../components/console/digest.tsx';
import { FormActions, FormErrorList, FormGrid, SelectField, TextField } from '../../components/console/form-field.tsx';
import { Section } from '../../components/console/section.tsx';
import { Stamp } from '../../components/console/stamp.tsx';
import { EmptyState, InlineError, Spinner } from '../../components/console/states.tsx';
import { Button } from '../../components/ui/button.tsx';
import { Checkbox } from '../../components/ui/checkbox.tsx';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '../../components/ui/sheet.tsx';
import { availabilityWord, CellNote, provenanceWord, ResourceStatus, Tag } from './parts.tsx';

const ROUTE_FIELDS = ['model', 'backend_id', 'upstream_model', 'artifact_digest', 'require_verified'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

/** Rows needing a human sort first: mismatch, then unverified or not pinned, then the rest. */
const PROVENANCE_RANK: Record<string, number> = { bad: 0, warn: 1, neutral: 2, info: 3, ok: 4 };
const AVAILABILITY_RANK: Record<string, number> = { unavailable: 0, disabled: 1, available: 2 };

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

  const columns: Column<ModelRoute>[] = [
    {
      id: 'model',
      header: 'Model',
      className: 'max-w-48 xl:max-w-64',
      sortValue: (r) => r.model,
      cell: (r) => (
        <>
          <MonoId value={r.model} className="text-bone" />
          {r.upstream_model !== r.model ? (
            <CellNote className="flex min-w-0 items-baseline gap-1 whitespace-nowrap">
              upstream <MonoId value={r.upstream_model} />
            </CellNote>
          ) : (
            <CellNote>same name upstream</CellNote>
          )}
        </>
      ),
    },
    {
      id: 'backend',
      header: 'Backend',
      className: 'max-w-48 xl:max-w-72',
      sortValue: (r) => r.backend_name || `#${r.backend_id}`,
      cell: (r) => (r.backend_name ? <MonoId value={r.backend_name} /> : <span className="font-mono">#{r.backend_id}</span>),
    },
    // The state column comes before the pinned artifact, so at widths where the
    // table scrolls sideways no state sits under the pinned actions.
    {
      id: 'state',
      header: 'Provenance and availability',
      label: 'State',
      className: 'min-w-36',
      sortValue: (r) => (PROVENANCE_RANK[provenanceWord(r).tone] ?? 2) * 10 + (AVAILABILITY_RANK[availabilityWord(r).word] ?? 1),
      cell: (r) => {
        const p = provenanceWord(r);
        const a = availabilityWord(r);
        return (
          <>
            <span className="flex flex-wrap items-center gap-x-3 gap-y-0.5">
              <Stamp state={p.state} land={false}>
                {p.word}
              </Stamp>
              <Stamp state={a.state} land={false}>
                {a.word}
              </Stamp>
            </span>
            {r.provenance.detail ? <CellNote>{r.provenance.detail}</CellNote> : null}
            {r.provenance.state === 'mismatch' && r.provenance.served_digest ? (
              <CellNote className="flex flex-wrap items-center gap-1">
                serving <Digest value={r.provenance.served_digest} label="served digest" />
              </CellNote>
            ) : null}
            {!r.available && r.reason ? <CellNote>{r.reason}</CellNote> : null}
          </>
        );
      },
    },
    {
      id: 'pinned',
      header: 'Pinned artifact',
      cell: (r) => (
        <>
          {r.artifact_digest ? <Digest value={r.artifact_digest} label={`pinned digest of ${r.model}`} /> : <Tag>not pinned</Tag>}
          <CellNote>{r.require_verified ? 'requires verified provenance' : 'serves without verification'}</CellNote>
        </>
      ),
    },
  ];

  if (isAdmin) {
    columns.push({
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'right',
      nowrap: true,
      cell: (r) => {
        const busy = busyId === r.id;
        return (
          <div className="flex items-center justify-end gap-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-disabled={busy || undefined}
              aria-label={`${r.enabled ? 'Disable' : 'Enable'} route ${r.model}`}
              onClick={() => {
                if (!busy) void toggle(r);
              }}
            >
              {busy ? <Spinner className="text-text-2" /> : null}
              {busy ? 'Saving…' : r.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-bad hover:bg-bad-subtle hover:text-bad"
              aria-label={`Delete route ${r.model}`}
              onClick={() => {
                setDeleteError(null);
                setToDelete(r);
              }}
            >
              Delete
            </Button>
          </div>
        );
      },
    });
  }

  const items = routes.data;

  return (
    <Section
      title="Routes"
      description="The model names apps can request through the gateway."
      actions={
        isAdmin ? (
          <Button type="button" variant="outline" size="sm" aria-haspopup="dialog" aria-expanded={adding} onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" />
            Add route
          </Button>
        ) : null
      }
      flush
    >
      {notice || actionError ? (
        <div className="flex flex-col items-start gap-2 px-3 pt-3">
          <Notice notice={notice} />
          {actionError ? <InlineError error={actionError} prefix="The route was not changed." /> : null}
        </div>
      ) : null}
      <ResourceStatus resource={routes} loadingLabel="Loading routes…" />
      <div aria-busy={routes.refreshing || undefined}>
        <DataTable
          caption="Routes"
          columns={columns}
          rows={items}
          rowKey={(r) => String(r.id)}
          loading={routes.loading}
          error={routes.error}
          onRetry={routes.reload}
          rerank={(items?.length ?? 0) <= 50}
          skeletonRows={3}
          rowTone={(r) => (r.provenance.state === 'mismatch' ? 'bad' : r.enabled && !r.available ? 'warn' : null)}
          rowProps={(r) => (r.enabled ? {} : { className: '[&>td]:text-text-2' })}
          empty={
            <EmptyState title="No routes.">
              {isAdmin ? 'Add a route' : 'An admin can add a route'} to expose an imported model, or on the host:{' '}
              <code className="font-mono">ferry route add MODEL --backend NAME --artifact DIGEST</code>.
            </EmptyState>
          }
        />
      </div>

      {isAdmin ? (
        <Sheet
          open={adding}
          onOpenChange={(open) => {
            if (!open) setAdding(false);
          }}
        >
          <SheetContent side="right" className="gap-0 overflow-y-auto bg-raised data-[side=right]:sm:max-w-lg">
            <SheetHeader className="border-b border-hairline px-4 py-3 pr-12">
              <SheetTitle className="text-base font-medium text-bone">Add route</SheetTitle>
              <SheetDescription className="text-xs text-text-3">
                Expose an imported model to apps under a public name, served by one backend.
              </SheetDescription>
            </SheetHeader>
            <div className="px-4 py-4">
              {adding ? (
                <RouteForm
                  backends={backends}
                  models={models}
                  onCancel={() => setAdding(false)}
                  onCreated={(name) => {
                    setAdding(false);
                    setNotice(null);
                    toast.success(`Route ${name} added.`, { description: 'Its provenance and availability appear in the table once the backend reports.' });
                    onChanged();
                  }}
                />
              ) : null}
            </div>
          </SheetContent>
        </Sheet>
      ) : null}

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
          Apps requesting <code className="font-mono text-xs">{toDelete?.model}</code> get a model-not-found error from then on. The backend and the
          imported artifact are not affected.
        </p>
      </ConfirmDialog>
    </Section>
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
  const formRef = useRef<HTMLFormElement>(null);
  const [model, setModel] = useState('');
  const [backendId, setBackendId] = useState(backends[0] ? String(backends[0].id) : '');
  const [upstream, setUpstream] = useState('');
  // Verified provenance is on by default, so the pin defaults to the first imported model file (a route without one would never be available).
  const [digest, setDigest] = useState(models[0]?.digest ?? '');
  const [requireVerified, setRequireVerified] = useState(true);
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);
  const backend = backends.find((b) => String(b.id) === backendId);
  const offered = backend?.last_status?.models ?? [];
  const listId = useId();
  const verifyHintId = useId();
  const verifyErrorId = useId();

  // Move focus to the first field the server or the checks below refused.
  useEffect(() => {
    if (Object.keys(errors.fields).length === 0) return;
    formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
  }, [errors]);

  if (backends.length === 0) {
    return (
      <div className="flex flex-col items-start gap-3">
        <Callout tone="warn">
          <p>Add a backend first: a route needs somewhere to send requests.</p>
        </Callout>
        <Button type="button" variant="outline" size="sm" onClick={onCancel}>
          Close
        </Button>
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

  const verifyError = errors.fields['require_verified'];

  return (
    <form ref={formRef} className="flex flex-col gap-4" onSubmit={(e) => void submit(e)} noValidate aria-label="Add route" aria-busy={busy || undefined}>
      <FormGrid className="sm:grid-cols-1">
        <TextField
          label="Public model name"
          mono
          error={errors.fields['model']}
          hint="What apps put in the request's model field."
          value={model}
          onChange={(e) => setModel(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          name="model"
        />
        <SelectField label="Backend" error={errors.fields['backend_id']} value={backendId} onChange={(e) => setBackendId(e.target.value)} name="backend_id">
          {backends.map((b) => (
            <option key={b.id} value={String(b.id)}>
              {b.name} ({b.kind})
            </option>
          ))}
        </SelectField>
        <TextField
          label="Upstream model id"
          mono
          error={errors.fields['upstream_model']}
          hint={
            offered.length
              ? 'Suggestions come from the backend’s last health check.'
              : 'The id the backend expects. For llama-server started with ferry runtime it is the --alias, usually the public name.'
          }
          value={upstream}
          onChange={(e) => setUpstream(e.target.value)}
          list={offered.length ? listId : undefined}
          autoComplete="off"
          spellCheck={false}
          name="upstream_model"
        />
        {offered.length ? (
          <datalist id={listId}>
            {offered.map((m) => (
              <option key={m} value={m} />
            ))}
          </datalist>
        ) : null}
        <SelectField
          label="Pinned artifact"
          error={errors.fields['artifact_digest']}
          hint="Pinning lets the gateway check that the backend serves exactly this imported file."
          value={digest}
          onChange={(e) => setDigest(e.target.value)}
          name="artifact_digest"
          controlClassName="[&_select]:font-mono [&_select]:text-xs"
        >
          <option value="">Not pinned</option>
          {models.map((m) => (
            <option key={m.digest} value={m.digest}>
              {(m.model_name ?? 'unnamed') + ' · ' + m.format + ' · ' + shortDigest(m.digest)}
            </option>
          ))}
        </SelectField>
        <div className="flex flex-col gap-1">
          <label className="flex min-h-8 cursor-pointer items-center gap-2 text-sm text-bone">
            <Checkbox
              checked={requireVerified}
              onCheckedChange={(checked) => setRequireVerified(checked)}
              aria-describedby={[verifyError ? verifyErrorId : null, verifyHintId].filter(Boolean).join(' ')}
              aria-invalid={verifyError ? true : undefined}
              className="border-line-control data-checked:border-bone data-checked:bg-bone data-checked:text-ground"
            />
            Serve only when provenance is verified
          </label>
          <p id={verifyHintId} className="text-xs text-text-3 text-pretty">
            The backend must report that it serves the pinned file from the store (llama.cpp can). Without a pin such a route is never available.
          </p>
          {requireVerified && !digest ? (
            <Callout tone="warn" role="status" className="mt-1 py-1.5 text-xs">
              <p>No artifact is pinned, so this route would never be available.</p>
            </Callout>
          ) : null}
          {verifyError ? (
            <p id={verifyErrorId} className="text-xs text-bad">
              {verifyError}
            </p>
          ) : null}
        </div>
      </FormGrid>
      <FormErrorList messages={errors.general} />
      <FormActions>
        <Button type="submit" aria-disabled={busy || undefined}>
          {busy ? <Spinner className="text-on-amber" /> : null}
          {busy ? 'Adding…' : 'Add route'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </FormActions>
    </form>
  );
}
