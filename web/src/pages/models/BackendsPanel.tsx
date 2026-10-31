/**
 * Inference backends: health as last checked, what each one serves, and the
 * admin controls (check now, enable or disable, delete, add). A backend
 * reported down holds its red row until the operator acknowledges it, by
 * checking it or by refreshing the page.
 */

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { api, BACKEND_KINDS, type Backend, type BackendInput, type BackendKind } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { joinBaseUrl, optionalNumber, optionalText, SCHEMES, splitBaseUrl, type Scheme } from '../../forms.ts';
import { formatMs } from '../../format.ts';
import type { Resource } from '../../hooks.ts';
import { useRole } from '../../session.tsx';
import { Notice, type NoticeMessage } from '../../components/console/callout.tsx';
import { ConfirmDialog } from '../../components/console/confirm-dialog.tsx';
import { DataTable, type Column } from '../../components/console/data-table.tsx';
import { Digest, MonoId, TruncatedPath } from '../../components/console/digest.tsx';
import { FormActions, FormErrorList, FormGrid, SelectField, TextField } from '../../components/console/form-field.tsx';
import { Section } from '../../components/console/section.tsx';
import { Stamp } from '../../components/console/stamp.tsx';
import { EmptyState, InlineError, Spinner } from '../../components/console/states.tsx';
import { Time } from '../../components/console/time.tsx';
import { Button } from '../../components/ui/button.tsx';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '../../components/ui/sheet.tsx';
import { CellNote, healthWord, isDown, ResourceStatus, Tag } from './parts.tsx';

const BACKEND_FIELDS = ['name', 'kind', 'base_url', 'auth_token_file', 'timeout_s', 'max_concurrency'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

const KIND_LABELS: Record<BackendKind, string> = {
  llamacpp: 'llama.cpp (llama-server)',
  ollama: 'Ollama',
  openai: 'OpenAI-compatible (vLLM and others)',
};

/** Down first, then loading, then not checked, then up. */
const HEALTH_RANK: Record<string, number> = { bad: 0, warn: 1, neutral: 2, info: 3, ok: 4 };

export function BackendsPanel({
  backends,
  isAdmin,
  onChanged,
  acknowledged,
  onAcknowledge,
}: {
  backends: Resource<Backend[]>;
  isAdmin: boolean;
  onChanged: () => void;
  /** Backends whose current down state the operator has acknowledged. */
  acknowledged: ReadonlySet<number>;
  onAcknowledge: (ids: readonly number[]) => void;
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
        const state = result.status.state;
        onAcknowledge([backend.id]);
        const facts = [
          result.status.latency_ms !== null ? formatMs(result.status.latency_ms) : null,
          result.status.http_status !== null ? `HTTP ${result.status.http_status}` : null,
        ]
          .filter(Boolean)
          .join(' · ');
        const text = `Checked ${backend.name}: ${state}.`;
        if (state === 'down') toast.error(text, { description: result.status.error ?? (facts || undefined), duration: Infinity, closeButton: true });
        else if (state === 'up') toast.success(text, { description: facts || undefined });
        else toast(text, { description: facts || undefined });
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

  const columns: Column<Backend>[] = [
    {
      id: 'name',
      header: 'Backend',
      className: 'max-w-48 xl:max-w-64',
      sortValue: (b) => b.name,
      cell: (b) => (
        <>
          <MonoId value={b.name} className="font-medium text-bone" />
          <div className="flex flex-wrap gap-1 pt-0.5">
            <Tag mono>{b.kind}</Tag>
            {b.has_token ? <Tag>token file</Tag> : null}
            {b.enabled ? null : <Tag>disabled</Tag>}
          </div>
        </>
      ),
    },
    {
      id: 'url',
      header: 'Base URL and limits',
      cell: (b) => (
        <>
          <span className="font-mono whitespace-nowrap">{b.base_url}</span>
          <CellNote>
            {b.timeout_s} s timeout · {b.max_concurrency} concurrent
          </CellNote>
        </>
      ),
    },
    {
      id: 'state',
      header: 'State and last check',
      label: 'State',
      className: 'min-w-36',
      sortValue: (b) => HEALTH_RANK[healthWord(b).tone] ?? 2,
      cell: (b) => {
        const status = b.last_status;
        if (busy === `check:${b.id}`) {
          return (
            <Stamp state="pending" running land={false}>
              checking
            </Stamp>
          );
        }
        const h = healthWord(b);
        const checkedAt = status?.checked_at ?? b.last_checked_at;
        return (
          <>
            <Stamp state={h.state} land={false}>
              {h.word}
            </Stamp>
            {status?.error ? <CellNote className="text-bad">{status.error}</CellNote> : null}
            {checkedAt ? (
              <CellNote>
                <span className="whitespace-nowrap">
                  checked <Time value={checkedAt} />
                </span>
                {status && status.latency_ms !== null ? <span className="whitespace-nowrap tabular-nums"> · {formatMs(status.latency_ms)}</span> : null}
                {status && status.http_status !== null ? <span className="whitespace-nowrap tabular-nums"> · HTTP {status.http_status}</span> : null}
              </CellNote>
            ) : (
              <CellNote>never checked</CellNote>
            )}
            {status?.version ? (
              <CellNote className="whitespace-nowrap">
                version <MonoId value={status.version} />
              </CellNote>
            ) : null}
          </>
        );
      },
    },
    {
      id: 'serving',
      header: 'Serving',
      className: 'max-w-48 xl:max-w-56',
      cell: (b) => <Serving backend={b} />,
    },
  ];

  if (isAdmin) {
    columns.push({
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'right',
      nowrap: true,
      cell: (b) => {
        const checking = busy === `check:${b.id}`;
        const toggling = busy === `toggle:${b.id}`;
        return (
          <div className="flex items-center justify-end gap-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-disabled={busy !== null || undefined}
              aria-label={`Check ${b.name} now`}
              onClick={() => {
                if (busy === null) void act(b, 'check');
              }}
            >
              {checking ? <Spinner className="text-text-2" /> : null}
              {checking ? 'Checking…' : 'Check'}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-disabled={busy !== null || undefined}
              aria-label={`${b.enabled ? 'Disable' : 'Enable'} backend ${b.name}`}
              onClick={() => {
                if (busy === null) void act(b, 'toggle');
              }}
            >
              {toggling ? <Spinner className="text-text-2" /> : null}
              {toggling ? 'Saving…' : b.enabled ? 'Disable' : 'Enable'}
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-bad hover:bg-bad-subtle hover:text-bad"
              aria-label={`Delete backend ${b.name}`}
              onClick={() => {
                setDeleteError(null);
                setToDelete(b);
              }}
            >
              Delete
            </Button>
          </div>
        );
      },
    });
  }

  const items = backends.data;
  const unacknowledged = (items ?? []).filter((b) => isDown(b) && !acknowledged.has(b.id)).length;

  return (
    <Section
      title="Backends"
      description="Inference servers on loopback or private addresses. Health is checked in the background and on demand."
      attention={unacknowledged > 0}
      actions={
        isAdmin ? (
          <Button type="button" variant="outline" size="sm" aria-haspopup="dialog" aria-expanded={adding} onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" />
            Add backend
          </Button>
        ) : null
      }
      footer={
        unacknowledged > 0 ? (
          <span>
            <span className="font-mono tabular-nums text-bad">{unacknowledged}</span> {unacknowledged === 1 ? 'backend is' : 'backends are'} down and held in red
            until {isAdmin ? 'checked or ' : ''}the page is refreshed.
          </span>
        ) : undefined
      }
      flush
    >
      {notice || actionError ? (
        <div className="flex flex-col items-start gap-2 px-3 pt-3">
          <Notice notice={notice} />
          {actionError ? <InlineError error={actionError.error} prefix={`${actionError.name}:`} /> : null}
        </div>
      ) : null}
      <ResourceStatus resource={backends} loadingLabel="Loading backends…" />
      <div aria-busy={backends.refreshing || undefined}>
        <DataTable
          caption="Backends"
          columns={columns}
          rows={items}
          rowKey={(b) => String(b.id)}
          loading={backends.loading}
          error={backends.error}
          onRetry={backends.reload}
          rerank={(items?.length ?? 0) <= 50}
          skeletonRows={2}
          rowTone={(b) => (isDown(b) ? 'bad' : null)}
          held={(b) => !acknowledged.has(b.id)}
          rowProps={(b) => (b.enabled ? {} : { className: '[&>td]:text-text-2' })}
          empty={
            <EmptyState title="No backends configured.">
              {isAdmin ? 'Add a backend' : 'An admin can add a backend'} here, or on the host with{' '}
              <code className="font-mono">ferry backend add NAME --kind llamacpp --url URL</code>. For an imported GGUF model,{' '}
              <code className="font-mono">ferry runtime llamacpp MODEL</code> prints a llama-server command and registers the backend and route.
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
              <SheetTitle className="text-base font-medium text-bone">Add backend</SheetTitle>
              <SheetDescription className="text-xs text-text-3">Register an inference server the gateway can send requests to.</SheetDescription>
            </SheetHeader>
            <div className="px-4 py-4">
              {adding ? (
                <BackendForm
                  onCancel={() => setAdding(false)}
                  onCreated={(name) => {
                    setAdding(false);
                    setNotice(null);
                    toast.success(`Backend ${name} added.`, { description: 'Use Check to see its state.' });
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
        title={`Delete backend ${toDelete?.name ?? ''}?`}
        confirmLabel="Delete backend"
        busyLabel="Deleting…"
        danger
        busy={deleting}
        error={deleteError}
        onConfirm={() => void confirmDelete()}
        onCancel={() => setToDelete(null)}
      >
        <p>The server refuses while routes still use this backend; delete or move those routes first. The inference server itself is not touched.</p>
      </ConfirmDialog>
    </Section>
  );
}

function Serving({ backend }: { backend: Backend }) {
  const status = backend.last_status;
  if (!status) return <span className="text-text-2">unknown until checked</span>;
  if (status.served.length === 0 && status.models.length === 0) return <span className="text-text-2">nothing reported</span>;
  return (
    <div className="flex flex-col gap-1">
      {status.models.length ? (
        <div className="flex flex-wrap gap-1">
          {status.models.map((m) => (
            <Tag key={m} mono>
              {m}
            </Tag>
          ))}
        </div>
      ) : null}
      {status.served.map((f, i) => (
        <CellNote key={`${f.path ?? ''}-${i}`} className="flex flex-col items-start gap-0.5">
          {f.path ? <TruncatedPath value={f.path} label="served file path" tail={14} /> : <span>{f.model_id ?? 'file'}</span>}
          {f.digest ? <Digest value={f.digest} label="served file digest" /> : <span> · not a store file</span>}
        </CellNote>
      ))}
    </div>
  );
}

function BackendForm({ onCreated, onCancel }: { onCreated: (name: string) => void; onCancel: () => void }) {
  const role = useRole();
  const formRef = useRef<HTMLFormElement>(null);
  const [name, setName] = useState('');
  const [kind, setKind] = useState<BackendKind>('llamacpp');
  const [scheme, setScheme] = useState<Scheme>('http');
  const [address, setAddress] = useState('');
  const [tokenFile, setTokenFile] = useState('');
  const [timeout, setTimeoutText] = useState('');
  const [concurrency, setConcurrency] = useState('');
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (Object.keys(errors.fields).length === 0) return;
    formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
  }, [errors]);

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
    <form ref={formRef} className="flex flex-col gap-4" onSubmit={(e) => void submit(e)} noValidate aria-label="Add backend" aria-busy={busy || undefined}>
      <FormGrid>
        <TextField label="Name" error={errors.fields['name']} value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" spellCheck={false} name="name" />
        <SelectField label="Kind" error={errors.fields['kind']} value={kind} onChange={(e) => setKind(e.target.value as BackendKind)} name="kind">
          {BACKEND_KINDS.map((k) => (
            <option key={k} value={k}>
              {KIND_LABELS[k]}
            </option>
          ))}
        </SelectField>
        <SelectField label="Scheme" value={scheme} onChange={(e) => setScheme(e.target.value as Scheme)} name="scheme">
          {SCHEMES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Host and port"
          mono
          error={errors.fields['base_url']}
          hint="Must resolve to a loopback or private address unless allow_public_backends is set in ferry.toml. A pasted full URL is split automatically."
          value={address}
          onChange={(e) => onAddress(e.target.value)}
          placeholder="e.g. 127.0.0.1:8080"
          autoComplete="off"
          spellCheck={false}
          name="base_url"
        />
        <TextField
          label="Token file"
          optional
          wide
          mono
          error={errors.fields['auth_token_file']}
          hint="Absolute path on the server to a file whose first line is the backend's bearer token. Set from the console, it must be inside Ferry's secrets directory and not readable by group or others. The token is never shown."
          value={tokenFile}
          onChange={(e) => setTokenFile(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          name="auth_token_file"
        />
        <TextField
          label="Read timeout (seconds)"
          optional
          error={errors.fields['timeout_s']}
          inputMode="decimal"
          value={timeout}
          onChange={(e) => setTimeoutText(e.target.value)}
          autoComplete="off"
          name="timeout_s"
          controlClassName="tabular-nums"
        />
        <TextField
          label="Max concurrent requests"
          optional
          error={errors.fields['max_concurrency']}
          inputMode="numeric"
          value={concurrency}
          onChange={(e) => setConcurrency(e.target.value)}
          autoComplete="off"
          name="max_concurrency"
          controlClassName="tabular-nums"
        />
      </FormGrid>
      <FormErrorList messages={errors.general} />
      <FormActions>
        <Button type="submit" aria-disabled={busy || undefined}>
          {busy ? <Spinner className="text-on-amber" /> : null}
          {busy ? 'Adding…' : 'Add backend'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </FormActions>
    </form>
  );
}
