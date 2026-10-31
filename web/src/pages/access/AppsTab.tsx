/**
 * Apps (the identities applications call the gateway with) and their keys,
 * in one table: each app row is followed by its key rows. Revoked keys print
 * in grey; secrets are shown once, in the issue dialog, never here.
 */

import { useState, type FormEvent } from 'react';
import { KeyRound, Plus } from 'lucide-react';
import { api, ENVIRONMENTS, type ApiKeySummary, type App, type Environment } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { APP_NAME, optionalText } from '../../forms.ts';
import { formatInt, plural } from '../../format.ts';
import { useResource } from '../../hooks.ts';
import { useNow } from '../../now.tsx';
import { useRole, useSession } from '../../session.tsx';
import { keyStatus, type KeyStatus } from '../../status.ts';
import { Notice, type NoticeMessage } from '../../components/console/callout.tsx';
import { ConfirmDialog } from '../../components/console/confirm-dialog.tsx';
import { DataTable, type Column } from '../../components/console/data-table.tsx';
import { MonoId } from '../../components/console/digest.tsx';
import { FormActions, FormErrorList, FormGrid, SelectField, TextField } from '../../components/console/form-field.tsx';
import { Section } from '../../components/console/section.tsx';
import { EmptyState, InlineError, Spinner } from '../../components/console/states.tsx';
import { StatusBadge } from '../../components/console/status-badge.tsx';
import { Time } from '../../components/console/time.tsx';
import { Button } from '../../components/ui/button.tsx';
import { IssueKeyDialog } from './IssueKeyDialog.tsx';

const APP_FIELDS = ['name', 'environment', 'description'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

type Pending = { kind: 'revoke'; app: App; key: ApiKeySummary } | { kind: 'disable'; app: App };

type Row =
  | { kind: 'app'; app: App; active: number }
  | { kind: 'key'; app: App; key: ApiKeySummary; status: KeyStatus }
  | { kind: 'nokeys'; app: App };

function rowsOf(apps: readonly App[], now: number): Row[] {
  const rows: Row[] = [];
  for (const app of apps) {
    const statuses = app.keys.map((key) => ({ key, status: keyStatus(key, now) }));
    rows.push({ kind: 'app', app, active: statuses.filter((s) => s.status === 'active').length });
    if (statuses.length === 0) rows.push({ kind: 'nokeys', app });
    for (const s of statuses) rows.push({ kind: 'key', app, key: s.key, status: s.status });
  }
  return rows;
}

function rowKey(row: Row): string {
  if (row.kind === 'key') return `key:${row.key.key_id}`;
  return `${row.kind}:${row.app.id}`;
}

export function AppsTab() {
  const { isAdmin } = useSession();
  const role = useRole();
  const now = useNow();
  const apps = useResource((s) => api.apps(s), []);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<NoticeMessage | null>(null);
  const [issueFor, setIssueFor] = useState<App | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [pendingBusy, setPendingBusy] = useState(false);
  const [pendingError, setPendingError] = useState<string | null>(null);
  const [enabling, setEnabling] = useState<number | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const confirmPending = async (): Promise<void> => {
    if (!pending) return;
    setPendingBusy(true);
    setPendingError(null);
    try {
      if (pending.kind === 'revoke') {
        await api.revokeKey(pending.key.key_id);
        setNotice({ text: `Key ${pending.key.key_id} of ${pending.app.name} revoked.`, focus: true });
      } else {
        await api.updateApp(pending.app.id, { disabled: true });
        setNotice({ text: `App ${pending.app.name} disabled.` });
      }
      setPending(null);
      apps.reload();
    } catch (err) {
      if (appliedDespiteBody(err)) {
        setPending(null);
        apps.reload();
      } else {
        setPendingError(describeError(err, role));
      }
    } finally {
      setPendingBusy(false);
    }
  };

  const enable = async (app: App): Promise<void> => {
    setEnabling(app.id);
    setActionError(null);
    try {
      await api.updateApp(app.id, { disabled: false });
      setNotice({ text: `App ${app.name} enabled.` });
      apps.reload();
    } catch (err) {
      if (appliedDespiteBody(err)) apps.reload();
      else setActionError(err);
    } finally {
      setEnabling(null);
    }
  };

  const columns: Column<Row>[] = [
    {
      id: 'name',
      header: 'App or key id',
      cell: (row) => {
        if (row.kind === 'app') {
          return (
            <div className="py-0.5">
              <span className="flex min-w-0 items-center gap-2">
                <MonoId value={row.app.name} className="font-medium text-bone" />
                <span className="inline-flex h-5 shrink-0 items-center rounded-sm border border-line-control/50 px-1.5 font-mono text-2xs text-text-2" title="Environment">
                  <span className="sr-only">environment </span>
                  {row.app.environment}
                </span>
              </span>
              {row.app.description ? <div className="text-xs text-text-3">{row.app.description}</div> : null}
            </div>
          );
        }
        if (row.kind === 'nokeys') {
          return (
            <span className="block pl-5 text-text-3">
              No API keys.{isAdmin ? ' Issue one so this app can call the gateway.' : ''}
            </span>
          );
        }
        return (
          <span className="flex items-center gap-1.5 pl-5">
            <KeyRound aria-hidden="true" className="size-3 shrink-0 text-text-3" />
            <code className="font-mono">{row.key.key_id}</code>
          </span>
        );
      },
    },
    {
      id: 'status',
      header: 'Status',
      nowrap: true,
      cell: (row) => {
        if (row.kind === 'app') {
          return (
            <>
              <StatusBadge domain="app" value={row.app.disabled ? 'disabled' : 'enabled'} />
              <div className="pt-0.5 text-2xs text-text-2 tabular-nums">
                {formatInt(row.active)} of {plural(row.app.keys.length, 'key')} active
              </div>
            </>
          );
        }
        if (row.kind === 'nokeys') return null;
        return (
          <span className="inline-flex items-center gap-1.5">
            <StatusBadge domain="key" value={row.status} />
            {row.key.revoked_at ? <Time value={row.key.revoked_at} className="text-text-3" /> : null}
          </span>
        );
      },
    },
    {
      id: 'dates',
      header: 'Created, expiry and last use',
      label: 'Dates',
      cell: (row) => {
        if (row.kind === 'app') {
          return (
            <span className="whitespace-nowrap text-text-2">
              created <Time value={row.app.created_at} />
            </span>
          );
        }
        if (row.kind === 'nokeys') return null;
        return (
          <span className="flex flex-wrap gap-x-3 text-text-2">
            <span className="whitespace-nowrap">
              created <Time value={row.key.created_at} />
            </span>
            <span className="whitespace-nowrap">
              expires <Time value={row.key.expires_at} fallback="never" future />
            </span>
            <span className="whitespace-nowrap">
              used <Time value={row.key.last_used_at} fallback="never" />
            </span>
          </span>
        );
      },
    },
  ];

  if (isAdmin) {
    columns.push({
      id: 'actions',
      header: 'Actions',
      srOnlyHeader: true,
      align: 'right',
      nowrap: true,
      cell: (row) => {
        if (row.kind === 'app') {
          const app = row.app;
          return (
            <span className="inline-flex items-center justify-end gap-1.5">
              <Button type="button" variant="outline" size="sm" onClick={() => setIssueFor(app)} aria-label={`Issue a key for ${app.name}`}>
                Issue key
              </Button>
              {app.disabled ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-busy={enabling === app.id || undefined}
                  aria-disabled={enabling === app.id || undefined}
                  aria-label={`Enable ${app.name}`}
                  onClick={() => {
                    if (enabling === null) void enable(app);
                  }}
                >
                  {enabling === app.id ? <Spinner className="text-current" /> : null}
                  {enabling === app.id ? 'Enabling…' : 'Enable'}
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Disable ${app.name}`}
                  onClick={() => {
                    setPendingError(null);
                    setPending({ kind: 'disable', app });
                  }}
                >
                  Disable
                </Button>
              )}
            </span>
          );
        }
        if (row.kind === 'key' && row.status !== 'revoked') {
          const { app, key } = row;
          return (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="text-bad hover:bg-bad-subtle hover:text-bad"
              aria-label={`Revoke key ${key.key_id} of ${app.name}`}
              onClick={() => {
                setPendingError(null);
                setPending({ kind: 'revoke', app, key });
              }}
            >
              Revoke
            </Button>
          );
        }
        return null;
      },
    });
  }

  const items = apps.data;
  const summary = items ? `${plural(items.length, 'app')} · ${plural(items.reduce((n, a) => n + a.keys.length, 0), 'key')}` : null;

  return (
    <div className="flex flex-col gap-4">
      <Section
        title="Apps"
        description="Each app has an environment, so traffic from test apps can be told apart from pilot and production."
        actions={
          <>
            {apps.refreshing ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-text-3" role="status">
                <Spinner />
                Refreshing…
              </span>
            ) : summary ? (
              <span className="text-2xs text-text-3 tabular-nums">{summary}</span>
            ) : null}
            {isAdmin ? (
              <Button type="button" variant="outline" size="sm" aria-expanded={creating} onClick={() => setCreating((c) => !c)}>
                <Plus aria-hidden="true" />
                New app
              </Button>
            ) : null}
          </>
        }
        flush
      >
        {creating ? (
          <CreateAppForm
            onCancel={() => setCreating(false)}
            onCreated={(name) => {
              setCreating(false);
              setNotice({ text: `App ${name} created. Issue it a key so it can call the gateway.` });
              apps.reload();
            }}
          />
        ) : null}
        {notice || actionError || (items && apps.error) ? (
          <div className="flex flex-col items-start gap-2 border-b border-hairline px-3 py-2">
            <Notice notice={notice} />
            {actionError ? <InlineError error={actionError} prefix="The app was not changed." /> : null}
            {items && apps.error ? <InlineError error={apps.error} prefix="Could not refresh; showing the last data loaded." onRetry={apps.reload} /> : null}
          </div>
        ) : null}
        <div aria-busy={apps.loading || apps.refreshing || undefined}>
          <DataTable
            caption="Apps and their API keys"
            columns={columns}
            rows={items ? rowsOf(items, now) : null}
            rowKey={rowKey}
            loading={apps.loading}
            error={apps.error}
            onRetry={apps.reload}
            skeletonRows={4}
            rowProps={(row) => ({
              className:
                row.kind === 'app'
                  ? 'bg-inset/50 border-t border-hairline first:border-t-0 sm:[&>td[data-pin]]:bg-[color-mix(in_srgb,var(--inset)_50%,var(--panel))]'
                  : row.kind === 'key' && row.status === 'revoked'
                    ? '[&>td]:text-text-3 [&_code]:text-text-3'
                    : undefined,
            })}
            empty={
              <EmptyState title="No apps yet.">
                An app is the identity an application uses to call the gateway.{' '}
                {isAdmin ? 'Create one, then issue it an API key.' : 'An admin can create one.'} On the host:{' '}
                <code className="font-mono text-xs">ferry app create NAME --environment test</code>.
              </EmptyState>
            }
          />
        </div>
      </Section>

      {issueFor ? (
        <IssueKeyDialog
          key={issueFor.id}
          app={issueFor}
          onClose={(issued) => {
            setIssueFor(null);
            if (issued) apps.reload();
          }}
        />
      ) : null}

      <ConfirmDialog
        open={pending !== null}
        title={pending?.kind === 'revoke' ? `Revoke key ${pending.key.key_id}?` : pending ? `Disable app ${pending.app.name}?` : ''}
        confirmLabel={pending?.kind === 'revoke' ? 'Revoke key' : 'Disable app'}
        busyLabel={pending?.kind === 'revoke' ? 'Revoking…' : 'Disabling…'}
        danger
        busy={pendingBusy}
        error={pendingError}
        onConfirm={() => void confirmPending()}
        onCancel={() => setPending(null)}
      >
        {pending?.kind === 'revoke' ? (
          <p>
            Requests from <strong className="font-medium">{pending.app.name}</strong> with this key are rejected from now on. Revocation
            cannot be undone; issue a new key if the app still needs access.
          </p>
        ) : pending ? (
          <p>
            Every key of <strong className="font-medium">{pending.app.name}</strong> is rejected until the app is enabled again. The keys are
            not revoked.
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}

function CreateAppForm({ onCreated, onCancel }: { onCreated: (name: string) => void; onCancel: () => void }) {
  const role = useRole();
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState<Environment>('test');
  const [description, setDescription] = useState('');
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const n = name.trim();
    if (!n || !APP_NAME.test(n)) {
      setErrors({
        fields: { name: n ? 'Use 1-64 lowercase letters, digits, "-" or "_", starting with a letter or digit.' : 'Enter a name.' },
        general: [],
      });
      return;
    }
    const desc = optionalText(description);
    setBusy(true);
    setErrors(NO_ERRORS);
    try {
      await api.createApp({ name: n, environment, ...(desc ? { description: desc } : {}) });
      onCreated(n);
    } catch (err) {
      if (appliedDespiteBody(err)) onCreated(n);
      else setErrors(formErrors(err, APP_FIELDS, role));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="flex flex-col gap-3 border-b border-hairline bg-inset/40 px-3 py-3" onSubmit={(e) => void submit(e)} noValidate aria-label="New app">
      <FormGrid>
        <TextField
          // Opened by the New app button: focus goes where the work is.
          autoFocus
          label="Name"
          mono
          error={errors.fields['name']}
          hint="Policies refer to it as app:NAME."
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
        <SelectField label="Environment" error={errors.fields['environment']} value={environment} onChange={(e) => setEnvironment(e.target.value as Environment)}>
          {ENVIRONMENTS.map((env) => (
            <option key={env} value={env}>
              {env}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Description"
          optional
          wide
          error={errors.fields['description']}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          autoComplete="off"
        />
      </FormGrid>
      <FormErrorList messages={errors.general} />
      <FormActions>
        <Button type="submit" aria-busy={busy || undefined} aria-disabled={busy || undefined}>
          {busy ? <Spinner className="text-current" /> : null}
          {busy ? 'Creating…' : 'Create app'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
      </FormActions>
    </form>
  );
}
