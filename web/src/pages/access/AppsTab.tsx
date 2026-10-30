/**
 * Apps (the identities applications call the gateway with) and their keys.
 */

import { Fragment, useState, type FormEvent } from 'react';
import { api, ENVIRONMENTS, type ApiKeySummary, type App, type Environment } from '../../api.ts';
import { appliedDespiteBody, describeError, formErrors, type FormErrors } from '../../errors.ts';
import { APP_NAME, optionalText } from '../../forms.ts';
import { formatInt } from '../../format.ts';
import { useResource } from '../../hooks.ts';
import { useNow } from '../../now.tsx';
import { useRole, useSession } from '../../session.tsx';
import { keyStatus } from '../../status.ts';
import { ConfirmDialog } from '../../components/Dialog.tsx';
import { Field, FormErrorList } from '../../components/Field.tsx';
import { IconPlus } from '../../components/Icons.tsx';
import { Notice, Panel, type NoticeMessage } from '../../components/Panel.tsx';
import { Async, EmptyState, InlineError } from '../../components/States.tsx';
import { StatusBadge } from '../../components/StatusBadge.tsx';
import { Time } from '../../components/Time.tsx';
import { IssueKeyDialog } from './IssueKeyDialog.tsx';

const APP_FIELDS = ['name', 'environment', 'description'] as const;
const NO_ERRORS: FormErrors = { fields: {}, general: [] };

type Pending = { kind: 'revoke'; app: App; key: ApiKeySummary } | { kind: 'disable'; app: App };

export function AppsTab() {
  const { isAdmin } = useSession();
  const role = useRole();
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

  return (
    <div className="stack">
      <Panel
        title="Apps"
        description="Each app has an environment, so traffic from test apps can be told apart from pilot and production."
        actions={
          isAdmin ? (
            <button type="button" className="button" aria-expanded={creating} onClick={() => setCreating((c) => !c)}>
              <IconPlus />
              New app
            </button>
          ) : null
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
        <Notice notice={notice} />
        {actionError ? (
          <div className="panel-inset">
            <InlineError error={actionError} prefix="The app was not changed." />
          </div>
        ) : null}
        <Async resource={apps} loadingLabel="Loading apps…">
          {(items) => (
            <AppsTable
              apps={items}
              isAdmin={isAdmin}
              enabling={enabling}
              onIssue={setIssueFor}
              onRevoke={(app, key) => {
                setPendingError(null);
                setPending({ kind: 'revoke', app, key });
              }}
              onDisable={(app) => {
                setPendingError(null);
                setPending({ kind: 'disable', app });
              }}
              onEnable={(app) => void enable(app)}
            />
          )}
        </Async>
      </Panel>

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
        title={
          pending?.kind === 'revoke' ? `Revoke key ${pending.key.key_id}?` : pending ? `Disable app ${pending.app.name}?` : ''
        }
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
            Requests from <strong>{pending.app.name}</strong> with this key are rejected from now on. Revocation cannot be undone;
            issue a new key if the app still needs access.
          </p>
        ) : pending ? (
          <p>
            Every key of <strong>{pending.app.name}</strong> is rejected until the app is enabled again. The keys are not revoked.
          </p>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}

function AppsTable({
  apps,
  isAdmin,
  enabling,
  onIssue,
  onRevoke,
  onDisable,
  onEnable,
}: {
  apps: readonly App[];
  isAdmin: boolean;
  enabling: number | null;
  onIssue: (app: App) => void;
  onRevoke: (app: App, key: ApiKeySummary) => void;
  onDisable: (app: App) => void;
  onEnable: (app: App) => void;
}) {
  const now = useNow();
  if (apps.length === 0) {
    return (
      <EmptyState title="No apps yet.">
        An app is the identity an application uses to call the gateway.{' '}
        {isAdmin ? 'Create one, then issue it an API key.' : 'An admin can create one.'} On the host:{' '}
        <code>ferry app create NAME --environment test</code>.
      </EmptyState>
    );
  }
  const columns = isAdmin ? 6 : 5;
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Apps and their API keys</caption>
        <thead>
          <tr>
            <th scope="col">App</th>
            <th scope="col">Environment</th>
            <th scope="col">Status</th>
            <th scope="col" className="num">
              Active keys
            </th>
            <th scope="col">Created</th>
            {isAdmin ? (
              <th scope="col" className="actions">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody>
          {apps.map((app) => {
            const active = app.keys.filter((k) => keyStatus(k, now) === 'active').length;
            return (
              <Fragment key={app.id}>
                <tr className="has-subrow">
                  <td>
                    <code className="strong">{app.name}</code>
                    {app.description ? <div className="cell-note">{app.description}</div> : null}
                  </td>
                  <td>
                    <span className="tag">{app.environment}</span>
                  </td>
                  <td>
                    <StatusBadge domain="app" value={app.disabled ? 'disabled' : 'enabled'} />
                  </td>
                  <td className="num">
                    {formatInt(active)}
                    <span className="subtle"> of {formatInt(app.keys.length)}</span>
                  </td>
                  <td>
                    <Time value={app.created_at} />
                  </td>
                  {isAdmin ? (
                    <td className="actions">
                      <div className="row">
                        <button type="button" className="button button--small" onClick={() => onIssue(app)} aria-label={`Issue a key for ${app.name}`}>
                          Issue key
                        </button>
                        {app.disabled ? (
                          <button
                            type="button"
                            className="button button--small"
                            aria-disabled={enabling === app.id || undefined}
                            aria-label={`Enable ${app.name}`}
                            onClick={() => {
                              if (enabling === null) onEnable(app);
                            }}
                          >
                            {enabling === app.id ? 'Enabling…' : 'Enable'}
                          </button>
                        ) : (
                          <button type="button" className="button button--small button--ghost" onClick={() => onDisable(app)} aria-label={`Disable ${app.name}`}>
                            Disable
                          </button>
                        )}
                      </div>
                    </td>
                  ) : null}
                </tr>
                <tr className="subrow">
                  <td colSpan={columns}>
                    <KeysTable app={app} isAdmin={isAdmin} now={now} onRevoke={onRevoke} />
                  </td>
                </tr>
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function KeysTable({
  app,
  isAdmin,
  now,
  onRevoke,
}: {
  app: App;
  isAdmin: boolean;
  now: number;
  onRevoke: (app: App, key: ApiKeySummary) => void;
}) {
  if (app.keys.length === 0) {
    return <p className="cell-note">No API keys. {isAdmin ? 'Issue one so this app can call the gateway.' : ''}</p>;
  }
  return (
    <table className="table table--compact table--nested">
      <caption className="sr-only">API keys of {app.name}</caption>
      <thead>
        <tr>
          <th scope="col">Key id</th>
          <th scope="col">Status</th>
          <th scope="col">Created</th>
          <th scope="col">Expires</th>
          <th scope="col">Last used</th>
          {isAdmin ? (
            <th scope="col" className="actions">
              <span className="sr-only">Actions</span>
            </th>
          ) : null}
        </tr>
      </thead>
      <tbody>
        {app.keys.map((k) => {
          const status = keyStatus(k, now);
          return (
            <tr key={k.key_id}>
              <td>
                <code>{k.key_id}</code>
              </td>
              <td>
                <StatusBadge domain="key" value={status} />
                {k.revoked_at ? (
                  <span className="cell-note">
                    {' '}
                    <Time value={k.revoked_at} />
                  </span>
                ) : null}
              </td>
              <td>
                <Time value={k.created_at} />
              </td>
              <td>
                <Time value={k.expires_at} fallback="never" future />
              </td>
              <td>
                <Time value={k.last_used_at} fallback="never" />
              </td>
              {isAdmin ? (
                <td className="actions">
                  {status === 'revoked' ? null : (
                    <button
                      type="button"
                      className="button button--small button--ghost text-bad"
                      onClick={() => onRevoke(app, k)}
                      aria-label={`Revoke key ${k.key_id} of ${app.name}`}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              ) : null}
            </tr>
          );
        })}
      </tbody>
    </table>
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
    <form className="form form-panel" onSubmit={(e) => void submit(e)} noValidate aria-label="New app">
      <div className="form-grid">
        <Field label="Name" error={errors.fields['name']} hint="Policies refer to it as app:NAME.">
          {(p) => (
            <input {...p} className="input input--mono" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" spellCheck={false} />
          )}
        </Field>
        <Field label="Environment" error={errors.fields['environment']}>
          {(p) => (
            <select {...p} className="select" value={environment} onChange={(e) => setEnvironment(e.target.value as Environment)}>
              {ENVIRONMENTS.map((env) => (
                <option key={env} value={env}>
                  {env}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Description" optional wide error={errors.fields['description']}>
          {(p) => <input {...p} className="input" value={description} onChange={(e) => setDescription(e.target.value)} autoComplete="off" />}
        </Field>
      </div>
      <FormErrorList messages={errors.general} />
      <div className="form-actions">
        <button type="submit" className="button button--primary" aria-disabled={busy || undefined}>
          {busy ? 'Creating…' : 'Create app'}
        </button>
        <button type="button" className="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
