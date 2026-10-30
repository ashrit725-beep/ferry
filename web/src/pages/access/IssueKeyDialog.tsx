/**
 * Issue an API key. The secret is in the response to this one request only
 * (spec section 6): it is held in this component's state, shown once, and
 * dropped when the dialog closes, because the dialog unmounts. It is never
 * logged, stored or put in a URL.
 */

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, type App, type IssuedKey } from '../../api.ts';
import { appliedDespiteBody, formErrors, type FormErrors } from '../../errors.ts';
import { optionalNumber } from '../../forms.ts';
import { useRole } from '../../session.tsx';
import { CopyButton } from '../../components/CopyButton.tsx';
import { Dialog } from '../../components/Dialog.tsx';
import { Field, FormErrorList } from '../../components/Field.tsx';
import { Callout, DefList } from '../../components/Panel.tsx';
import { Time } from '../../components/Time.tsx';

const NO_ERRORS: FormErrors = { fields: {}, general: [] };

export function IssueKeyDialog({ app, onClose }: { app: App; onClose: (issued: boolean) => void }) {
  const role = useRole();
  const [days, setDays] = useState('');
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [issued, setIssued] = useState<IssuedKey | null>(null);
  const [appliedUnknown, setAppliedUnknown] = useState(false);
  const keyRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (issued) keyRef.current?.focus();
  }, [issued]);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const parsed = optionalNumber(days, { integer: true, min: 1 });
    if (!parsed.ok) {
      setErrors({ fields: { expires_in_days: parsed.error }, general: [] });
      return;
    }
    setBusy(true);
    setErrors(NO_ERRORS);
    try {
      setIssued(await api.issueKey(app.id, parsed.value ?? null));
    } catch (err) {
      if (appliedDespiteBody(err)) setAppliedUnknown(true);
      else setErrors(formErrors(err, ['expires_in_days'], role));
    } finally {
      setBusy(false);
    }
  };

  const close = (): void => onClose(issued !== null || appliedUnknown);

  return (
    <Dialog
      open
      title={issued ? `API key for ${app.name}` : `Issue an API key for ${app.name}`}
      onClose={close}
      footer={
        issued ? (
          <button type="button" className="button button--primary" onClick={close}>
            Done
          </button>
        ) : undefined
      }
    >
      {issued ? (
        <>
          <Callout tone="warn" title="Copy the key now. It is shown only this once.">
            <p>Ferry stores only a hash of the secret. If the key is lost, issue a new one and revoke this one.</p>
          </Callout>
          <Field label="API key">
            {(p) => (
              <div className="secret">
                <input
                  {...p}
                  ref={keyRef}
                  className="input"
                  readOnly
                  value={issued.api_key}
                  onFocus={(e) => e.currentTarget.select()}
                  autoComplete="off"
                  spellCheck={false}
                />
                <CopyButton text={issued.api_key} label="Copy API key" withText />
              </div>
            )}
          </Field>
          <DefList
            items={[
              ['Key id', <code>{issued.key_id}</code>],
              ['Expires', issued.expires_at ? <Time value={issued.expires_at} exact future /> : 'never'],
              ['Send as', <code>Authorization: Bearer &lt;key&gt;</code>],
            ]}
          />
        </>
      ) : appliedUnknown ? (
        <Callout tone="warn" title="A key was probably issued, but the response could not be read.">
          <p>The secret cannot be shown again. Revoke any key you did not receive and issue a new one.</p>
        </Callout>
      ) : (
        <form className="form" onSubmit={(e) => void submit(e)} noValidate>
          <p className="muted">
            The app uses the key as a bearer token on <code>/v1</code> requests. What it may do is decided by the access policy,
            not by the key.
          </p>
          <Field
            label="Expires in (days)"
            optional
            error={errors.fields['expires_in_days']}
            hint="Leave empty to use the server's default. The expiry is shown with the key."
          >
            {(p) => (
              <input {...p} className="input" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} autoComplete="off" />
            )}
          </Field>
          <FormErrorList messages={errors.general} />
          <div className="form-actions">
            <button type="submit" className="button button--primary" aria-disabled={busy || undefined}>
              {busy ? 'Issuing…' : 'Issue key'}
            </button>
            <button type="button" className="button" onClick={close}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
