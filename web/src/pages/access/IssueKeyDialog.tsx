/**
 * Issue an API key. The secret is in the response to this one request only
 * (spec section 6): it is held in this component's state, shown once, and
 * dropped when the dialog closes, because the dialog unmounts. It is never
 * logged, stored or put in a URL.
 *
 * Once the key is shown the dialog is locked (Escape and the close button do
 * nothing) until the operator confirms they have stored it.
 */

import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { api, type App, type IssuedKey } from '../../api.ts';
import { appliedDespiteBody, formErrors, type FormErrors } from '../../errors.ts';
import { optionalNumber } from '../../forms.ts';
import { useRole } from '../../session.tsx';
import { Callout } from '../../components/console/callout.tsx';
import { Checklist, ChecklistLine } from '../../components/console/checklist.tsx';
import { CopyButton } from '../../components/console/copy-button.tsx';
import { Dialog } from '../../components/console/dialog.tsx';
import { Field, FormErrorList, TextField } from '../../components/console/form-field.tsx';
import { KeyValueList } from '../../components/console/key-value-list.tsx';
import { Spinner } from '../../components/console/states.tsx';
import { Time } from '../../components/console/time.tsx';
import { Button } from '../../components/ui/button.tsx';
import { Checkbox } from '../../components/ui/checkbox.tsx';
import { Input } from '../../components/ui/input.tsx';

const NO_ERRORS: FormErrors = { fields: {}, general: [] };

export function IssueKeyDialog({ app, onClose }: { app: App; onClose: (issued: boolean) => void }) {
  const role = useRole();
  const formId = useId();
  const storedHintId = useId();
  const [days, setDays] = useState('');
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<FormErrors>(NO_ERRORS);
  const [issued, setIssued] = useState<IssuedKey | null>(null);
  const [appliedUnknown, setAppliedUnknown] = useState(false);
  const [stored, setStored] = useState(false);
  const [storedNudge, setStoredNudge] = useState(false);
  const keyRef = useRef<HTMLInputElement>(null);
  const storedRef = useRef<HTMLSpanElement>(null);

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

  /** The one-time key stays on screen until the operator says it is stored. */
  const finish = (): void => {
    if (issued && !stored) {
      setStoredNudge(true);
      storedRef.current?.focus();
      return;
    }
    close();
  };

  const locked = issued !== null && !stored;

  return (
    <Dialog
      open
      locked={locked}
      title={issued ? `API key for ${app.name}` : `Issue an API key for ${app.name}`}
      description={
        issued || appliedUnknown ? undefined : (
          <>
            The app uses the key as a bearer token on <code className="font-mono text-xs">/v1</code> requests. What it may do is decided by
            the access policy, not by the key.
          </>
        )
      }
      onClose={issued ? finish : close}
      footer={
        issued ? (
          <Button type="button" onClick={finish} aria-disabled={!stored || undefined} aria-describedby={!stored ? storedHintId : undefined}>
            Done
          </Button>
        ) : appliedUnknown ? (
          <Button type="button" onClick={close}>
            Close
          </Button>
        ) : (
          <>
            <Button type="button" variant="outline" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" form={formId} aria-busy={busy || undefined} aria-disabled={busy || undefined}>
              {busy ? <Spinner className="text-current" /> : null}
              {busy ? 'Issuing…' : 'Issue key'}
            </Button>
          </>
        )
      }
    >
      {issued ? (
        <div className="flex flex-col gap-3">
          <Callout tone="warn" title="Copy the key now. It is shown only this once.">
            <p>Ferry stores only a hash of the secret. If the key is lost, issue a new one and revoke this one.</p>
          </Callout>
          <Field label="API key">
            {(p) => (
              <div className="flex items-center gap-2">
                <Input
                  {...p}
                  ref={keyRef}
                  readOnly
                  value={issued.api_key}
                  onFocus={(e) => e.currentTarget.select()}
                  autoComplete="off"
                  spellCheck={false}
                  className="h-8 min-w-0 flex-1 rounded-sm border-line-control bg-inset font-mono text-xs text-bone select-all"
                />
                <CopyButton text={issued.api_key} label="Copy API key" withText />
              </div>
            )}
          </Field>
          <KeyValueList
            items={[
              { term: 'Key id', value: issued.key_id, mono: true },
              ['Expires', issued.expires_at ? <Time value={issued.expires_at} exact future /> : 'never'],
              { term: 'Send as', value: 'Authorization: Bearer <key>', mono: true },
            ]}
          />
          <Checklist ariaLabel="Key handover" as="div">
            <ChecklistLine
              as="div"
              state={stored ? 'confirmed' : 'pending'}
              stamp={stored ? 'Stored' : 'Not stored'}
              label={
                <label className="flex min-h-10 cursor-pointer items-center gap-2">
                  <Checkbox
                    ref={storedRef}
                    checked={stored}
                    onCheckedChange={(checked) => {
                      setStored(checked);
                      if (checked) setStoredNudge(false);
                    }}
                    aria-describedby={storedHintId}
                    className="border-line-control data-checked:border-amber data-checked:bg-amber data-checked:text-on-amber"
                  />
                  I have stored this key
                </label>
              }
              detail={
                <span id={storedHintId} className={storedNudge ? 'text-amber' : undefined} role={storedNudge ? 'alert' : undefined}>
                  {storedNudge
                    ? 'Confirm that the key is stored before closing. It cannot be shown again.'
                    : 'The dialog stays open until you confirm. The key cannot be shown again.'}
                </span>
              }
            />
          </Checklist>
        </div>
      ) : appliedUnknown ? (
        <Callout tone="warn" title="A key was probably issued, but the response could not be read.">
          <p>The secret cannot be shown again. Revoke any key you did not receive and issue a new one.</p>
        </Callout>
      ) : (
        <form id={formId} className="flex flex-col gap-3" onSubmit={(e) => void submit(e)} noValidate aria-label={`Issue an API key for ${app.name}`}>
          <TextField
            label="Expires in (days)"
            optional
            error={errors.fields['expires_in_days']}
            hint="Leave empty to use the server's default. The expiry is shown with the key."
            inputMode="numeric"
            value={days}
            onChange={(e) => setDays(e.target.value)}
            autoComplete="off"
            mono
            controlClassName="w-32"
          />
          <FormErrorList messages={errors.general} />
        </form>
      )}
    </Dialog>
  );
}
