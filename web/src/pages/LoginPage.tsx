import { useRef, useState, type FormEvent } from 'react';
import { api, type User } from '../api.ts';
import { loginError } from '../errors.ts';
import { useDocumentTitle } from '../hooks.ts';
import { Field } from '../components/Field.tsx';
import { IconLogo } from '../components/Icons.tsx';
import { Callout } from '../components/Panel.tsx';

/**
 * Sign-in. The password is held only in this form's state and cleared after
 * every attempt; the session itself lives in an HttpOnly cookie the console
 * never sees. Fields go read-only (not disabled) while a request runs, so
 * keyboard focus is never dropped and can return to the password field.
 */
export function LoginPage({ notice, onSignedIn }: { notice: string | null; onSignedIn: (user: User) => void }) {
  useDocumentTitle('Sign in');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const name = username.trim();
    if (!name || !password) {
      setError('Enter your username and password.');
      (name ? passwordRef : usernameRef).current?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const user = await api.login(name, password);
      setPassword('');
      onSignedIn(user);
    } catch (err) {
      setPassword('');
      setBusy(false);
      setError(loginError(err));
      passwordRef.current?.focus();
    }
  };

  return (
    <div className="login">
      <main className="login__card" aria-labelledby="login-title">
        <p className="login__brand">
          <IconLogo />
          Ferry
        </p>
        <h1 id="login-title" className="login__title">
          Sign in to the console
        </h1>
        {notice ? (
          <Callout tone="info" role="status">
            {notice}
          </Callout>
        ) : null}
        <form className="form login__form" onSubmit={(e) => void submit(e)} noValidate>
          <Field label="Username">
            {(p) => (
              <input
                {...p}
                ref={usernameRef}
                className="input"
                name="username"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                readOnly={busy}
                autoFocus
              />
            )}
          </Field>
          <Field label="Password">
            {(p) => (
              <input
                {...p}
                ref={passwordRef}
                className="input"
                type="password"
                name="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                readOnly={busy}
              />
            )}
          </Field>
          {error ? (
            <Callout tone="bad" role="alert">
              {error}
            </Callout>
          ) : null}
          <button type="submit" className="button button--primary login__submit" aria-disabled={busy || undefined}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="login__foot">
          Console accounts are created on the server host with <code>ferry admin create-user</code>.
        </p>
      </main>
    </div>
  );
}
