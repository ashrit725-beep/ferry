import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { api, type User } from '../api.ts';
import { loginError } from '../errors.ts';
import { useDocumentTitle } from '../hooks.ts';
import { IconLogo } from '../components/console/nav-icons.tsx';
import { Callout } from '@/components/console/callout.tsx';
import { Checklist, ChecklistLine } from '@/components/console/checklist.tsx';
import { TextField } from '@/components/console/form-field.tsx';
import { Spinner } from '@/components/console/states.tsx';
import { AnimatedBeam } from '@/components/fx/animated-beam.tsx';
import { DotField } from '@/components/fx/dot-field.tsx';
import { Button } from '@/components/ui/button.tsx';
import { cn } from '@/lib/utils';

/** True while the tab is visible; ambient effects stop while it is hidden. */
function useTabVisible(): boolean {
  const [visible, setVisible] = useState(() => document.visibilityState === 'visible');
  useEffect(() => {
    const onChange = (): void => setVisible(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', onChange);
    return () => document.removeEventListener('visibilitychange', onChange);
  }, []);
  return visible;
}

/**
 * The card used outside the Shell (sign-in, unreachable): the Ferry mark and
 * name over a hairline that one beam runs along, once, left to right. The
 * beam is the card's only motion; under reduced motion only the track shows.
 */
export function ConsoleCard({ titleId, title, children, beam = true, field = false }: { titleId: string; title: string; children: ReactNode; beam?: boolean; field?: boolean }) {
  const trackRef = useRef<HTMLDivElement>(null);
  const fromRef = useRef<HTMLSpanElement>(null);
  const toRef = useRef<HTMLSpanElement>(null);
  const visible = useTabVisible();
  return (
    <div className="relative flex min-h-svh items-center justify-center overflow-hidden bg-ground px-4 py-8">
      {field ? <DotField still={!visible} /> : null}
      <main aria-labelledby={titleId} className="relative w-full max-w-sm rounded-lg bg-panel ring-1 ring-hairline">
        <div className="flex items-center gap-2 px-4 pt-4 pb-3">
          <IconLogo className="size-5 shrink-0 text-amber" strokeWidth={1.75} />
          <span className="text-base font-medium text-bone">Ferry</span>
          <span className="text-xs text-text-3">console</span>
        </div>
        <div ref={trackRef} className="relative mx-4 h-px" aria-hidden="true">
          <span ref={fromRef} className="absolute top-0 left-0 size-px" />
          <span ref={toRef} className="absolute top-0 right-0 size-px" />
          {beam ? <AnimatedBeam containerRef={trackRef} fromRef={fromRef} toRef={toRef} pathWidth={1.5} duration={0.6} delay={0.1} /> : <span className="absolute inset-0 border-t border-hairline" />}
        </div>
        <div className="flex flex-col gap-4 px-4 pt-4 pb-4">
          <h1 id={titleId} tabIndex={-1} className="text-[1.75rem] leading-9 font-semibold tracking-[-0.01em] text-bone font-stretch-[112%] sm:text-[1.875rem]">
            {title}
          </h1>
          {children}
        </div>
      </main>
    </div>
  );
}

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
  const [missing, setMissing] = useState<{ username: boolean; password: boolean }>({ username: false, password: false });
  const [attempts, setAttempts] = useState(0);
  const [refused, setRefused] = useState(false);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const submit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (busy) return;
    const name = username.trim();
    if (!name || !password) {
      // The field messages say what is missing; no second copy in a callout.
      setMissing({ username: !name, password: !password });
      setError(null);
      (name ? passwordRef : usernameRef).current?.focus();
      return;
    }
    setMissing({ username: false, password: false });
    setBusy(true);
    setError(null);
    setRefused(false);
    setAttempts((n) => n + 1);
    try {
      const user = await api.login(name, password);
      setPassword('');
      onSignedIn(user);
    } catch (err) {
      setPassword('');
      setBusy(false);
      setRefused(true);
      setError(loginError(err));
      passwordRef.current?.focus();
    }
  };

  const sessionState = busy ? 'pending' : refused ? 'failed' : 'pending';
  const sessionStamp = busy ? 'Signing in' : refused ? 'Not signed in' : 'Awaiting sign-in';

  return (
    <ConsoleCard titleId="login-title" title="Sign in to the console" field>
      {notice ? (
        <Callout tone="info" role="status">
          {notice}
        </Callout>
      ) : null}
      <Checklist as="div" ariaLabel="Connection">
        <ChecklistLine as="div" label="Server" state="confirmed" stamp="Reached" value={<span className="truncate font-mono" title={window.location.host}>{window.location.host}</span>} />
        <ChecklistLine as="div" label="Session" state={sessionState} stamp={sessionStamp} pending={busy} drawKey={attempts} />
      </Checklist>
      <form className="flex flex-col gap-3" onSubmit={(e) => void submit(e)} noValidate aria-busy={busy || undefined}>
        <TextField
          label="Username"
          ref={usernameRef}
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          value={username}
          onChange={(e) => {
            setUsername(e.target.value);
            if (missing.username) setMissing((m) => ({ ...m, username: false }));
          }}
          readOnly={busy}
          error={missing.username ? 'Enter your username.' : null}
          autoFocus
        />
        <TextField
          label="Password"
          ref={passwordRef}
          type="password"
          name="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            if (missing.password) setMissing((m) => ({ ...m, password: false }));
          }}
          readOnly={busy}
          error={missing.password ? 'Enter your password.' : null}
        />
        {error ? (
          <Callout tone="bad" role="alert">
            {error}
          </Callout>
        ) : null}
        <Button type="submit" className={cn('w-full', busy && 'cursor-progress')} aria-disabled={busy || undefined} aria-busy={busy || undefined}>
          {busy ? <Spinner className="text-on-amber" /> : null}
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
      <p className="text-xs text-text-3 text-pretty">
        Console accounts are created on the server host with <code className="font-mono whitespace-nowrap text-bone">ferry admin create-user</code>.
      </p>
    </ConsoleCard>
  );
}
