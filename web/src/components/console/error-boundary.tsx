/**
 * PageErrorBoundary: catches a render error in one page so the shell (rail,
 * top bar, navigation) stays usable. The fallback carries the page's single
 * h1 and an ErrorState; it resets when the shell passes a new resetKey (a
 * route change) or when the operator chooses Try again.
 */

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ErrorState } from './states.tsx';

interface Props {
  resetKey: string;
  children: ReactNode;
}

interface State {
  error: unknown;
  failedKey: string | null;
}

export class PageErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, failedKey: null };

  static getDerivedStateFromError(error: unknown): Partial<State> {
    return { error: error ?? new Error('The page failed to render.') };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    if (state.error !== null && state.failedKey !== null && state.failedKey !== props.resetKey) {
      return { error: null, failedKey: null };
    }
    return null;
  }

  override componentDidCatch(_error: unknown, _info: ErrorInfo): void {
    this.setState({ failedKey: this.props.resetKey });
  }

  override render(): ReactNode {
    if (this.state.error === null) return this.props.children;
    return (
      <div>
        <h1 tabIndex={-1} className="mb-2 text-xl font-medium text-bone">
          This page could not be shown
        </h1>
        <p className="max-w-[72ch] text-sm text-text-2 text-pretty">
          The console hit an error while drawing this page. Nothing was changed on the server. Other pages still work from the navigation.
        </p>
        <ErrorState
          className="px-0"
          title="Rendering failed."
          error={this.state.error}
          onRetry={() => this.setState({ error: null, failedKey: null })}
        />
      </div>
    );
  }
}
