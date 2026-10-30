/**
 * Models: imported model artifacts, the routes that expose them through the
 * gateway, and the backends that serve them.
 */

import { api, type ModelArtifact } from '../api.ts';
import { modelFacts } from '../evidence.ts';
import { DASH, formatBytes } from '../format.ts';
import { useResource } from '../hooks.ts';
import { BUNDLE_ID, paths, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { Digest } from '../components/Digest.tsx';
import { PageHeader, Panel, RefreshButton } from '../components/Panel.tsx';
import { Async, EmptyState } from '../components/States.tsx';
import { Time } from '../components/Time.tsx';
import { BackendsPanel } from './models/BackendsPanel.tsx';
import { RoutesPanel } from './models/RoutesPanel.tsx';

export function ModelsPage() {
  const { isAdmin } = useSession();
  const models = useResource((s) => api.models(s), []);
  const routes = useResource((s) => api.routes(s), []);
  const backends = useResource((s) => api.backends(s), []);

  const refreshAll = (): void => {
    models.reload();
    routes.reload();
    backends.reload();
  };

  return (
    <>
      <PageHeader
        title="Models"
        description="A route exposes an imported model under a public name. It is available only when its backend is up and, if it requires it, the backend proves it serves the pinned file."
        actions={<RefreshButton onClick={refreshAll} busy={models.refreshing || routes.refreshing || backends.refreshing} />}
      />
      <div className="stack">
        <Panel title="Model artifacts" description="Model files imported from accepted bundles, stored by SHA-256." flush>
          <Async resource={models} loadingLabel="Loading model artifacts…">
            {(items) => <ArtifactsTable items={items} />}
          </Async>
        </Panel>
        <RoutesPanel
          routes={routes}
          backends={backends.data ?? []}
          models={models.data ?? []}
          isAdmin={isAdmin}
          onChanged={() => {
            routes.reload();
            models.reload();
          }}
        />
        <BackendsPanel
          backends={backends}
          isAdmin={isAdmin}
          onChanged={() => {
            backends.reload();
            routes.reload();
          }}
        />
      </div>
    </>
  );
}

function ArtifactsTable({ items }: { items: readonly ModelArtifact[] }) {
  if (items.length === 0) {
    return (
      <EmptyState title="No model artifacts imported.">
        Import a bundle that contains a model on the <a href={toHash(paths.bundles)}>Bundles</a> page.
      </EmptyState>
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Imported model artifacts</caption>
        <thead>
          <tr>
            <th scope="col">Model</th>
            <th scope="col">Format</th>
            <th scope="col" className="num">
              Size
            </th>
            <th scope="col">Licence</th>
            <th scope="col">Source bundle</th>
            <th scope="col">SHA-256</th>
            <th scope="col">Routes</th>
            <th scope="col">Imported</th>
          </tr>
        </thead>
        <tbody>
          {items.map((m) => {
            const facts = modelFacts(m.metadata);
            const bundleLabel = m.bundle_name ? `${m.bundle_name} ${m.bundle_version ?? ''}`.trim() : null;
            return (
              <tr key={m.digest}>
                <td>
                  <code>{m.model_name ?? 'unnamed'}</code>
                  {facts.length ? <div className="cell-note">{facts.join(' · ')}</div> : null}
                </td>
                <td>
                  <code>{m.format}</code>
                </td>
                <td className="num" title={`${m.size} bytes`}>
                  {formatBytes(m.size)}
                </td>
                <td>{m.license ? <span className="tag">{m.license}</span> : <span className="subtle">{DASH}</span>}</td>
                <td>
                  {BUNDLE_ID.test(m.first_bundle_id) ? (
                    <a href={toHash(paths.bundle(m.first_bundle_id))}>{bundleLabel ?? 'open bundle'}</a>
                  ) : (
                    (bundleLabel ?? <code>{m.first_bundle_id}</code>)
                  )}
                </td>
                <td className="nowrap">
                  <Digest value={m.digest} label={`sha256 of ${m.model_name ?? 'model'}`} />
                </td>
                <td>
                  {m.routes.length ? (
                    <span className="inline-list">
                      {m.routes.map((r) => (
                        <span key={r} className="tag tag--mono">
                          {r}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="subtle">no route</span>
                  )}
                </td>
                <td>
                  <Time value={m.imported_at} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
