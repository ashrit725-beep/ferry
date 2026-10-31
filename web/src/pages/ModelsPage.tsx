/**
 * Models: imported model artifacts, the routes that expose them through the
 * gateway, and the backends that serve them, with the route map drawing all
 * three as lines. Data loads on mount, on Refresh and after a change; a
 * refresh also acknowledges the backends currently reported down.
 */

import { useEffect, useState } from 'react';
import { api, type ModelArtifact } from '../api.ts';
import { modelFacts } from '../evidence.ts';
import { formatBytes } from '../format.ts';
import { useResource } from '../hooks.ts';
import { BUNDLE_ID, paths, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { RefreshButton } from '../components/console/callout.tsx';
import { DataTable, type Column } from '../components/console/data-table.tsx';
import { Digest, MonoId } from '../components/console/digest.tsx';
import { PageHeader } from '../components/console/page-header.tsx';
import { Section } from '../components/console/section.tsx';
import { EmptyState } from '../components/console/states.tsx';
import { Time } from '../components/console/time.tsx';
import { BackendsPanel } from './models/BackendsPanel.tsx';
import { CellNote, isDown, ResourceStatus, Tag } from './models/parts.tsx';
import { RouteMap } from './models/RouteMap.tsx';
import { RoutesPanel } from './models/RoutesPanel.tsx';

const NO_IDS: ReadonlySet<number> = new Set();

export function ModelsPage() {
  const { isAdmin } = useSession();
  const models = useResource((s) => api.models(s), []);
  const routes = useResource((s) => api.routes(s), []);
  const backends = useResource((s) => api.backends(s), []);
  const [acknowledged, setAcknowledged] = useState<ReadonlySet<number>>(NO_IDS);

  // A backend that recovers forgets its acknowledgement, so a later failure holds red again.
  const backendList = backends.data;
  useEffect(() => {
    if (!backendList) return;
    setAcknowledged((prev) => {
      const still = [...prev].filter((id) => backendList.some((b) => b.id === id && isDown(b)));
      return still.length === prev.size ? prev : new Set(still);
    });
  }, [backendList]);

  const acknowledge = (ids: readonly number[]): void => {
    if (ids.length === 0) return;
    setAcknowledged((prev) => new Set([...prev, ...ids]));
  };

  const refreshAll = (): void => {
    acknowledge((backends.data ?? []).filter(isDown).map((b) => b.id));
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
      <div className="flex flex-col gap-4">
        <RouteMap routes={routes} backends={backends.data ?? []} models={models.data ?? []} />
        <Section title="Model artifacts" description="Model files imported from accepted bundles, stored by SHA-256." flush>
          <ResourceStatus resource={models} loadingLabel="Loading model artifacts…" />
          <div aria-busy={models.refreshing || undefined}>
            <DataTable
              caption="Imported model artifacts"
              columns={ARTIFACT_COLUMNS}
              rows={models.data}
              rowKey={(m) => m.digest}
              loading={models.loading}
              error={models.error}
              onRetry={models.reload}
              skeletonRows={2}
              rowProps={(m) => (m.routes.length ? {} : { className: '[&>td]:text-text-2' })}
              empty={
                <EmptyState title="No model artifacts imported.">
                  Import a bundle that contains a model on the{' '}
                  <a href={toHash(paths.bundles)} className="rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone">
                    Bundles
                  </a>{' '}
                  page.
                </EmptyState>
              }
            />
          </div>
        </Section>
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
          acknowledged={acknowledged}
          onAcknowledge={acknowledge}
          onChanged={() => {
            backends.reload();
            routes.reload();
          }}
        />
      </div>
    </>
  );
}

const ARTIFACT_COLUMNS: Column<ModelArtifact>[] = [
  {
    id: 'model',
    header: 'Model',
    className: 'max-w-56 xl:max-w-72',
    sortValue: (m) => m.model_name ?? '',
    cell: (m) => {
      const facts = [m.format, ...(m.license ? [`licence ${m.license}`] : []), ...modelFacts(m.metadata)];
      return (
        <>
          {m.model_name ? <MonoId value={m.model_name} className="text-bone" /> : <span className="text-text-2">unnamed</span>}
          <CellNote className="tabular-nums">{facts.join(' · ')}</CellNote>
        </>
      );
    },
  },
  {
    id: 'size',
    header: 'Size',
    align: 'right',
    nowrap: true,
    sortValue: (m) => m.size,
    cell: (m) => <span title={`${m.size} bytes`}>{formatBytes(m.size)}</span>,
  },
  {
    id: 'bundle',
    header: 'Source bundle',
    className: 'max-w-56 xl:max-w-72',
    sortValue: (m) => m.imported_at,
    cell: (m) => {
      const bundleLabel = m.bundle_name ? `${m.bundle_name} ${m.bundle_version ?? ''}`.trim() : null;
      return (
        <>
          {BUNDLE_ID.test(m.first_bundle_id) ? (
            <a
              href={toHash(paths.bundle(m.first_bundle_id))}
              className="inline-flex max-w-full rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone"
            >
              {bundleLabel ? <MonoId value={bundleLabel} /> : 'open bundle'}
            </a>
          ) : (
            <MonoId value={bundleLabel ?? m.first_bundle_id} />
          )}
          <CellNote className="whitespace-nowrap">
            imported <Time value={m.imported_at} />
          </CellNote>
        </>
      );
    },
  },
  {
    id: 'digest',
    header: 'SHA-256',
    nowrap: true,
    cell: (m) => <Digest value={m.digest} label={`sha256 of ${m.model_name ?? 'model'}`} />,
  },
  {
    id: 'routes',
    header: 'Routes',
    cell: (m) =>
      m.routes.length ? (
        <span className="flex flex-wrap gap-1">
          {m.routes.map((r) => (
            <Tag key={r} mono>
              {r}
            </Tag>
          ))}
        </span>
      ) : (
        <span className="text-text-2">no route</span>
      ),
  },
];
