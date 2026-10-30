/**
 * An imported bundle: identity, signers, what the manifest declares, the
 * artifacts as stored, and the verification report recorded at import.
 */

import { api, type BundleArtifactRow, type BundleDetail, type ManifestArtifact } from '../api.ts';
import { DASH, formatBytes, formatInt } from '../format.ts';
import { useResource } from '../hooks.ts';
import { paths, toHash } from '../router.ts';
import { Digest, KeyId } from '../components/Digest.tsx';
import { JsonView } from '../components/JsonView.tsx';
import { DefList, PageHeader, Panel } from '../components/Panel.tsx';
import { ReportView } from '../components/ReportView.tsx';
import { Async } from '../components/States.tsx';
import { Time } from '../components/Time.tsx';

const CRUMBS = [{ label: 'Bundles', href: toHash(paths.bundles) }];

export function BundleDetailPage({ bundleId }: { bundleId: string }) {
  const bundle = useResource((s) => api.bundle(bundleId, s), [bundleId]);
  const b = bundle.data;
  return (
    <>
      <PageHeader
        breadcrumb={CRUMBS}
        title={b ? `${b.name} ${b.version}` : 'Imported bundle'}
        meta={b ? <>Imported <Time value={b.imported_at} /> by {b.imported_by}</> : <code className="break">{bundleId}</code>}
      />
      <Async resource={bundle} loadingLabel="Loading the bundle…" errorTitle="Could not load this bundle.">
        {(data) => <BundleBody bundle={data} />}
      </Async>
    </>
  );
}

interface ArtifactRow {
  path: string;
  digest: string | null;
  size: number | null;
  kind: string | null;
  format: string | null;
  model: ManifestArtifact['model'];
}

/** Stored rows are authoritative for digests; the manifest adds licence and upstream source. */
function artifactRows(bundle: BundleDetail): ArtifactRow[] {
  const declared = new Map((bundle.manifest?.artifacts ?? []).map((a) => [a.path, a]));
  const stored: readonly BundleArtifactRow[] = bundle.artifacts;
  if (stored.length > 0) {
    return stored.map((a) => {
      const m = declared.get(a.path) ?? declared.get(`artifacts/${a.path}`);
      return {
        path: a.path,
        digest: a.digest ?? m?.sha256 ?? null,
        size: a.size ?? m?.size ?? null,
        kind: a.kind ?? m?.kind ?? null,
        format: a.format ?? m?.format ?? null,
        model: m?.model ?? null,
      };
    });
  }
  return (bundle.manifest?.artifacts ?? []).map((a) => ({
    path: a.path,
    digest: a.sha256,
    size: a.size,
    kind: a.kind,
    format: a.format,
    model: a.model,
  }));
}

function BundleBody({ bundle }: { bundle: BundleDetail }) {
  const manifest = bundle.manifest;
  const requires = manifest?.requires ?? null;
  const rows = artifactRows(bundle);
  return (
    <div className="stack">
      <Panel title="Summary">
        <DefList
          wide
          items={[
            ['Bundle id', <Digest value={bundle.bundle_id} label="bundle id" full />],
            ['Name and version', <span>{bundle.name} <span className="mono">{bundle.version}</span></span>],
            ['Description', manifest?.bundle?.description || null],
            ['Created', manifest?.bundle?.created_at ? <Time value={manifest.bundle.created_at} exact /> : null],
            ['Imported', <Time value={bundle.imported_at} exact />],
            ['Imported by', bundle.imported_by],
            ['Source file', <code>{bundle.source_name}</code>],
            ['Artifacts', `${formatInt(bundle.artifact_count)}, ${formatBytes(bundle.total_bytes)} in total`],
            ['Requires Ferry', requires?.ferry_min_version ? <span className="mono">{requires.ferry_min_version} or later</span> : null],
            [
              'Runtime',
              requires?.runtime ? (
                <span>
                  {requires.runtime}
                  {requires.runtime_min_version ? ` ${requires.runtime_min_version} or later` : ''}
                </span>
              ) : null,
            ],
            ['Memory', requires?.min_memory_bytes ? `${formatBytes(requires.min_memory_bytes)} or more` : null],
            ['Manifest schema', manifest?.schema ? <code>{manifest.schema}</code> : null],
          ]}
        />
      </Panel>

      <Panel title="Signers" flush>
        {bundle.signers.length === 0 ? (
          <p className="panel-note">No signers were recorded for this bundle.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Signers whose signatures were accepted at import</caption>
              <thead>
                <tr>
                  <th scope="col">Signer</th>
                  <th scope="col">Key id</th>
                  <th scope="col">Roles</th>
                </tr>
              </thead>
              <tbody>
                {bundle.signers.map((s) => (
                  <tr key={s.key_id}>
                    <td>{s.name ?? <span className="subtle">unnamed</span>}</td>
                    <td className="nowrap">
                      <KeyId value={s.key_id} />
                    </td>
                    <td>
                      <span className="inline-list">
                        {s.roles.map((r) => (
                          <span key={r} className="tag">
                            {r}
                          </span>
                        ))}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Artifacts" flush>
        {rows.length === 0 ? (
          <p className="panel-note">No artifacts are recorded for this bundle.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <caption className="sr-only">Artifacts in this bundle</caption>
              <thead>
                <tr>
                  <th scope="col">Path</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Format</th>
                  <th scope="col" className="num">
                    Size
                  </th>
                  <th scope="col">SHA-256</th>
                  <th scope="col">Licence and upstream source</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.path}>
                    <td className="break">
                      <code>{a.path}</code>
                    </td>
                    <td>{a.kind ?? DASH}</td>
                    <td>
                      <code>{a.format ?? DASH}</code>
                    </td>
                    <td className="num" title={a.size !== null ? `${a.size} bytes` : undefined}>
                      {formatBytes(a.size)}
                    </td>
                    <td className="nowrap">
                      <Digest value={a.digest} label={`sha256 of ${a.path}`} />
                    </td>
                    <td>
                      {a.model ? (
                        <div className="stack-xs">
                          <span>
                            {a.model.name ? <code>{a.model.name}</code> : null}
                            {a.model.license ? <span className="tag">{a.model.license}</span> : null}
                          </span>
                          {a.model.source_uri ? <span className="cell-note break">{a.model.source_uri}</span> : null}
                          {a.model.source_revision ? (
                            <span className="cell-note">
                              revision <code>{a.model.source_revision}</code>
                            </span>
                          ) : null}
                        </div>
                      ) : (
                        <span className="subtle">{DASH}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Verification report at import">
        {bundle.report ? <ReportView report={bundle.report} /> : <p className="subtle">No report was stored with this bundle.</p>}
      </Panel>

      {bundle.manifest_raw !== null && bundle.manifest_raw !== undefined ? (
        <Panel title="manifest.json">
          <details className="disclosure">
            <summary>Show the manifest as imported</summary>
            <JsonView value={bundle.manifest_raw} copyLabel="Copy manifest JSON" />
          </details>
        </Panel>
      ) : null}
    </div>
  );
}
