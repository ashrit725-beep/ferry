/**
 * An imported bundle: identity beside the two signers of the two-person rule,
 * the checks recorded at import as a checklist, the artifacts as stored, and
 * what the report adds (verdict, details, policy) with the full report as
 * recorded behind a disclosure.
 */

import { ChevronDown } from 'lucide-react';
import { api, type BundleArtifactRow, type BundleDetail, type ManifestArtifact, type ReportSignature, type Signer } from '../api.ts';
import { DASH, formatBytes, formatInt } from '../format.ts';
import { useResource } from '../hooks.ts';
import { paths, toHash } from '../router.ts';
import { Checklist, ChecklistLine } from '@/components/console/checklist.tsx';
import { DataTable, type Column } from '@/components/console/data-table.tsx';
import { Digest, KeyId, MonoId, PathText } from '@/components/console/digest.tsx';
import { JsonView } from '@/components/console/json-view.tsx';
import { KeyValueList } from '@/components/console/key-value-list.tsx';
import { PageHeader } from '@/components/console/page-header.tsx';
import { ReportDetails, ReportVerdict, ReportView } from '@/components/console/report-view.tsx';
import { Section } from '@/components/console/section.tsx';
import { Async, PanelSkeleton } from '@/components/console/states.tsx';
import { StatusBadge } from '@/components/console/status-badge.tsx';
import { Time } from '@/components/console/time.tsx';
import { CheckChecklist } from './bundles/checks.tsx';

const CRUMBS = [{ label: 'Bundles', href: toHash(paths.bundles) }];

/** The roles of the two-person rule, in signing order. */
const ROLES = ['publisher', 'reviewer'] as const;
type Role = (typeof ROLES)[number];

export function BundleDetailPage({ bundleId }: { bundleId: string }) {
  const bundle = useResource((s) => api.bundle(bundleId, s), [bundleId]);
  const b = bundle.data;
  return (
    <>
      <PageHeader
        breadcrumb={CRUMBS}
        title={b ? `${b.name} ${b.version}` : 'Imported bundle'}
        meta={
          <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
            {b ? (
              <span>
                Imported <Time value={b.imported_at} /> by {b.imported_by}
              </span>
            ) : null}
            <Digest value={b?.bundle_id ?? bundleId} label="bundle id" />
          </span>
        }
      />
      <Async
        resource={bundle}
        loadingLabel="Loading the bundle…"
        errorTitle="Could not load this bundle."
        skeleton={
          <div className="flex flex-col gap-4">
            <p role="status" className="sr-only">
              Loading the bundle…
            </p>
            <div className="grid gap-4 xl:grid-cols-2">
              <div className="rounded-lg bg-panel ring-1 ring-hairline">
                <PanelSkeleton lines={4} />
              </div>
              <div className="rounded-lg bg-panel ring-1 ring-hairline">
                <PanelSkeleton lines={4} />
              </div>
            </div>
            <div className="rounded-lg bg-panel ring-1 ring-hairline">
              <PanelSkeleton lines={6} />
            </div>
          </div>
        }
      >
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

function RoleTags({ roles }: { roles: readonly string[] }) {
  if (roles.length === 0) return <span className="text-text-3">{DASH}</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {roles.map((r) => (
        <span key={r} className="rounded-sm border border-hairline px-1 text-2xs text-text-2">
          {r}
        </span>
      ))}
    </span>
  );
}

const ARTIFACT_COLUMNS: ReadonlyArray<Column<ArtifactRow>> = [
  { id: 'path', header: 'Path', mono: true, sortValue: (a) => a.path, cell: (a) => <PathText value={a.path} whole /> },
  { id: 'kind', header: 'Kind', nowrap: true, sortValue: (a) => a.kind, cell: (a) => a.kind ?? <span className="text-text-3">{DASH}</span> },
  { id: 'format', header: 'Format', nowrap: true, mono: true, cell: (a) => a.format ?? <span className="text-text-3">{DASH}</span> },
  {
    id: 'size',
    header: 'Size',
    align: 'right',
    nowrap: true,
    sortValue: (a) => a.size,
    cell: (a) => <span title={a.size !== null ? `${a.size} bytes` : undefined}>{formatBytes(a.size)}</span>,
  },
  { id: 'sha', header: 'SHA-256', nowrap: true, cell: (a) => <Digest value={a.digest} label={`sha256 of ${a.path}`} /> },
  {
    id: 'source',
    header: 'Licence and upstream source',
    cell: (a) =>
      a.model ? (
        <div className="flex flex-col gap-0.5">
          <span className="inline-flex flex-wrap items-center gap-1">
            {a.model.name ? <MonoId value={a.model.name} /> : null}
            {a.model.license ? <span className="rounded-sm border border-hairline px-1 text-2xs text-text-2">{a.model.license}</span> : null}
          </span>
          {a.model.source_uri ? <span className="font-mono text-2xs text-text-3 [overflow-wrap:anywhere]">{a.model.source_uri}</span> : null}
          {a.model.source_revision ? (
            <span className="text-2xs text-text-3">
              revision <code className="font-mono">{a.model.source_revision}</code>
            </span>
          ) : null}
        </div>
      ) : (
        <span className="text-text-3">{DASH}</span>
      ),
  },
];

const OTHER_SIGNER_COLUMNS: ReadonlyArray<Column<Signer>> = [
  { id: 'signer', header: 'Signer', cell: (s) => s.name ?? <span className="text-text-3">unnamed</span> },
  { id: 'key', header: 'Key id', nowrap: true, cell: (s) => <KeyId value={s.key_id} /> },
  { id: 'roles', header: 'Roles', cell: (s) => <RoleTags roles={s.roles} /> },
];

/** One side of the two-person rule: who signed in this role, or the open slot. */
function SignerBlock({ role, signer, signature }: { role: Role; signer: Signer | undefined; signature: ReportSignature | undefined }) {
  const title = role === 'publisher' ? 'Publisher' : 'Reviewer';
  return (
    <div className="flex min-w-0 flex-col gap-1 border-t border-hairline pt-2">
      <Checklist as="div">
        <ChecklistLine
          as="div"
          label={`${title} signature`}
          state={signer ? 'confirmed' : 'pending'}
          value={signer ? <KeyId value={signer.key_id} label={`${role} key id`} /> : undefined}
          stamp={signer ? 'Accepted' : `No ${role}`}
          detail={signer ? undefined : `No ${role} signature was accepted at import.`}
        />
      </Checklist>
      {signer ? (
        <KeyValueList
          className="pl-4"
          items={[
            ['Signer', signer.name ?? <span className="text-text-3">unnamed</span>],
            ['Fingerprint', <Digest value={signer.key_id} label={`${role} key fingerprint`} full copy />],
            ['Roles', <RoleTags roles={signer.roles} />],
            ['At import', signature ? <StatusBadge domain="signature" value={signature.status} /> : null],
            ['Detail', signature?.detail ? <span className="text-text-2">{signature.detail}</span> : null],
          ]}
        />
      ) : null}
    </div>
  );
}

function SignersSection({ bundle, className }: { bundle: BundleDetail; className?: string }) {
  const signatures = bundle.report?.signatures ?? [];
  const byRole = ROLES.map((role) => {
    const signer = bundle.signers.find((s) => s.roles.includes(role));
    return { role, signer, signature: signer ? signatures.find((x) => x.key_id === signer.key_id) : undefined };
  });
  const [pub, rev] = byRole;
  const both = Boolean(pub?.signer && rev?.signer);
  const sameKey = both && pub?.signer?.key_id === rev?.signer?.key_id;
  const others = bundle.signers.filter((s) => !s.roles.some((r) => (ROLES as readonly string[]).includes(r)));
  return (
    <Section
      title="Signers"
      description="Signatures accepted at import. The publisher packs and signs; a second key reviews and countersigns."
      attention={!both || sameKey}
      className={className}
    >
      <div className="flex flex-col gap-3">
        <Checklist as="div">
          <ChecklistLine
            as="div"
            label="Two-person rule"
            state={sameKey ? 'warning' : both ? 'confirmed' : 'pending'}
            value={`${formatInt(byRole.filter((x) => x.signer).length)} of 2 roles`}
            stamp={sameKey ? 'One key, two roles' : both ? 'Satisfied' : 'Not satisfied'}
            detail={
              bundle.signers.length === 0
                ? 'No signers were recorded for this bundle.'
                : sameKey
                  ? 'The same key signed as publisher and reviewer.'
                  : both
                    ? 'Publisher and reviewer signed with different keys.'
                    : undefined
            }
          />
        </Checklist>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-1">
          {byRole.map((x) => (
            <SignerBlock key={x.role} role={x.role} signer={x.signer} signature={x.signature} />
          ))}
        </div>
        {others.length ? (
          <div className="overflow-hidden rounded-sm border border-hairline">
            <DataTable columns={OTHER_SIGNER_COLUMNS} rows={others} rowKey={(s) => s.key_id} caption="Other signers whose signatures were accepted at import" />
          </div>
        ) : null}
      </div>
    </Section>
  );
}

function BundleBody({ bundle }: { bundle: BundleDetail }) {
  const manifest = bundle.manifest;
  const requires = manifest?.requires ?? null;
  const rows = artifactRows(bundle);
  const report = bundle.report;
  return (
    <div className="flex flex-col gap-4">
      {/* Side by side only from 1280 px; below that each panel takes the full width so values are not squeezed into a narrow column. */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="Summary">
          <KeyValueList
            wide
            items={[
              ['Bundle id', <Digest value={bundle.bundle_id} label="bundle id" full />],
              [
                'Name and version',
                <MonoId value={`${bundle.name} ${bundle.version}`} className="text-xs" />,
              ],
              ['Description', manifest?.bundle?.description || null],
              ['Created', manifest?.bundle?.created_at ? <Time value={manifest.bundle.created_at} exact /> : null],
              ['Imported', <Time value={bundle.imported_at} exact />],
              ['Imported by', bundle.imported_by],
              ['Source file', <PathText value={bundle.source_name} whole className="text-xs" />],
              ['Artifacts', `${formatInt(bundle.artifact_count)}, ${formatBytes(bundle.total_bytes)} in total`],
              ['Requires Ferry', requires?.ferry_min_version ? <span><span className="font-mono text-xs">{requires.ferry_min_version}</span> or later</span> : null],
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
              ['Manifest schema', manifest?.schema ? <code className="font-mono text-xs">{manifest.schema}</code> : null],
            ]}
          />
        </Section>
        <SignersSection bundle={bundle} />
      </div>

      <Section
        title="Checks at import"
        description={report ? 'Each check the verifier ran before anything was copied into the store.' : undefined}
        attention={report ? report.checks.some((c) => c.status === 'fail' || c.status === 'warn') : false}
        actions={report ? <StatusBadge domain="verdict" value={report.verdict} /> : null}
      >
        {report ? <CheckChecklist checks={report.checks} label={null} columns /> : <p className="text-sm text-text-2">No report was stored with this bundle.</p>}
      </Section>

      <Section title="Artifacts" description="Stored by SHA-256 in the content-addressed store." flush>
        <DataTable
          columns={ARTIFACT_COLUMNS}
          rows={rows}
          rowKey={(a) => a.path}
          caption="Artifacts in this bundle"
          emptyTitle="No artifacts are recorded for this bundle."
        />
      </Section>

      <Section title="Verification report at import" description="What the checks above do not show: the verdict as recorded, report details and the import policy applied.">
        {report ? (
          <div className="flex flex-col gap-4">
            <ReportVerdict report={report} />
            <ReportDetails report={report} />
            <details className="group">
              <summary className="inline-flex cursor-pointer items-center gap-1 rounded-sm text-sm text-text-2 hover:text-bone [&::-webkit-details-marker]:hidden">
                <ChevronDown aria-hidden="true" className="size-3.5 transition-transform duration-150 ease-out group-open:rotate-180 motion-reduce:transition-none" />
                Full verification report (as recorded)
              </summary>
              <div className="mt-3">
                <ReportView report={report} verdict={false} />
              </div>
            </details>
          </div>
        ) : (
          <p className="text-sm text-text-2">No report was stored with this bundle.</p>
        )}
      </Section>

      {bundle.manifest_raw !== null && bundle.manifest_raw !== undefined ? (
        <Section title="manifest.json">
          <details className="group">
            <summary className="inline-flex cursor-pointer items-center gap-1 rounded-sm text-sm text-text-2 hover:text-bone [&::-webkit-details-marker]:hidden">
              <ChevronDown aria-hidden="true" className="size-3.5 transition-transform duration-150 ease-out group-open:rotate-180 motion-reduce:transition-none" />
              Show the manifest as imported
            </summary>
            <JsonView value={bundle.manifest_raw} copyLabel="Copy manifest JSON" className="mt-2" />
          </details>
        </Section>
      ) : null}
    </div>
  );
}

