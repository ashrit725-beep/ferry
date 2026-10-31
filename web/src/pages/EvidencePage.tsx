/**
 * Evidence report (spec section 10) rendered as readable sections. The same
 * report downloads as Markdown or JSON. It records configuration and events;
 * it is not a compliance certification, and the page says so.
 *
 * The top of the page is the report's own checklist: one challenge/response
 * line per section, stamped with what the report shows, each line jumping to
 * its section. Nothing here is admin-only: auditors read the same view.
 */

import type { ReactNode } from 'react';
import { ChevronDown, Download } from 'lucide-react';
import { EVIDENCE_JSON_URL, EVIDENCE_MD_URL, api, type Dependency, type Evidence, type NetworkInventoryEntry } from '../api.ts';
import { isObject, type JsonObject } from '../decode.ts';
import { numberOf, objectsOf, pick, provenanceOf, stringsOf, textOf } from '../evidence.ts';
import { DASH, exactUtc, formatBytes, formatInt, plural } from '../format.ts';
import { useResource } from '../hooks.ts';
import { paths, toHash } from '../router.ts';
import { Callout, RefreshButton } from '../components/console/callout.tsx';
import { Checklist, ChecklistLine } from '../components/console/checklist.tsx';
import { DataTable, type Column } from '../components/console/data-table.tsx';
import { Digest, KeyId, MonoId, PathText } from '../components/console/digest.tsx';
import { JsonView } from '../components/console/json-view.tsx';
import { KeyValueList } from '../components/console/key-value-list.tsx';
import { PageHeader } from '../components/console/page-header.tsx';
import { Section } from '../components/console/section.tsx';
import type { StampState } from '../components/console/stamp.tsx';
import { Async, EmptyState, Loading, PanelSkeleton, TableSkeleton } from '../components/console/states.tsx';
import { StatusBadge } from '../components/console/status-badge.tsx';
import { Time } from '../components/console/time.tsx';
import { ObjectTable, RowsTable, Value } from '../components/console/value.tsx';
import { buttonVariants } from '../components/ui/button.tsx';
import { cn } from '@/lib/utils';

type SectionKey = 'trust' | 'import-policy' | 'bundles' | 'routes' | 'access-policy' | 'audit' | 'network' | 'dependencies' | 'config';

function sectionId(key: SectionKey): string {
  return `evidence-${key}`;
}

/** In-page jumps cannot use #fragments: the fragment is the console route. */
function jumpTo(key: SectionKey): void {
  const section = document.getElementById(sectionId(key));
  const heading = section?.querySelector<HTMLElement>('h2');
  if (!section || !heading) return;
  section.scrollIntoView({ block: 'start' });
  heading.setAttribute('tabindex', '-1');
  heading.focus({ preventScroll: true });
}

const DOWNLOAD_CLASS = buttonVariants({ variant: 'outline', size: 'sm' });

export function EvidencePage() {
  const evidence = useResource((s) => api.evidence(s), []);
  const e = evidence.data;
  const stamp = e?.generated_at ? e.generated_at.slice(0, 10) : 'report';
  return (
    <>
      <PageHeader
        title="Evidence"
        description="A summary of this installation's configuration and recorded events, for reviewers and assessors. It is evidence to examine, not a compliance certification."
        meta={
          e ? (
            <>
              Generated <Time value={e.generated_at} /> by Ferry {e.ferry_version}
              {e.host ? hostText(e.host) : ''}
            </>
          ) : null
        }
        actions={
          <>
            <a className={DOWNLOAD_CLASS} href={EVIDENCE_MD_URL} download={`ferry-evidence-${stamp}.md`}>
              <Download aria-hidden="true" />
              Markdown
            </a>
            <a className={DOWNLOAD_CLASS} href={EVIDENCE_JSON_URL} download={`ferry-evidence-${stamp}.json`}>
              <Download aria-hidden="true" />
              JSON
            </a>
            <RefreshButton onClick={evidence.reload} busy={evidence.refreshing} />
          </>
        }
      />
      <p aria-live="polite" className="sr-only">
        {evidence.refreshing ? 'Building the evidence report…' : e ? `Evidence report generated ${exactUtc(e.generated_at)}.` : ''}
      </p>
      <Async resource={evidence} errorTitle="Could not build the evidence report." skeleton={<EvidenceSkeleton />}>
        {(data) => (
          <div aria-busy={evidence.refreshing || undefined} className={cn('flex flex-col gap-4 transition-opacity duration-150 ease-out', evidence.refreshing && 'opacity-80')}>
            <EvidenceBody evidence={data} />
          </div>
        )}
      </Async>
    </>
  );
}

function EvidenceSkeleton() {
  return (
    <div aria-busy="true" className="flex flex-col gap-4">
      <div className="rounded-lg bg-panel ring-1 ring-hairline">
        <Loading label="Building the evidence report…" />
        <PanelSkeleton lines={9} className="px-3 pb-3" />
      </div>
      <div className="rounded-lg bg-panel ring-1 ring-hairline">
        <TableSkeleton rows={4} columns={6} />
      </div>
    </div>
  );
}

function hostText(host: JsonObject): string {
  const platform = textOf(host['platform']);
  const python = textOf(host['python']);
  const parts = [platform, python ? `Python ${python}` : null].filter(Boolean);
  return parts.length ? ` on ${parts.join(', ')}` : '';
}

// ---------------------------------------------------------------------------
// The report's checklist: what each section attests, read from the report.

interface Attestation {
  key: SectionKey;
  label: string;
  state: StampState;
  stamp: string;
  value?: ReactNode;
  detail?: ReactNode;
}

function attestations(e: Evidence): Attestation[] {
  return [trustLine(e), importPolicyLine(e), bundlesLine(e), routesLine(e), policyLine(e), auditLine(e), inventoryLine(e), dependenciesLine(e), configLine(e)];
}

const NOT_REPORTED = { state: 'neutral', stamp: 'Not reported' } as const;

function trustLine(e: Evidence): Attestation {
  const base = { key: 'trust', label: 'Trust anchors' } as const;
  const rows = e.trust_anchors;
  if (rows.length === 0) return { ...base, state: 'failed', stamp: 'Empty', value: '0 keys', detail: 'With an empty trust store every bundle is rejected.' };
  if (!rows.some((r) => 'status' in r)) return { ...base, state: 'info', stamp: 'Recorded', value: plural(rows.length, 'key') };
  const active = rows.filter((r) => textOf(r['status']) === 'active').length;
  const value = `${formatInt(active)} of ${formatInt(rows.length)} active`;
  if (active === 0) return { ...base, state: 'failed', stamp: 'None active', value, detail: 'No key can sign an importable bundle.' };
  return { ...base, state: 'confirmed', stamp: 'Trusted', value };
}

function importPolicyLine(e: Evidence): Attestation {
  const base = { key: 'import-policy', label: 'Import policy' } as const;
  if (!e.import_policy) return { ...base, ...NOT_REPORTED };
  return { ...base, state: 'info', stamp: 'Recorded', value: plural(Object.keys(e.import_policy).length, 'setting') };
}

function bundlesLine(e: Evidence): Attestation {
  const base = { key: 'bundles', label: 'Bundles' } as const;
  if (e.bundles.length === 0) return { ...base, state: 'neutral', stamp: 'None imported', value: '0 bundles' };
  const artifacts = e.bundles.reduce((n, b) => n + objectsOf(b['artifacts']).length, 0);
  return { ...base, state: 'info', stamp: 'Recorded', value: `${plural(e.bundles.length, 'bundle')} · ${plural(artifacts, 'artifact')}` };
}

function routesLine(e: Evidence): Attestation {
  const base = { key: 'routes', label: 'Routes' } as const;
  const rows = e.routes;
  if (rows.length === 0) return { ...base, state: 'neutral', stamp: 'None configured', value: '0 routes' };
  const states = rows.map((r) => provenanceOf(r['provenance']).state);
  const verified = states.filter((s) => s === 'verified').length;
  const mismatched = states.filter((s) => s === 'mismatch').length;
  const value = `${formatInt(verified)} of ${formatInt(rows.length)} verified`;
  if (mismatched > 0) return { ...base, state: 'failed', stamp: 'Mismatch', value, detail: `${plural(mismatched, 'route')} served a digest that does not match its pin.` };
  if (verified < rows.length) return { ...base, state: 'warning', stamp: 'Unverified', value, detail: `${plural(rows.length - verified, 'route')} without verified provenance.` };
  return { ...base, state: 'confirmed', stamp: 'Verified', value };
}

function policyLine(e: Evidence): Attestation {
  const base = { key: 'access-policy', label: 'Access policy' } as const;
  const active = e.active_policy;
  if (!active) return { ...base, state: 'failed', stamp: 'No policy', detail: 'No active policy: every gateway request is denied.' };
  return { ...base, state: 'confirmed', stamp: 'Active', value: `v${textOf(active['version']) ?? '?'}` };
}

function auditLine(e: Evidence): Attestation {
  const base = { key: 'audit', label: 'Audit chain' } as const;
  const audit = e.audit;
  if (!audit) return { ...base, ...NOT_REPORTED };
  const firstBad = numberOf(audit['first_bad_seq']);
  if (audit['ok'] !== true) {
    return {
      ...base,
      state: 'failed',
      stamp: 'Broken',
      value: firstBad !== null ? `#${formatInt(firstBad)}` : undefined,
      detail: `Chain broken${firstBad !== null ? ` at event #${formatInt(firstBad)}` : ''}.`,
    };
  }
  const head = textOf(audit['head_hash']);
  return { ...base, state: 'confirmed', stamp: 'Intact', value: head ? <Digest value={head} label="head hash" copy={false} /> : undefined };
}

function inventoryLine(e: Evidence): Attestation {
  const base = { key: 'network', label: 'Network inventory' } as const;
  if (e.network_inventory.length === 0) return { ...base, ...NOT_REPORTED };
  return { ...base, state: 'info', stamp: 'Recorded', value: plural(e.network_inventory.length, 'connection') };
}

function dependenciesLine(e: Evidence): Attestation {
  const base = { key: 'dependencies', label: 'Dependencies' } as const;
  if (e.dependencies.length === 0) return { ...base, ...NOT_REPORTED };
  return { ...base, state: 'info', stamp: 'Recorded', value: plural(e.dependencies.length, 'package') };
}

function configLine(e: Evidence): Attestation {
  const base = { key: 'config', label: 'Effective configuration' } as const;
  if (!e.config) return { ...base, ...NOT_REPORTED };
  return { ...base, state: 'info', stamp: 'Recorded', value: plural(Object.keys(e.config).length, 'setting') };
}

function summaryOf(lines: readonly Attestation[]): string {
  const count = (s: StampState): number => lines.filter((l) => l.state === s).length;
  const parts = [
    [count('confirmed'), 'confirmed'],
    [count('failed'), 'failed'],
    [count('warning'), 'to review'],
    [count('info'), 'recorded'],
    [count('neutral'), 'empty or not reported'],
  ] as const;
  return parts
    .filter(([n]) => n > 0)
    .map(([n, word]) => `${formatInt(n)} ${word}`)
    .join(' · ');
}

function Attests({ evidence }: { evidence: Evidence }) {
  const lines = attestations(evidence);
  return (
    <Section
      title="What this report attests"
      description="One line per section of the report, stamped with what it shows. Select a line to read its section."
      footer="Recorded lines are evidence to examine, not a pass. The report is rebuilt from the live store each time it is generated."
    >
      <nav aria-label="Evidence sections">
        <Checklist summary={summaryOf(lines)}>
          {lines.map((l) => (
            <ChecklistLine
              key={l.key}
              label={l.label}
              state={l.state}
              stamp={l.stamp}
              value={l.value}
              detail={l.detail}
              drawKey={evidence.generated_at}
              onClick={() => jumpTo(l.key)}
            />
          ))}
        </Checklist>
      </nav>
    </Section>
  );
}

// ---------------------------------------------------------------------------
// Report sections.

function EvidenceBody({ evidence: e }: { evidence: Evidence }) {
  return (
    <>
      <Attests evidence={e} />

      <Section id={sectionId('trust')} flush title="Trust anchors" description="Keys this installation accepts bundle signatures from, and their status.">
        <TrustAnchors rows={e.trust_anchors} />
      </Section>

      <Section id={sectionId('import-policy')} flush title="Import policy" description="What an imported bundle must satisfy. Set in ferry.toml on the host.">
        {e.import_policy ? (
          <ObjectTable value={e.import_policy} caption="Import policy" />
        ) : (
          <NotReported>The report carries no import policy. Check the <code>[import]</code> settings in ferry.toml on the host, then refresh.</NotReported>
        )}
      </Section>

      <Section id={sectionId('bundles')} flush title="Bundles" description="Imported bundles, who signed them, and their artifacts.">
        <Bundles rows={e.bundles} />
      </Section>

      <Section id={sectionId('routes')} flush title="Routes" description="Public model names, their backends, pinned artifacts and provenance at report time.">
        <Routes rows={e.routes} />
      </Section>

      <Section id={sectionId('access-policy')} title="Access policy" description="The policy version in force and every version before it.">
        <AccessPolicy active={e.active_policy} history={e.policy_history} />
      </Section>

      <Section id={sectionId('audit')} title="Audit chain" description="The hash chain recomputed when this report was generated.">
        <AuditChain audit={e.audit} />
      </Section>

      <Section id={sectionId('network')} flush title="Network inventory" description="Connections Ferry is configured to accept or make: its listener and the configured backends.">
        <Inventory rows={e.network_inventory} />
      </Section>

      <Section id={sectionId('dependencies')} flush title="Dependencies" description="Installed runtime packages and versions.">
        <Dependencies rows={e.dependencies} />
      </Section>

      <Section id={sectionId('config')} title="Effective configuration" description="Settings in force, after defaults. Contains no secrets.">
        {e.config ? (
          <Config config={e.config} />
        ) : (
          <NotReported className="px-0 py-2">The report carries no configuration. Run <code>ferry evidence</code> on the host to see whether the configuration loads.</NotReported>
        )}
      </Section>
    </>
  );
}

function NotReported({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <EmptyState title="Not reported." className={className}>
      {children}
    </EmptyState>
  );
}

function Roles({ value }: { value: unknown }) {
  const roles = stringsOf(value);
  if (roles.length === 0) return <span className="text-text-3">none</span>;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {roles.map((r) => (
        <Tag key={r}>{r}</Tag>
      ))}
    </span>
  );
}

function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-flex h-5 items-center rounded-sm border border-line-control/50 bg-raised px-1.5 text-2xs whitespace-nowrap text-text-2">{children}</span>;
}

function TimeOrText({ value, fallback, future = false }: { value: unknown; fallback: string; future?: boolean }) {
  const t = textOf(value);
  return t ? <Time value={t} future={future} /> : <span className="text-text-3">{fallback}</span>;
}

function rowKeyOf(row: JsonObject, index: number, ...keys: string[]): string {
  return `${textOf(pick(row, ...keys)) ?? ''}#${index}`;
}

type Indexed<T> = { row: T; index: number };

function indexed<T>(rows: readonly T[]): Indexed<T>[] {
  return rows.map((row, index) => ({ row, index }));
}

const TRUST_COLUMNS: ReadonlyArray<Column<Indexed<JsonObject>>> = [
  { id: 'name', header: 'Name', cell: ({ row: r }) => textOf(r['name']) ?? <span className="text-text-3">unnamed</span> },
  {
    id: 'key',
    header: 'Key id',
    nowrap: true,
    cell: ({ row: r }) => {
      const keyId = textOf(r['key_id']);
      return keyId ? <KeyId value={keyId} /> : null;
    },
  },
  { id: 'roles', header: 'Roles', cell: ({ row: r }) => <Roles value={r['roles']} /> },
  { id: 'status', header: 'Status', nowrap: true, sortValue: ({ row: r }) => textOf(r['status']), cell: ({ row: r }) => <StatusBadge domain="trust" value={textOf(r['status'])} /> },
  { id: 'from', header: 'Valid from', nowrap: true, cell: ({ row: r }) => <TimeOrText value={r['not_before']} fallback="any time" future /> },
  { id: 'until', header: 'Valid until', nowrap: true, cell: ({ row: r }) => <TimeOrText value={r['not_after']} fallback="no expiry" future /> },
  {
    id: 'revoked',
    header: 'Revoked',
    cell: ({ row: r }) => {
      const reason = textOf(r['revocation_reason']);
      if (!textOf(r['revoked_at'])) return <span className="text-text-3">no</span>;
      return (
        <>
          <TimeOrText value={r['revoked_at']} fallback="" />
          {reason ? <div className="text-2xs text-text-3">{reason}</div> : null}
        </>
      );
    },
  },
];

/** Keys that cannot sign right now but are not revoked hold an amber row; revoked keys print in grey. */
const TRUST_WARN = new Set(['expired', 'not_yet_valid']);

function TrustAnchors({ rows }: { rows: readonly JsonObject[] }) {
  if (rows.length > 0 && !rows.some((r) => 'key_id' in r)) return <RowsTable rows={rows} caption="Trust anchors" />;
  return (
    <DataTable
      caption="Trust anchors"
      columns={TRUST_COLUMNS}
      rows={indexed(rows)}
      rowKey={({ row, index }) => rowKeyOf(row, index, 'key_id')}
      rowTone={({ row }) => (TRUST_WARN.has(textOf(row['status']) ?? '') ? 'warn' : null)}
      rowProps={({ row }) => (textOf(row['status']) === 'revoked' ? { className: '[&_td]:text-text-3' } : {})}
      maxHeight="max-h-none"
      empty={
        <EmptyState title="No trust anchors.">
          With an empty trust store every bundle is rejected. Keys are added on the host with <code>ferry trust add</code>.
        </EmptyState>
      }
    />
  );
}

function SignerList({ value }: { value: unknown }) {
  const signers = Array.isArray(value) ? value : [];
  if (signers.length === 0) return <span className="text-text-3">none recorded</span>;
  return (
    <ul className="m-0 flex list-none flex-col gap-1 p-0">
      {signers.map((s, i) => {
        if (!isObject(s)) return <li key={i}>{textOf(s) ?? ''}</li>;
        const keyId = textOf(s['key_id']);
        return (
          <li key={keyId ?? i} className="flex flex-wrap items-center gap-2">
            <span>{textOf(s['name']) ?? (keyId ? <KeyId value={keyId} /> : 'unnamed')}</span>
            <Roles value={s['roles']} />
          </li>
        );
      })}
    </ul>
  );
}

const ARTIFACT_COLUMNS: ReadonlyArray<Column<Indexed<JsonObject>>> = [
  { id: 'path', header: 'Path', sortValue: ({ row: a }) => textOf(a['path']), cell: ({ row: a }) => <PathText value={textOf(a['path']) ?? ''} /> },
  { id: 'kind', header: 'Kind', cell: ({ row: a }) => textOf(a['kind']) ?? '' },
  { id: 'format', header: 'Format', mono: true, cell: ({ row: a }) => textOf(a['format']) ?? '' },
  { id: 'size', header: 'Size', align: 'right', nowrap: true, sortValue: ({ row: a }) => numberOf(a['size']), cell: ({ row: a }) => formatBytes(numberOf(a['size'])) },
  {
    id: 'sha',
    header: 'SHA-256',
    nowrap: true,
    cell: ({ row: a }) => <Digest value={textOf(pick(a, 'sha256', 'digest'))} label={`sha256 of ${textOf(a['path']) ?? 'artifact'}`} />,
  },
];

function Bundles({ rows }: { rows: readonly JsonObject[] }) {
  if (rows.length === 0) {
    return (
      <EmptyState title="No bundles imported.">
        Bundles appear here once imported from the inbox on the <a className="text-bone underline underline-offset-3" href={toHash(paths.bundles)}>Bundles</a> page, or on the host with <code>ferry import BUNDLE</code>.
      </EmptyState>
    );
  }
  return (
    <ul className="m-0 list-none divide-y divide-hairline p-0">
      {rows.map((b, i) => {
        const id = textOf(pick(b, 'bundle_id', 'id'));
        const artifacts = objectsOf(b['artifacts']);
        const total = artifacts.reduce((n, a) => n + (numberOf(a['size']) ?? 0), 0);
        const name = textOf(b['name']) ?? 'unnamed';
        return (
          <li key={id ?? i} className="flex flex-col gap-2 py-3">
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 px-3">
              <h3 className="font-mono text-sm font-medium text-bone">
                {name} <span className="text-text-2">{textOf(b['version']) ?? ''}</span>
              </h3>
              {id ? <Digest value={id} label="bundle id" /> : null}
            </div>
            <KeyValueList
              className="px-3"
              items={[
                ['Imported', <TimeOrText value={b['imported_at']} fallback="not recorded" />],
                ['Signers', <SignerList value={b['signers']} />],
                ['Artifacts', artifacts.length ? `${plural(artifacts.length, 'artifact')}, ${formatBytes(total)}` : <Value value={b['artifacts']} />],
              ]}
            />
            {artifacts.length ? (
              <div className="border-t border-hairline">
                <DataTable
                  caption={`Artifacts of ${name}`}
                  columns={ARTIFACT_COLUMNS}
                  rows={indexed(artifacts)}
                  rowKey={({ row, index }) => rowKeyOf(row, index, 'path')}
                  maxHeight="max-h-none"
                />
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

const ROUTE_COLUMNS: ReadonlyArray<Column<Indexed<JsonObject>>> = [
  {
    id: 'model',
    header: 'Model',
    className: 'max-w-48 xl:max-w-64',
    sortValue: ({ row: r }) => textOf(r['model']),
    cell: ({ row: r }) => {
      const model = textOf(r['model']);
      return model ? <MonoId value={model} /> : '';
    },
  },
  {
    id: 'backend',
    header: 'Backend',
    className: 'max-w-48 xl:max-w-64',
    cell: ({ row: r }) => {
      const backend = pick(r, 'backend', 'backend_name');
      const name = isObject(backend) ? textOf(backend['name']) : textOf(backend);
      return name ? <MonoId value={name} /> : isObject(backend) ? <Value value={backend} /> : '';
    },
  },
  {
    id: 'pin',
    header: 'Pinned artifact',
    nowrap: true,
    cell: ({ row: r }) => {
      const pin = textOf(pick(r, 'pin', 'artifact_digest'));
      return pin ? <Digest value={pin} label="pinned digest" /> : <Tag>not pinned</Tag>;
    },
  },
  {
    id: 'prov',
    header: 'Provenance',
    sortValue: ({ row: r }) => provenanceOf(r['provenance']).state,
    cell: ({ row: r }) => {
      const prov = provenanceOf(r['provenance']);
      return (
        <>
          <StatusBadge domain="provenance" value={prov.state} />
          {prov.detail ? <div className="pt-0.5 text-2xs text-text-3">{prov.detail}</div> : null}
        </>
      );
    },
  },
];

function Routes({ rows }: { rows: readonly JsonObject[] }) {
  return (
    <DataTable
      caption="Routes"
      columns={ROUTE_COLUMNS}
      rows={indexed(rows)}
      rowKey={({ row, index }) => rowKeyOf(row, index, 'model')}
      rowTone={({ row }) => {
        const state = provenanceOf(row['provenance']).state;
        return state === 'mismatch' ? 'bad' : state === 'verified' ? null : 'warn';
      }}
      maxHeight="max-h-none"
      empty={
        <EmptyState title="No routes configured.">
          Add a route on the <a className="text-bone underline underline-offset-3" href={toHash(paths.models)}>Models</a> page, or on the host with{' '}
          <code>ferry route add MODEL --backend NAME --artifact DIGEST</code>.
        </EmptyState>
      }
    />
  );
}

const HISTORY_COLUMNS: ReadonlyArray<Column<Indexed<JsonObject>>> = [
  { id: 'version', header: 'Version', mono: true, nowrap: true, sortValue: ({ row: h }) => numberOf(h['version']), cell: ({ row: h }) => `v${textOf(h['version']) ?? '?'}` },
  { id: 'created', header: 'Created', nowrap: true, cell: ({ row: h }) => <TimeOrText value={h['created_at']} fallback="" /> },
  { id: 'by', header: 'By', cell: ({ row: h }) => textOf(h['created_by']) ?? '' },
  { id: 'comment', header: 'Comment', cell: ({ row: h }) => textOf(h['comment']) || <span className="text-text-3">none</span> },
  { id: 'sha', header: 'SHA-256', nowrap: true, cell: ({ row: h }) => <Digest value={textOf(h['sha256'])} label="policy sha256" /> },
];

function AccessPolicy({ active, history }: { active: JsonObject | null; history: readonly JsonObject[] }) {
  const sha = active ? textOf(active['sha256']) : null;
  return (
    <div className="flex flex-col gap-3">
      {active ? (
        <KeyValueList
          items={[
            { term: 'Active version', value: `v${textOf(active['version']) ?? '?'}`, mono: true },
            ['SHA-256', sha ? <Digest value={sha} label="policy sha256" /> : null],
            ['Activated', <TimeOrText value={active['activated_at']} fallback="not recorded" />],
            ['Activated by', textOf(active['activated_by'])],
          ]}
        />
      ) : (
        <Callout tone="bad" title="No active policy">
          <p>Every gateway request is denied.</p>
        </Callout>
      )}
      {history.length ? (
        <div className="-mx-3 -mb-3 border-t border-hairline">
          <h3 className="px-3 pt-2 text-xs font-medium text-text-2">Version history</h3>
          <DataTable
            caption="Policy version history"
            columns={HISTORY_COLUMNS}
            rows={indexed(history)}
            rowKey={({ row, index }) => rowKeyOf(row, index, 'version')}
            maxHeight="max-h-none"
          />
        </div>
      ) : null}
    </div>
  );
}

function AuditChain({ audit }: { audit: JsonObject | null }) {
  if (!audit) {
    return (
      <NotReported className="px-0 py-2">
        The report carries no chain check. Verify the chain on the <a className="text-bone underline underline-offset-3" href={toHash(paths.audit({}))}>Audit</a> page, then refresh.
      </NotReported>
    );
  }
  const ok = audit['ok'] === true;
  const firstBad = numberOf(audit['first_bad_seq']);
  const checked = numberOf(audit['events_checked']);
  const headSeq = numberOf(audit['head_seq']);
  const headHash = textOf(audit['head_hash']);
  const problem = textOf(audit['problem']);
  return (
    <div className="flex flex-col gap-3">
      <Checklist as="div">
        <ChecklistLine
          as="div"
          label="Hash chain recomputed"
          state={ok ? 'confirmed' : 'failed'}
          stamp={ok ? 'Intact' : 'Broken'}
          value={ok ? (headSeq !== null ? `#${formatInt(headSeq)}` : undefined) : firstBad !== null ? `#${formatInt(firstBad)}` : undefined}
          detail={ok ? 'Chain intact.' : `Chain broken${firstBad !== null ? ` at event #${formatInt(firstBad)}` : ''}.${problem ? ` ${problem}` : ''}`}
        />
      </Checklist>
      <KeyValueList
        items={[
          { term: 'Events checked', value: checked !== null ? formatInt(checked) : null, mono: true },
          { term: 'Head', value: headSeq !== null ? `#${formatInt(headSeq)}` : null, mono: true },
          ['Head hash', headHash ? <Digest value={headHash} label="head hash" /> : null],
          ['Checked', <TimeOrText value={audit['verified_at']} fallback="not recorded" />],
        ]}
      />
    </div>
  );
}

const INVENTORY_COLUMNS: ReadonlyArray<Column<Indexed<NetworkInventoryEntry>>> = [
  { id: 'component', header: 'Component', sortValue: ({ row: r }) => r.component, cell: ({ row: r }) => r.component },
  { id: 'direction', header: 'Direction', nowrap: true, sortValue: ({ row: r }) => r.direction, cell: ({ row: r }) => <Tag>{r.direction}</Tag> },
  { id: 'destination', header: 'Destination', mono: true, cell: ({ row: r }) => r.destination },
  { id: 'purpose', header: 'Purpose', cell: ({ row: r }) => r.purpose },
  {
    id: 'configurable',
    header: 'Configurable',
    nowrap: true,
    cell: ({ row: r }) => (r.configurable === null ? <span className="text-text-3">{DASH}</span> : r.configurable ? 'yes' : 'no'),
  },
  { id: 'notes', header: 'Notes', cell: ({ row: r }) => r.notes || <span className="text-text-3">{DASH}</span> },
];

function Inventory({ rows }: { rows: readonly NetworkInventoryEntry[] }) {
  return (
    <DataTable
      caption="Network inventory"
      columns={INVENTORY_COLUMNS}
      rows={indexed(rows)}
      rowKey={({ row: r, index }) => `${r.component}-${r.destination}-${index}`}
      maxHeight="max-h-none"
      empty={<NotReported>The report lists no connections. The listener and every configured backend should appear here; check the configuration on the host and refresh.</NotReported>}
    />
  );
}

const DEPENDENCY_COLUMNS: ReadonlyArray<Column<Dependency>> = [
  { id: 'name', header: 'Package', mono: true, sortValue: (d) => d.name, cell: (d) => d.name },
  { id: 'version', header: 'Version', mono: true, nowrap: true, cell: (d) => d.version },
];

function Dependencies({ rows }: { rows: readonly Dependency[] }) {
  return (
    <DataTable
      caption="Dependencies"
      columns={DEPENDENCY_COLUMNS}
      rows={rows}
      rowKey={(d) => d.name}
      maxHeight="max-h-none"
      className="sm:max-w-xl"
      empty={<NotReported>The report lists no installed packages. Run <code>ferry evidence</code> on the host to compare.</NotReported>}
    />
  );
}

function Config({ config }: { config: JsonObject }) {
  const scalars = Object.entries(config).filter(([, v]) => !isObject(v));
  const sections = Object.entries(config).filter((entry): entry is [string, JsonObject] => isObject(entry[1]));
  return (
    <div className="flex flex-col gap-3">
      {scalars.length ? <KeyValueList wide monoTerms items={scalars.map(([k, v]) => [k, <Value value={v} name={k} />] as const)} /> : null}
      {sections.map(([name, value]) => (
        <div key={name} className="-mx-3 border-t border-hairline">
          <h3 className="px-3 pt-2 font-mono text-xs text-text-2">[{name}]</h3>
          <ObjectTable value={value} caption={`[${name}] settings`} />
        </div>
      ))}
      <details className="group -mx-3 -mb-3 border-t border-hairline px-3 py-2">
        <summary className="inline-flex h-8 cursor-pointer items-center gap-1 rounded-sm text-xs text-text-2 hover:text-bone [&::-webkit-details-marker]:hidden">
          <ChevronDown aria-hidden="true" className="size-3.5 transition-transform duration-150 ease-out group-open:rotate-180 motion-reduce:transition-none" />
          Show the effective configuration as JSON
        </summary>
        <JsonView value={config} copyLabel="Copy effective configuration as JSON" className="mt-1" />
      </details>
    </div>
  );
}
