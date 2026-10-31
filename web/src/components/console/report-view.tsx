/**
 * A `ferry verify` report (spec section 4): verdict, every check in the order
 * it ran, signers, artifacts with expected and actual digests, errors and
 * warnings. Logic unchanged; the tables are DataTables and the summary is a
 * Callout with stamps.
 */

import { REPORT_VERSION, type ReportArtifact, type ReportCheck, type ReportSignature, type VerificationReport } from '../../api.ts';
import { DASH, formatBytes, formatInt, plural } from '../../format.ts';
import { statusLabel } from '../../status.ts';
import { Callout } from './callout.tsx';
import { DataTable, type Column } from './data-table.tsx';
import { Digest, KeyId, PathText } from './digest.tsx';
import { KeyValueList } from './key-value-list.tsx';
import { StatusBadge } from './status-badge.tsx';
import { Time } from './time.tsx';
import { ObjectTable } from './value.tsx';

function countBy(checks: readonly ReportCheck[], status: string): number {
  return checks.filter((c) => c.status === status).length;
}

/** The verdict line: accepted or rejected, the counts, and every error. */
export function ReportVerdict({ report }: { report: VerificationReport }) {
  const accepted = report.verdict === 'accepted';
  const failed = countBy(report.checks, 'fail');
  const parts = [
    plural(countBy(report.checks, 'pass'), 'check') + ' passed',
    failed ? `${formatInt(failed)} failed` : null,
    report.warnings.length ? plural(report.warnings.length, 'warning') : null,
  ].filter(Boolean);
  const name = report.bundle?.name ? `${report.bundle.name} ${report.bundle.version ?? ''}`.trim() : null;
  return (
    <Callout
      tone={accepted ? 'ok' : report.verdict === 'rejected' ? 'bad' : 'neutral'}
      title={
        <>
          {accepted ? 'Accepted' : report.verdict === 'rejected' ? 'Rejected' : statusLabel(report.verdict)}
          {name ? <span className="font-normal text-text-2"> · {name}</span> : null}
        </>
      }
    >
      <p>{parts.join(', ')}.</p>
      {report.errors.length ? (
        <ul>
          {report.errors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      ) : null}
    </Callout>
  );
}

const CHECK_COLUMNS: ReadonlyArray<Column<ReportCheck & { row: number }>> = [
  { id: 'result', header: 'Result', nowrap: true, cell: (c) => <StatusBadge domain="check" value={c.status} /> },
  { id: 'check', header: 'Check', nowrap: true, mono: true, cell: (c) => c.id },
  { id: 'message', header: 'Message', cell: (c) => c.message || <span className="text-text-3">{DASH}</span> },
];

const SIGNATURE_COLUMNS: ReadonlyArray<Column<ReportSignature>> = [
  { id: 'status', header: 'Status', nowrap: true, cell: (s) => <StatusBadge domain="signature" value={s.status} /> },
  { id: 'signer', header: 'Signer', cell: (s) => s.name ?? <span className="text-text-3">not in the trust store</span> },
  { id: 'key', header: 'Key id', nowrap: true, cell: (s) => <KeyId value={s.key_id} /> },
  {
    id: 'roles',
    header: 'Roles',
    cell: (s) =>
      s.roles.length ? (
        <span className="inline-flex flex-wrap gap-1">
          {s.roles.map((r) => (
            <span key={r} className="rounded-sm border border-hairline px-1 text-2xs text-text-2">
              {r}
            </span>
          ))}
        </span>
      ) : (
        <span className="text-text-3">{DASH}</span>
      ),
  },
  { id: 'detail', header: 'Detail', cell: (s) => s.detail || <span className="text-text-3">{DASH}</span> },
];

function FormatCell({ artifact }: { artifact: ReportArtifact }) {
  const { declared_format: declared, detected_format: detected } = artifact;
  if (declared && detected && declared !== detected) {
    return (
      <span className="text-bad">
        declared <code>{declared}</code>, detected <code>{detected}</code>
      </span>
    );
  }
  return <code>{declared ?? detected ?? DASH}</code>;
}

function DigestCell({ artifact }: { artifact: ReportArtifact }) {
  const { expected_sha256: expected, actual_sha256: actual } = artifact;
  if (expected && actual && expected !== actual) {
    return (
      <div className="flex flex-col gap-0.5">
        <span>
          <span className="text-text-3">expected </span>
          <Digest value={expected} label={`expected sha256 of ${artifact.path}`} />
        </span>
        <span className="text-bad">
          <span>actual </span>
          <Digest value={actual} label={`actual sha256 of ${artifact.path}`} />
        </span>
      </div>
    );
  }
  return <Digest value={expected ?? actual} label={`sha256 of ${artifact.path}`} />;
}

const ARTIFACT_COLUMNS: ReadonlyArray<Column<ReportArtifact>> = [
  { id: 'status', header: 'Status', nowrap: true, cell: (a) => <StatusBadge domain="artifact" value={a.status} /> },
  { id: 'path', header: 'Path', mono: true, cell: (a) => <PathText value={a.path} /> },
  { id: 'kind', header: 'Kind', cell: (a) => a.kind ?? <span className="text-text-3">{DASH}</span> },
  { id: 'format', header: 'Format', nowrap: true, cell: (a) => <FormatCell artifact={a} /> },
  { id: 'size', header: 'Size', align: 'right', nowrap: true, cell: (a) => <span title={a.size !== null ? `${a.size} bytes` : undefined}>{formatBytes(a.size)}</span> },
  { id: 'sha', header: 'SHA-256', nowrap: true, cell: (a) => <DigestCell artifact={a} /> },
  { id: 'detail', header: 'Detail', cell: (a) => a.detail || <span className="text-text-3">{DASH}</span> },
];

function Sub({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-xs font-medium text-text-2">{title}</h3>
      {children}
    </section>
  );
}

export function ReportView({ report, verdict = true }: { report: VerificationReport; /** False when the verdict callout is already shown above. */ verdict?: boolean }) {
  const checks = report.checks.map((c, row) => ({ ...c, row }));
  return (
    <div className="flex flex-col gap-4">
      {verdict ? <ReportVerdict report={report} /> : null}
      {report.report_version !== null && report.report_version !== REPORT_VERSION ? (
        <Callout tone="warn">
          This report has report_version {report.report_version}; this console was built for version {REPORT_VERSION} and may not show every field.
        </Callout>
      ) : null}
      {report.warnings.length ? (
        <Callout tone="warn" title={plural(report.warnings.length, 'warning')}>
          <ul>
            {report.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </Callout>
      ) : null}
      <Sub title="Checks">
        <div className="rounded-sm border border-hairline">
          <DataTable columns={CHECK_COLUMNS} rows={checks} rowKey={(c) => `${c.id}-${c.row}`} caption="Checks, in the order they ran" emptyTitle="The report lists no checks." rowTone={(c) => (c.status === 'fail' ? 'bad' : c.status === 'warn' ? 'warn' : null)} maxHeight="max-h-none" />
        </div>
      </Sub>
      <Sub title="Signatures">
        <div className="rounded-sm border border-hairline">
          <DataTable columns={SIGNATURE_COLUMNS} rows={report.signatures} rowKey={(s) => s.key_id} caption="Signatures" emptyTitle="No signatures were read from this bundle." maxHeight="max-h-none" />
        </div>
      </Sub>
      <Sub title="Artifacts">
        <div className="rounded-sm border border-hairline">
          <DataTable columns={ARTIFACT_COLUMNS} rows={report.artifacts} rowKey={(a) => a.path} caption="Artifacts" emptyTitle="The report lists no artifacts." rowTone={(a) => (a.status === 'ok' || a.status === 'skipped' ? null : 'bad')} maxHeight="max-h-none" />
        </div>
      </Sub>
      <Sub title="Report details">
        <ReportDetails report={report} />
      </Sub>
    </div>
  );
}

/** Report details and the import policy applied: what the checks and tables do not show. */
export function ReportDetails({ report }: { report: VerificationReport }) {
  const source = report.source;
  return (
    <div className="flex flex-col gap-2">
      <KeyValueList
        wide
        items={[
          ['Bundle id', report.bundle_id ? <Digest value={report.bundle_id} label="bundle id" full /> : null],
          ['Bundle created', report.bundle?.created_at ? <Time value={report.bundle.created_at} exact /> : null],
          [
            'Source',
            source?.name ? (
              <span>
                <code className="text-xs">{source.name}</code>
                <span className="text-text-3">
                  {source.type ? ` · ${source.type}` : ''}
                  {source.size !== null ? ` · ${formatBytes(source.size)}` : ''}
                </span>
              </span>
            ) : null,
          ],
          ['Verified', report.verified_at ? <Time value={report.verified_at} exact /> : null],
          ['Ferry version', report.tool_version ? <span className="font-mono text-xs">{report.tool_version}</span> : null],
          ['Report version', report.report_version !== null ? String(report.report_version) : null],
        ]}
      />
      {report.policy && Object.keys(report.policy).length ? (
        <div className="flex flex-col gap-2">
          <h4 className="text-xs font-medium text-text-2">Import policy applied</h4>
          <div className="rounded-sm border border-hairline">
            <ObjectTable value={report.policy} caption="Import policy applied" />
          </div>
        </div>
      ) : null}
    </div>
  );
}
