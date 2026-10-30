/**
 * A `ferry verify` report (spec section 4): verdict, every check in the order
 * it ran, signers, artifacts with expected and actual digests, errors and
 * warnings. Used for job results, verification records and imported bundles.
 */

import { REPORT_VERSION, type ReportArtifact, type ReportCheck, type VerificationReport } from '../api.ts';
import { DASH, formatBytes, formatInt, plural } from '../format.ts';
import { statusLabel } from '../status.ts';
import { Digest, KeyId } from './Digest.tsx';
import { Callout, DefList } from './Panel.tsx';
import { StatusBadge } from './StatusBadge.tsx';
import { Time } from './Time.tsx';
import { ObjectTable } from './Value.tsx';

function countBy(checks: readonly ReportCheck[], status: string): number {
  return checks.filter((c) => c.status === status).length;
}

function Summary({ report }: { report: VerificationReport }) {
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
          {name ? <span className="callout__subject"> · {name}</span> : null}
        </>
      }
    >
      <p>{parts.join(', ')}.</p>
      {report.errors.length ? (
        <ul className="report__errors">
          {report.errors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      ) : null}
    </Callout>
  );
}

function ChecksTable({ checks }: { checks: readonly ReportCheck[] }) {
  if (checks.length === 0) return <p className="table-note">The report lists no checks.</p>;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Checks, in the order they ran</caption>
        <thead>
          <tr>
            <th scope="col">Result</th>
            <th scope="col">Check</th>
            <th scope="col">Message</th>
          </tr>
        </thead>
        <tbody>
          {checks.map((c, i) => (
            <tr key={`${c.id}-${i}`} className={c.status === 'fail' ? 'is-bad' : undefined}>
              <td className="nowrap">
                <StatusBadge domain="check" value={c.status} />
              </td>
              <td className="nowrap">
                <code>{c.id}</code>
              </td>
              <td className="break">{c.message || <span className="subtle">{DASH}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SignaturesTable({ report }: { report: VerificationReport }) {
  if (report.signatures.length === 0) {
    return <p className="table-note">No signatures were read from this bundle.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Signatures</caption>
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Signer</th>
            <th scope="col">Key id</th>
            <th scope="col">Roles</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {report.signatures.map((s) => (
            <tr key={s.key_id}>
              <td className="nowrap">
                <StatusBadge domain="signature" value={s.status} />
              </td>
              <td>{s.name ?? <span className="subtle">not in the trust store</span>}</td>
              <td className="nowrap">
                <KeyId value={s.key_id} />
              </td>
              <td>
                {s.roles.length ? (
                  <span className="inline-list">
                    {s.roles.map((r) => (
                      <span key={r} className="tag">
                        {r}
                      </span>
                    ))}
                  </span>
                ) : (
                  <span className="subtle">{DASH}</span>
                )}
              </td>
              <td className="break">{s.detail || <span className="subtle">{DASH}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

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
      <div className="digest-pair">
        <span>
          <span className="subtle">expected </span>
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

function ArtifactsTable({ artifacts }: { artifacts: readonly ReportArtifact[] }) {
  if (artifacts.length === 0) return <p className="table-note">The report lists no artifacts.</p>;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Artifacts</caption>
        <thead>
          <tr>
            <th scope="col">Status</th>
            <th scope="col">Path</th>
            <th scope="col">Kind</th>
            <th scope="col">Format</th>
            <th scope="col" className="num">
              Size
            </th>
            <th scope="col">SHA-256</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {artifacts.map((a) => (
            <tr key={a.path}>
              <td className="nowrap">
                <StatusBadge domain="artifact" value={a.status} />
              </td>
              <td className="break">
                <code>{a.path}</code>
              </td>
              <td>{a.kind ?? <span className="subtle">{DASH}</span>}</td>
              <td className="nowrap">
                <FormatCell artifact={a} />
              </td>
              <td className="num" title={a.size !== null ? `${a.size} bytes` : undefined}>
                {formatBytes(a.size)}
              </td>
              <td className="nowrap">
                <DigestCell artifact={a} />
              </td>
              <td className="break">{a.detail || <span className="subtle">{DASH}</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ReportView({ report }: { report: VerificationReport }) {
  const source = report.source;
  return (
    <div className="report stack stack--tight">
      <Summary report={report} />
      {report.report_version !== null && report.report_version !== REPORT_VERSION ? (
        <Callout tone="warn">
          This report has report_version {report.report_version}; this console was built for version {REPORT_VERSION} and
          may not show every field.
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

      <section className="subsection">
        <h3>Checks</h3>
        <ChecksTable checks={report.checks} />
      </section>
      <section className="subsection">
        <h3>Signatures</h3>
        <SignaturesTable report={report} />
      </section>
      <section className="subsection">
        <h3>Artifacts</h3>
        <ArtifactsTable artifacts={report.artifacts} />
      </section>
      <section className="subsection">
        <h3>Report details</h3>
        <DefList
          wide
          items={[
            ['Bundle id', report.bundle_id ? <Digest value={report.bundle_id} label="bundle id" full /> : null],
            ['Bundle created', report.bundle?.created_at ? <Time value={report.bundle.created_at} exact /> : null],
            [
              'Source',
              source?.name ? (
                <span>
                  <code>{source.name}</code>
                  <span className="subtle">
                    {source.type ? ` · ${source.type}` : ''}
                    {source.size !== null ? ` · ${formatBytes(source.size)}` : ''}
                  </span>
                </span>
              ) : null,
            ],
            ['Verified', report.verified_at ? <Time value={report.verified_at} exact /> : null],
            ['Ferry version', report.tool_version],
            ['Report version', report.report_version !== null ? String(report.report_version) : null],
          ]}
        />
        {report.policy && Object.keys(report.policy).length ? (
          <div className="subsection">
            <h4>Import policy applied</h4>
            <ObjectTable value={report.policy} caption="Import policy applied" />
          </div>
        ) : null}
      </section>
    </div>
  );
}
