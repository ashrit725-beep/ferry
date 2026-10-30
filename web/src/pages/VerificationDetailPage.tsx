/**
 * One recorded verification or import attempt and its full report.
 */

import { api, type VerificationRecord } from '../api.ts';
import { formatInt } from '../format.ts';
import { useResource } from '../hooks.ts';
import { BUNDLE_ID, paths, toHash } from '../router.ts';
import { Digest } from '../components/Digest.tsx';
import { DefList, PageHeader, Panel } from '../components/Panel.tsx';
import { ReportView } from '../components/ReportView.tsx';
import { Async } from '../components/States.tsx';
import { StatusBadge } from '../components/StatusBadge.tsx';
import { Time } from '../components/Time.tsx';

const CRUMBS = [{ label: 'Bundles', href: toHash(paths.bundles) }];

export function VerificationDetailPage({ id }: { id: number }) {
  const record = useResource((s) => api.verification(id, s), [id]);
  const v = record.data;
  return (
    <>
      <PageHeader
        breadcrumb={CRUMBS}
        title={`Verification #${id}`}
        meta={
          v ? (
            <>
              {v.mode === 'import' ? 'Import' : 'Verification'} of <code>{v.source_name}</code>, recorded <Time value={v.created_at} />
            </>
          ) : null
        }
      />
      <Async resource={record} loadingLabel="Loading the verification…" errorTitle="Could not load this verification.">
        {(data) => <RecordBody record={data} />}
      </Async>
    </>
  );
}

function RecordBody({ record: v }: { record: VerificationRecord }) {
  // Only an accepted import has a bundle page; a verification alone stores nothing.
  const bundleHref =
    v.mode === 'import' && v.verdict === 'accepted' && v.bundle_id && BUNDLE_ID.test(v.bundle_id)
      ? toHash(paths.bundle(v.bundle_id))
      : null;
  return (
    <div className="stack">
      <Panel title="Record">
        <DefList
          wide
          items={[
            ['Verdict', <StatusBadge domain="verdict" value={v.verdict} />],
            ['Mode', <span className="tag">{v.mode}</span>],
            ['Source', <code>{v.source_name}</code>],
            [
              'Bundle',
              v.bundle_name ? (
                <span>
                  {v.bundle_name} <span className="mono">{v.bundle_version ?? ''}</span>
                  {bundleHref ? (
                    <>
                      {' · '}
                      <a href={bundleHref}>open imported bundle</a>
                    </>
                  ) : null}
                </span>
              ) : (
                <span className="subtle">the manifest could not be read</span>
              ),
            ],
            ['Bundle id', v.bundle_id ? <Digest value={v.bundle_id} label="bundle id" full /> : null],
            ['Recorded', <Time value={v.created_at} exact />],
            ['Actor', v.actor],
            ['Errors', <span className="num">{formatInt(v.error_count)}</span>],
            ['Warnings', <span className="num">{formatInt(v.warning_count)}</span>],
          ]}
        />
      </Panel>
      <Panel title="Report">
        <ReportView report={v.report} />
      </Panel>
    </div>
  );
}
