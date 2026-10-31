/**
 * One recorded verification or import attempt: the record, a checklist that
 * confirms verdict, checks, signatures and artifacts from the report, and
 * the full report.
 */

import { ArrowRight } from 'lucide-react';
import { api, type VerificationRecord } from '../api.ts';
import { formatInt } from '../format.ts';
import { useResource } from '../hooks.ts';
import { BUNDLE_ID, paths, toHash } from '../router.ts';
import { Digest } from '@/components/console/digest.tsx';
import { KeyValueList } from '@/components/console/key-value-list.tsx';
import { PageHeader } from '@/components/console/page-header.tsx';
import { ReportView } from '@/components/console/report-view.tsx';
import { Section } from '@/components/console/section.tsx';
import { Async, PanelSkeleton } from '@/components/console/states.tsx';
import { StatusBadge } from '@/components/console/status-badge.tsx';
import { Time } from '@/components/console/time.tsx';
import { buttonVariants } from '@/components/ui/button.tsx';
import { ReportSummaryChecklist } from './bundles/checks.tsx';

const CRUMBS = [{ label: 'Bundles', href: toHash(paths.bundles) }];

/** Only an accepted import has a bundle page; a verification alone stores nothing. */
function bundleHrefOf(v: VerificationRecord): string | null {
  return v.mode === 'import' && v.verdict === 'accepted' && v.bundle_id && BUNDLE_ID.test(v.bundle_id) ? toHash(paths.bundle(v.bundle_id)) : null;
}

export function VerificationDetailPage({ id }: { id: number }) {
  const record = useResource((s) => api.verification(id, s), [id]);
  const v = record.data;
  const bundleHref = v ? bundleHrefOf(v) : null;
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
        actions={
          bundleHref ? (
            <a
              href={bundleHref}
              className={buttonVariants({ variant: 'outline' })}
            >
              Open imported bundle
              <ArrowRight aria-hidden="true" className="size-4" />
            </a>
          ) : null
        }
      />
      <Async
        resource={record}
        loadingLabel="Loading the verification…"
        errorTitle="Could not load this verification."
        skeleton={
          <div className="flex flex-col gap-4">
            <p role="status" className="sr-only">
              Loading the verification…
            </p>
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-lg bg-panel ring-1 ring-hairline">
                <PanelSkeleton lines={6} />
              </div>
              <div className="rounded-lg bg-panel ring-1 ring-hairline">
                <PanelSkeleton lines={5} />
              </div>
            </div>
          </div>
        }
      >
        {(data) => <RecordBody record={data} />}
      </Async>
    </>
  );
}

function RecordBody({ record: v }: { record: VerificationRecord }) {
  const bundleHref = bundleHrefOf(v);
  const failed = v.verdict === 'rejected';
  return (
    <div className="flex flex-col gap-4">
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Section title="Record">
          <KeyValueList
            wide
            items={[
              ['Verdict', <StatusBadge domain="verdict" value={v.verdict} />],
              ['Mode', <span className="rounded-sm border border-hairline px-1 text-2xs text-text-2">{v.mode}</span>],
              ['Source', <code className="font-mono text-xs">{v.source_name}</code>],
              [
                'Bundle',
                v.bundle_name ? (
                  <span>
                    <span className="font-mono text-xs">
                      {v.bundle_name} {v.bundle_version ?? ''}
                    </span>
                    {bundleHref ? (
                      <>
                        {' · '}
                        <a href={bundleHref} className="rounded-sm text-bone underline decoration-text-3 underline-offset-3 hover:decoration-bone">
                          open imported bundle
                        </a>
                      </>
                    ) : null}
                  </span>
                ) : (
                  <span className="text-text-3">the manifest could not be read</span>
                ),
              ],
              ['Bundle id', v.bundle_id ? <Digest value={v.bundle_id} label="bundle id" full /> : null],
              ['Recorded', <Time value={v.created_at} exact />],
              ['Actor', v.actor],
              ['Errors', <span className="tabular-nums">{formatInt(v.error_count)}</span>],
              ['Warnings', <span className="tabular-nums">{formatInt(v.warning_count)}</span>],
            ]}
          />
        </Section>
        <Section title="Summary" description="Each line is read from the report below." attention={failed}>
          <ReportSummaryChecklist report={v.report} />
        </Section>
      </div>
      <Section title="Report">
        <ReportView report={v.report} />
      </Section>
    </div>
  );
}
