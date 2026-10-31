/**
 * The verification report read as a checklist: every check in the order it
 * ran (name verbatim, stamped with its result, message one click away), and
 * a summary that confirms verdict, checks, signatures and artifacts against
 * the counts the report itself carries. Used by bundle and verification
 * detail; the full report tables stay in ReportView.
 */

import { useId, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import type { ReportCheck, VerificationReport } from '../../api.ts';
import { formatInt, plural } from '../../format.ts';
import { statusLabel, toneFor, type StatusDomain } from '../../status.ts';
import { Checklist, ChecklistLine } from '@/components/console/checklist.tsx';
import { IconButton } from '@/components/console/icon-button.tsx';
import { toneToStamp, type StampState } from '@/components/console/stamp.tsx';
import { cn } from '@/lib/utils';

export function stampFor(domain: StatusDomain, value: string | null | undefined): StampState {
  return toneToStamp(toneFor(domain, value));
}

function CheckLine({ check, index }: { check: ReportCheck; index: number }) {
  const detailId = useId();
  const failing = check.status === 'fail' || check.status === 'warn';
  const [open, setOpen] = useState(failing);
  const hasMessage = check.message.trim() !== '';
  return (
    <ChecklistLine
      label={
        <span className="inline-flex items-baseline gap-2">
          <span className="w-5 shrink-0 text-right text-xs text-text-3 tabular-nums">{formatInt(index + 1)}</span>
          <code className="font-mono text-xs [overflow-wrap:anywhere]">{check.id}</code>
        </span>
      }
      state={stampFor('check', check.status)}
      stamp={statusLabel(check.status)}
      action={
        hasMessage ? (
          <IconButton
            label={`${open ? 'Hide' : 'Show'} the message for ${check.id}`}
            size="sm"
            aria-expanded={open}
            aria-controls={detailId}
            onClick={() => setOpen((v) => !v)}
            noTooltip
          >
            <ChevronDown aria-hidden="true" className={cn('size-3.5 transition-transform duration-150 ease-out motion-reduce:transition-none', open && 'rotate-180')} />
          </IconButton>
        ) : (
          <span aria-hidden="true" className="inline-block size-7" />
        )
      }
      detail={hasMessage && open ? <span id={detailId} className="text-text-2">{check.message}</span> : undefined}
    />
  );
}

/** Every check in the order it ran. */
export function CheckChecklist({
  checks,
  label = 'Checks, in the order they ran',
  columns = false,
}: {
  checks: readonly ReportCheck[];
  /** Visible caps label; null when the panel title already names the list. */
  label?: string | null;
  columns?: boolean;
}) {
  const passed = checks.filter((c) => c.status === 'pass').length;
  if (checks.length === 0) {
    return <p className="text-sm text-text-2">The report lists no checks.</p>;
  }
  return (
    <Checklist
      label={label ?? undefined}
      summary={`${formatInt(passed)} of ${formatInt(checks.length)} passed`}
      ariaLabel={label ?? 'Checks, in the order they ran'}
      listClassName={columns ? 'lg:columns-2 lg:gap-x-8 lg:divide-y-0 [&>li]:break-inside-avoid lg:[&>li]:border-b lg:[&>li]:border-hairline' : undefined}
    >
      {checks.map((c, i) => (
        <CheckLine key={`${c.id}-${i}`} check={c} index={i} />
      ))}
    </Checklist>
  );
}

function count<T>(items: readonly T[], test: (item: T) => boolean): number {
  return items.filter(test).length;
}

/** Verdict, checks, signatures, artifacts and warnings, each confirmed from the report. */
export function ReportSummaryChecklist({ report, label }: { report: VerificationReport; label?: string }) {
  const checksFailed = count(report.checks, (c) => c.status === 'fail');
  const checksPassed = count(report.checks, (c) => c.status === 'pass');
  const sigValid = count(report.signatures, (s) => s.status === 'valid');
  const sigBad = count(report.signatures, (s) => toneFor('signature', s.status) === 'bad');
  const artOk = count(report.artifacts, (a) => a.status === 'ok');
  const artBad = count(report.artifacts, (a) => toneFor('artifact', a.status) === 'bad');
  const verdictState = stampFor('verdict', report.verdict);
  return (
    <Checklist label={label} ariaLabel={label ?? 'Verification summary'}>
      <ChecklistLine label="Verdict" state={verdictState} stamp={statusLabel(report.verdict)} detail={report.errors[0]} />
      <ChecklistLine
        label="Checks passed"
        state={report.checks.length === 0 ? 'neutral' : checksFailed ? 'failed' : 'confirmed'}
        value={`${formatInt(checksPassed)} of ${formatInt(report.checks.length)}`}
        stamp={report.checks.length === 0 ? 'None listed' : checksFailed ? `${formatInt(checksFailed)} failed` : 'Passed'}
      />
      <ChecklistLine
        label="Valid signatures"
        state={report.signatures.length === 0 ? 'neutral' : sigBad ? 'failed' : sigValid === report.signatures.length ? 'confirmed' : 'warning'}
        value={`${formatInt(sigValid)} of ${formatInt(report.signatures.length)}`}
        stamp={report.signatures.length === 0 ? 'None read' : sigBad ? `${formatInt(sigBad)} rejected` : sigValid === report.signatures.length ? 'Valid' : 'Review'}
      />
      <ChecklistLine
        label="Artifacts matching the manifest"
        state={report.artifacts.length === 0 ? 'neutral' : artBad ? 'failed' : 'confirmed'}
        value={`${formatInt(artOk)} of ${formatInt(report.artifacts.length)}`}
        stamp={report.artifacts.length === 0 ? 'None listed' : artBad ? `${formatInt(artBad)} failed` : 'Match'}
      />
      <ChecklistLine
        label="Warnings"
        state={report.warnings.length ? 'warning' : 'confirmed'}
        value={formatInt(report.warnings.length)}
        stamp={report.warnings.length ? plural(report.warnings.length, 'warning') : 'None'}
      />
    </Checklist>
  );
}
