/**
 * The crossing: the bundle lifecycle as the Overview's hero band, the page's
 * one focal element (hero scale: 48 px mono counts, 14 px tracked-caps stage
 * labels, a 4 px baseline). Two upstream stages (PACKED, SIGNED) sit muted
 * under "Connected side": this server never sees them happen, so they carry no
 * count. A wide break in the baseline marks the air gap, set as a marker of its
 * own ("Air gap" tag on the line, "reviewed transfer" under it); bundles
 * waiting in the inbox show there in amber. Then three enclave stages with real
 * counts: VERIFIED (imported bundles, each passed the fail-closed checks),
 * IMPORTED (model artifacts in the store) and SERVING (routes available with
 * verified provenance). A stage with a count of 0 is drawn unreached. The
 * one-way beam (CrossingBeam) runs across the gap once on mount and when a
 * count changes, passing behind the air-gap tag. Under 768 px the band becomes
 * a vertical list with the gap as a break.
 */

import { formatInt } from '../../format.ts';
import { CrossingBeam } from '../fx/stage-beam.tsx';
import { cn } from '@/lib/utils';

export interface LifecycleStripProps {
  /** Imported bundles (each passed verification). */
  verified: number;
  /** Model artifacts in the store. */
  imported: number;
  /** Routes available with verified provenance. */
  serving: number;
  /** Bundles waiting in the inbox, on the transfer side of the gap. */
  inboxPending: number;
  /** Where the inbox marker links. */
  inboxHref: string;
  label?: string;
  className?: string;
}

interface UpstreamStage {
  id: string;
  label: string;
  caption: string;
}

interface EnclaveStage {
  id: string;
  label: string;
  count: number;
  caption: string;
}

const UPSTREAM: readonly UpstreamStage[] = [
  { id: 'packed', label: 'Packed', caption: 'model files and manifest' },
  { id: 'signed', label: 'Signed', caption: 'publisher and reviewer' },
];

/*
 * Geometry (desktop), from the top of each stage list: label 20 px, 12 px air,
 * a 24 px marker (centre at 44 px), so the 4 px baseline sits at 42 px.
 */
// The hero scale (14 px, 0.16em) needs the room of a 1280 px window; below that the
// labels step down to 12 px at 0.12em so neighbours keep at least 16 px between them.
const STAGE_LABEL = 'h-5 text-xs leading-5 font-semibold tracking-[0.12em] uppercase whitespace-nowrap font-stretch-[112%] xl:text-sm xl:tracking-[0.16em]';
const GROUP_CAPTION = 'mb-3 h-6 text-2xs leading-6 font-medium tracking-[0.14em] text-text-3 uppercase';
const BASELINE = 'absolute top-[42px] h-1';
const AIR_GAP_TAG =
  'inline-flex h-6 items-center gap-1.5 rounded-sm border border-leader bg-ground px-2 text-2xs font-semibold tracking-[0.16em] text-bone uppercase whitespace-nowrap';

function Marker({ reached, muted = false }: { reached: boolean; muted?: boolean }) {
  return (
    <span
      data-stage-marker=""
      aria-hidden="true"
      className={cn(
        'relative z-10 mt-3 block size-6 shrink-0 rounded-full border-[3px]',
        reached ? 'border-ok bg-ok' : 'bg-ground',
        !reached && (muted ? 'border-text-3' : 'border-leader'),
      )}
    />
  );
}

function Diamond() {
  return <span aria-hidden="true" className="size-2 shrink-0 rotate-45 bg-amber" />;
}

export function LifecycleStrip({ verified, imported, serving, inboxPending, inboxHref, label = 'Bundle lifecycle', className }: LifecycleStripProps) {
  const enclave: EnclaveStage[] = [
    { id: 'verified', label: 'Verified', count: verified, caption: verified === 1 ? 'bundle passed verification' : 'bundles passed verification' },
    { id: 'imported', label: 'Imported', count: imported, caption: imported === 1 ? 'model file in the store' : 'model files in the store' },
    { id: 'serving', label: 'Serving', count: serving, caption: serving === 1 ? 'route serving' : 'routes serving' },
  ];
  const lastReached = enclave.reduce((acc, stage, i) => (stage.count > 0 ? i : acc), -1);
  // Beam target, in marker order: 0-1 upstream, 2-4 enclave.
  const beamTo = lastReached >= 0 ? UPSTREAM.length + lastReached : null;
  const runKey = `${verified}:${imported}:${serving}`;
  const waiting = inboxPending > 0;
  const crossed = verified > 0;

  const inboxMarker = waiting ? (
    <a href={inboxHref} className="rounded-sm text-xs font-medium text-amber underline-offset-3 hover:underline">
      <span className="font-mono tabular-nums">{formatInt(inboxPending)}</span> waiting in the inbox
    </a>
  ) : null;

  return (
    <div role="group" aria-label={label} className={cn('min-w-0', className)}>
      {/* 768 px and wider: one baseline, broken by the air gap. */}
      <div className="relative hidden py-2 md:flex">
        <div className="min-w-0 flex-[1.6] xl:flex-[2]">
          <p className={cn(GROUP_CAPTION, 'text-center')}>Connected side</p>
          <ol aria-label="Connected side" className="relative m-0 grid list-none grid-cols-2 p-0">
            <span aria-hidden="true" className={cn(BASELINE, 'right-0 left-1/4 bg-leader')} />
            {UPSTREAM.map((stage) => (
              <li key={stage.id} className="relative flex min-w-0 flex-col items-center px-2 text-center">
                <span className={cn(STAGE_LABEL, 'text-text-2')}>{stage.label}</span>
                <Marker reached={false} muted />
                <span className="mt-3 flex h-14 items-center text-xs text-text-3 text-balance">{stage.caption}</span>
                <span className="sr-only">, outside this server.</span>
              </li>
            ))}
          </ol>
        </div>

        <div className="flex w-52 shrink-0 flex-col items-center xl:w-72">
          <span aria-hidden="true" className="mb-3 h-6" />
          <span className="relative flex h-14 w-full items-start justify-center">
            <span aria-hidden="true" className={cn(BASELINE, 'left-0 w-10 bg-leader')} />
            <span aria-hidden="true" className="absolute top-[30px] left-10 h-7 w-0.5 bg-text-2" />
            <span aria-hidden="true" className={cn(BASELINE, 'right-0 w-10', crossed ? 'bg-ok/70' : 'bg-hairline')} />
            <span aria-hidden="true" className="absolute top-[30px] right-10 h-7 w-0.5 bg-text-2" />
            <span className={cn(AIR_GAP_TAG, 'relative z-20 mt-8', waiting && 'border-amber/70')}>
              {waiting ? <Diamond /> : null}
              Air gap
            </span>
          </span>
          <p className="mt-3 text-center text-xs whitespace-nowrap text-text-2">
            <span className="sr-only">Air gap · </span>reviewed transfer
          </p>
          {inboxMarker ? <p className="mt-1 text-center">{inboxMarker}</p> : null}
        </div>

        <div className="min-w-0 flex-[3]">
          <p className={cn(GROUP_CAPTION, 'text-center')}>This enclave</p>
          <ol aria-label="This enclave" className="relative m-0 grid list-none grid-cols-3 p-0">
            <span aria-hidden="true" className={cn(BASELINE, 'right-1/6 left-0 bg-hairline')} />
            {lastReached >= 0 ? (
              <span
                aria-hidden="true"
                className={cn(BASELINE, 'left-0 bg-ok/70', lastReached === 0 ? 'right-5/6' : lastReached === 1 ? 'right-1/2' : 'right-1/6')}
              />
            ) : null}
            {enclave.map((stage) => (
              <EnclaveItem key={stage.id} stage={stage} />
            ))}
          </ol>
        </div>

        <CrossingBeam to={beamTo} runKey={runKey} />
      </div>

      {/* Under 768 px: a vertical list, the gap as a horizontal break. */}
      <div className="flex flex-col md:hidden">
        <p className="text-2xs font-medium tracking-[0.14em] text-text-3 uppercase">Connected side</p>
        <ol aria-label="Connected side" className="m-0 list-none p-0">
          {UPSTREAM.map((stage) => (
            <li key={stage.id} className="flex min-h-10 items-center gap-3">
              <span aria-hidden="true" className="size-4 shrink-0 rounded-full border-[3px] border-text-3 bg-ground" />
              <span className={cn(STAGE_LABEL, 'w-24 shrink-0 text-text-2')}>{stage.label}</span>
              <span className="min-w-0 text-xs text-text-3">{stage.caption}</span>
            </li>
          ))}
        </ol>
        <div className="my-2 flex flex-col gap-1.5 border-y border-dashed border-leader py-3">
          <p className="flex flex-wrap items-center gap-2">
            <span className={cn(AIR_GAP_TAG, waiting && 'border-amber/70')}>
              {waiting ? <Diamond /> : null}
              Air gap
            </span>
            <span className="text-xs text-text-2">
              <span className="sr-only">· </span>reviewed transfer
            </span>
          </p>
          {inboxMarker ? <p>{inboxMarker}</p> : null}
        </div>
        <p className="text-2xs font-medium tracking-[0.14em] text-text-3 uppercase">This enclave</p>
        <ol aria-label="This enclave" className="m-0 list-none p-0">
          {enclave.map((stage) => (
            <li key={stage.id} className="flex min-h-12 items-center gap-3">
              <span aria-hidden="true" className={cn('size-4 shrink-0 rounded-full border-[3px]', stage.count > 0 ? 'border-ok bg-ok' : 'border-leader bg-ground')} />
              <span className={cn(STAGE_LABEL, 'w-24 shrink-0', stage.count > 0 ? 'text-bone' : 'text-text-3')}>{stage.label}</span>
              <span className={cn('ml-auto font-mono text-2xl font-medium tabular-nums', stage.count > 0 ? 'text-bone' : 'text-text-3')}>{formatInt(stage.count)}</span>
              <span className="w-36 shrink-0 text-xs text-text-3">{stage.caption}</span>
              <span className="sr-only">{stage.count > 0 ? ', reached.' : ', not reached.'}</span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function EnclaveItem({ stage }: { stage: EnclaveStage }) {
  const reached = stage.count > 0;
  return (
    <li className="relative flex min-w-0 flex-col items-center px-2 text-center">
      <span className={cn(STAGE_LABEL, reached ? 'text-bone' : 'text-text-3')}>{stage.label}</span>
      <Marker reached={reached} />
      <span className={cn('mt-3 font-mono text-[2.5rem] leading-[3.5rem] font-medium tracking-[-0.02em] tabular-nums lg:text-[3rem]', reached ? 'text-bone' : 'text-text-3')}>
        {formatInt(stage.count)}
      </span>
      <span className="max-w-44 text-xs text-text-2 text-balance">{stage.caption}</span>
      <span className="sr-only">{reached ? ', reached.' : ', not reached.'}</span>
    </li>
  );
}
