/**
 * Route map: how a request travels, drawn as a transit diagram. Every route
 * is a line from the apps (through the gateway) to its public model name, its
 * backend and, when pinned, the imported file. Shared stations are
 * interchanges. Lines carry the route's provenance (colour, dash pattern and
 * word), backend stations their health (ring colour and word).
 *
 * Plain SVG, no dependency beyond motion. The diagram is decorative for
 * assistive technology: the same facts are a checklist beside it at wide
 * widths, and a stacked strip list (one vertical line per route) at narrow
 * widths. The only motion is a one-way reveal on first draw, 240 ms, none
 * under reduced motion; refreshes never redraw it.
 */

import { motion, useReducedMotion } from 'motion/react';
import type { Backend, ModelArtifact, ModelRoute } from '../../api.ts';
import { shortDigest } from '../../format.ts';
import type { Resource } from '../../hooks.ts';
import type { Tone } from '../../status.ts';
import { Checklist, ChecklistLine } from '../../components/console/checklist.tsx';
import { Digest } from '../../components/console/digest.tsx';
import { Section } from '../../components/console/section.tsx';
import { Stamp } from '../../components/console/stamp.tsx';
import { EmptyState, ErrorState, PanelSkeleton } from '../../components/console/states.tsx';
import { presets } from '@/lib/motion';
import { cn } from '@/lib/utils';
import { availabilityWord, healthWord, provenanceWord, type StateWord } from './parts.tsx';

const STROKE: Record<Tone, string> = {
  ok: 'stroke-ok',
  warn: 'stroke-amber',
  bad: 'stroke-bad',
  info: 'stroke-info',
  neutral: 'stroke-neutral',
};
const FILL: Record<Tone, string> = {
  ok: 'fill-ok',
  warn: 'fill-amber',
  bad: 'fill-bad',
  info: 'fill-info',
  neutral: 'fill-neutral',
};
const BORDER: Record<Tone, string> = {
  ok: 'border-ok',
  warn: 'border-amber',
  bad: 'border-bad',
  info: 'border-info',
  neutral: 'border-neutral',
};

/** Line pattern per state, so the state reads without colour. */
type LineKind = 'verified' | 'attention' | 'failed' | 'unknown' | 'disabled';
const DASH: Record<LineKind, string | undefined> = {
  verified: undefined,
  attention: '9 5',
  failed: '1 6',
  unknown: '12 4 2 4',
  disabled: '2 7',
};
const BORDER_STYLE: Record<LineKind, string> = {
  verified: 'border-solid',
  attention: 'border-dashed',
  failed: 'border-dotted',
  unknown: 'border-dashed',
  disabled: 'border-dotted',
};
const LEGEND: ReadonlyArray<{ kind: LineKind; tone: Tone; word: string }> = [
  { kind: 'verified', tone: 'ok', word: 'verified' },
  { kind: 'attention', tone: 'warn', word: 'unverified or not pinned' },
  { kind: 'failed', tone: 'bad', word: 'mismatch' },
  { kind: 'unknown', tone: 'neutral', word: 'unknown' },
  { kind: 'disabled', tone: 'neutral', word: 'route disabled' },
];

interface Line {
  route: ModelRoute;
  row: number;
  tone: Tone;
  kind: LineKind;
  provenance: StateWord;
  backendKey: string;
  artifactKey: string | null;
}

interface Station {
  key: string;
  label: string;
  title: string;
  sub: string;
  subTone: Tone | null;
  subMono: boolean;
  ringTone: Tone | 'bone';
  row: number;
  lines: number[];
}

const W = 1100;
const COL = { gateway: 48, route: 250, backend: 590, artifact: 890 } as const;
const ROW_H = 60;
const TOP = 76;
const LANE = 5;

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function lineOf(route: ModelRoute, row: number): Line {
  const provenance = provenanceWord(route);
  const tone: Tone = route.enabled ? provenance.tone : 'neutral';
  const kind: LineKind = !route.enabled
    ? 'disabled'
    : provenance.tone === 'ok'
      ? 'verified'
      : provenance.tone === 'bad'
        ? 'failed'
        : provenance.tone === 'warn'
          ? 'attention'
          : 'unknown';
  return {
    route,
    row,
    tone,
    kind,
    provenance,
    backendKey: `b${route.backend_id}`,
    artifactKey: route.artifact_digest ? `a${route.artifact_digest}` : null,
  };
}

/** Place stations near the mean row of their lines, keeping one per row. */
function placeRows(stations: Station[], lines: readonly Line[]): Station[] {
  const desired = (s: Station): number =>
    s.lines.length ? s.lines.reduce((sum, i) => sum + (lines[i]?.row ?? 0), 0) / s.lines.length : Number.POSITIVE_INFINITY;
  const ordered = stations.toSorted((a, b) => desired(a) - desired(b));
  let next = 0;
  return ordered.map((s) => {
    const want = desired(s);
    const row = Number.isFinite(want) ? Math.max(next, Math.round(want)) : next;
    next = row + 1;
    return { ...s, row };
  });
}

function backendStations(lines: readonly Line[], backends: readonly Backend[]): Station[] {
  const byKey = new Map<string, Station>();
  const health = (b: Backend | undefined): StateWord => (b ? healthWord(b) : { tone: 'neutral', state: 'neutral', word: 'unknown' });
  for (const b of backends) {
    const h = health(b);
    byKey.set(`b${b.id}`, {
      key: `b${b.id}`,
      label: clip(b.name, 30),
      title: `${b.name} (${b.kind}) ${b.base_url}`,
      sub: b.enabled ? h.word : `${h.word} · disabled`,
      subTone: h.tone,
      subMono: false,
      ringTone: h.tone,
      row: 0,
      lines: [],
    });
  }
  lines.forEach((line, i) => {
    let station = byKey.get(line.backendKey);
    if (!station) {
      const name = line.route.backend_name || `#${line.route.backend_id}`;
      station = { key: line.backendKey, label: clip(name, 30), title: name, sub: 'unknown', subTone: 'neutral', subMono: false, ringTone: 'neutral', row: 0, lines: [] };
      byKey.set(line.backendKey, station);
    }
    station.lines.push(i);
  });
  return placeRows([...byKey.values()], lines);
}

function artifactStations(lines: readonly Line[], models: readonly ModelArtifact[]): Station[] {
  const byKey = new Map<string, Station>();
  const make = (digest: string, model: ModelArtifact | undefined): Station => ({
    key: `a${digest}`,
    label: clip(model ? (model.model_name ?? 'unnamed') : 'not among imported files', 30),
    title: model ? `${model.model_name ?? 'unnamed'} · ${model.format} ${digest}` : digest,
    sub: model ? `${model.format} · ${shortDigest(digest)}` : shortDigest(digest),
    subTone: null,
    subMono: true,
    ringTone: 'bone',
    row: 0,
    lines: [],
  });
  for (const m of models) byKey.set(`a${m.digest}`, make(m.digest, m));
  lines.forEach((line, i) => {
    if (!line.artifactKey || !line.route.artifact_digest) return;
    let station = byKey.get(line.artifactKey);
    if (!station) {
      station = make(line.route.artifact_digest, undefined);
      byKey.set(line.artifactKey, station);
    }
    station.lines.push(i);
  });
  return placeRows([...byKey.values()], lines);
}

const y = (row: number): number => TOP + row * ROW_H;

/** Offset of line `i` inside a station that `lines` pass through. */
function lane(lines: readonly number[], i: number, spacing = LANE): number {
  const index = lines.indexOf(i);
  if (index < 0 || lines.length < 2) return 0;
  return (index - (lines.length - 1) / 2) * spacing;
}

/** Horizontal, one diagonal in the middle of the gap, horizontal: the transit-map bend. */
function segment(x0: number, y0: number, x1: number, y1: number): string {
  if (Math.abs(y1 - y0) < 0.5) return `M ${x0} ${y0} H ${x1}`;
  const gap = x1 - x0;
  const diag = Math.min(Math.abs(y1 - y0), gap * 0.4);
  const xm = (x0 + x1) / 2;
  return `M ${x0} ${y0} H ${xm - diag / 2} L ${xm + diag / 2} ${y1} H ${x1}`;
}

function StationMark({ x, cy, count, ring, spacing = LANE }: { x: number; cy: number; count: number; ring: Tone | 'bone'; spacing?: number }) {
  const span = Math.max(0, count - 1) * spacing;
  const h = span + 16;
  const interchange = count > 1;
  return (
    <rect
      x={x - 8}
      y={cy - h / 2}
      width={16}
      height={h}
      rx={8}
      strokeWidth={3}
      className={cn('transition-[stroke] duration-200 ease-out', interchange ? 'fill-raised' : 'fill-panel', ring === 'bone' ? 'stroke-bone' : STROKE[ring])}
    />
  );
}

/** Station labels are names (mono) except these fallback words. */
const PROSE_LABELS: ReadonlySet<string> = new Set(['unnamed', 'not among imported files']);

function StationLabel({ x, top, bottom, station }: { x: number; top: number; bottom: number; station: Station }) {
  return (
    <g>
      <title>{station.title}</title>
      <text
        x={x - 8}
        y={top - 7}
        className={cn('fill-bone stroke-panel text-[12px] [paint-order:stroke] [stroke-width:4px]', PROSE_LABELS.has(station.label) ? 'font-sans' : 'font-mono')}
      >
        {station.label}
      </text>
      <text
        x={x - 8}
        y={bottom + 15}
        className={cn(
          'stroke-panel [paint-order:stroke] [stroke-width:4px]',
          station.subMono ? 'font-mono text-[11px] fill-text-2' : 'font-sans text-[10px] font-medium tracking-[0.08em] uppercase',
          !station.subMono && (station.subTone ? FILL[station.subTone] : 'fill-text-2'),
        )}
      >
        {station.sub}
      </text>
    </g>
  );
}

function MapSvg({ lines, backends, artifacts }: { lines: readonly Line[]; backends: readonly Station[]; artifacts: readonly Station[] }) {
  const reduce = useReducedMotion();
  const rows = Math.max(lines.length, ...backends.map((s) => s.row + 1), ...artifacts.map((s) => s.row + 1), 1);
  const height = y(rows - 1) + 48;
  const gatewayRow = (Math.max(lines.length, 1) - 1) / 2;
  const allLines = lines.map((_, i) => i);
  const gatewaySpacing = Math.min(LANE, 40 / Math.max(lines.length, 1));
  const backendBy = new Map(backends.map((s) => [s.key, s]));
  const artifactBy = new Map(artifacts.map((s) => [s.key, s]));

  const columns: ReadonlyArray<readonly [number, string]> = [
    [COL.gateway, 'Gateway'],
    [COL.route, 'Public model name'],
    [COL.backend, 'Backend'],
    [COL.artifact, 'Imported file'],
  ];

  const gy = y(gatewayRow);
  const gatewaySpan = Math.max(0, lines.length - 1) * gatewaySpacing + 16;

  return (
    <svg viewBox={`0 0 ${W} ${height}`} className="block h-auto w-full" aria-hidden="true" focusable="false">
      {columns.map(([x, label]) => (
        <text key={label} x={x - 8} y={24} className="fill-text-2 text-[12px] font-medium">
          {label}
        </text>
      ))}
      <line x1={0} x2={W} y1={36} y2={36} strokeWidth={1} className="stroke-hairline" />
      <motion.g initial={reduce ? false : { clipPath: 'inset(0 100% 0 0)' }} animate={{ clipPath: 'inset(0 0% 0 0)' }} transition={presets.confirm}>
        {lines.map((line, i) => {
          const backend = backendBy.get(line.backendKey);
          const artifact = line.artifactKey ? artifactBy.get(line.artifactKey) : undefined;
          const y0 = gy + lane(allLines, i, gatewaySpacing);
          const yr = y(line.row);
          const yb = backend ? y(backend.row) + lane(backend.lines, i) : yr;
          let d = segment(COL.gateway, y0, COL.route, yr) + ' ' + segment(COL.route, yr, COL.backend, yb);
          if (artifact) d += ' ' + segment(COL.backend, yb, COL.artifact, y(artifact.row) + lane(artifact.lines, i));
          return (
            <g key={line.route.id}>
              <path d={d} fill="none" strokeWidth={8} strokeLinejoin="round" className="stroke-panel" />
              <path
                d={d}
                fill="none"
                strokeWidth={4}
                strokeLinejoin="round"
                strokeLinecap="round"
                strokeDasharray={DASH[line.kind]}
                className={cn('transition-[stroke] duration-200 ease-out', STROKE[line.tone])}
              />
              {!artifact ? <line x1={COL.backend + 14} x2={COL.backend + 14} y1={yb - 7} y2={yb + 7} strokeWidth={3} strokeLinecap="round" className={STROKE[line.tone]} /> : null}
            </g>
          );
        })}

        <rect x={COL.gateway - 8} y={gy - gatewaySpan / 2} width={16} height={gatewaySpan} rx={8} strokeWidth={3} className="fill-raised stroke-bone" />
        <text x={COL.gateway - 8} y={gy - gatewaySpan / 2 - 7} className="fill-bone stroke-panel text-[12px] [paint-order:stroke] [stroke-width:4px]">
          Apps
        </text>
        <text x={COL.gateway - 8} y={gy + gatewaySpan / 2 + 15} className="fill-text-2 stroke-panel text-[10px] font-medium tracking-[0.08em] uppercase [paint-order:stroke] [stroke-width:4px]">
          by name
        </text>

        {lines.map((line) => {
          const cy = y(line.row);
          const station: Station = {
            key: `r${line.route.id}`,
            label: clip(line.route.model, 28),
            title: `${line.route.model}: ${line.provenance.word}`,
            sub: line.route.enabled ? line.provenance.word : `${line.provenance.word} · disabled`,
            subTone: line.tone,
            subMono: false,
            ringTone: line.tone,
            row: line.row,
            lines: [],
          };
          return (
            <g key={`r${line.route.id}`}>
              <StationMark x={COL.route} cy={cy} count={1} ring={line.tone} />
              <StationLabel x={COL.route} top={cy - 8} bottom={cy + 8} station={station} />
            </g>
          );
        })}

        {[...backends, ...artifacts].map((s) => {
          const x = s.key.startsWith('b') ? COL.backend : COL.artifact;
          const cy = y(s.row);
          const h = Math.max(0, s.lines.length - 1) * LANE + 16;
          return (
            <g key={s.key} className={s.lines.length === 0 ? 'opacity-60' : undefined}>
              <StationMark x={x} cy={cy} count={s.lines.length} ring={s.ringTone} />
              <StationLabel x={x} top={cy - h / 2} bottom={cy + h / 2} station={s} />
            </g>
          );
        })}
      </motion.g>
    </svg>
  );
}

function Legend() {
  return (
    <ul aria-hidden="true" className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-hairline px-3 py-2 text-xs text-text-2">
      {LEGEND.map((item) => (
        <li key={item.kind} className="flex items-center gap-2">
          <svg viewBox="0 0 32 8" className="h-2 w-8" focusable="false">
            <line x1={2} x2={30} y1={4} y2={4} strokeWidth={4} strokeLinecap="round" strokeDasharray={DASH[item.kind]} className={STROKE[item.tone]} />
          </svg>
          {item.word}
        </li>
      ))}
      <li className="flex items-center gap-2">
        <svg viewBox="0 0 24 16" className="h-4 w-6" focusable="false">
          <rect x={4} y={2} width={16} height={12} rx={6} strokeWidth={2.5} className="fill-raised stroke-bone" />
        </svg>
        interchange: a shared backend or file
      </li>
    </ul>
  );
}

function artifactName(digest: string, models: readonly ModelArtifact[]): string {
  const m = models.find((a) => a.digest === digest);
  return m ? (m.model_name ?? 'unnamed') : 'not among imported files';
}

/** The stacked form: one vertical line per route, stops top to bottom. */
function Strip({ line, backends, models }: { line: Line; backends: readonly Backend[]; models: readonly ModelArtifact[] }) {
  const r = line.route;
  const backend = backends.find((b) => b.id === r.backend_id);
  const health = backend ? healthWord(backend) : null;
  const availability = availabilityWord(r);
  const dot = cn('relative z-10 mt-1 size-3 shrink-0 rounded-full border-2 bg-panel', BORDER[line.tone]);
  return (
    <li className="min-w-0 rounded-md bg-inset/60 px-3 py-2 ring-1 ring-hairline">
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 font-mono text-xs [overflow-wrap:anywhere] text-bone">{r.model}</span>
        <Stamp state={line.provenance.state} land={false}>
          {line.provenance.word}
        </Stamp>
        <Stamp state={availability.state} land={false}>
          {availability.word}
        </Stamp>
      </div>
      <ol className="relative mt-2 flex flex-col gap-2" aria-label={`Line ${r.model}`}>
        <span aria-hidden="true" className={cn('absolute top-2 bottom-2 left-[5px] border-l-[3px]', BORDER[line.tone], BORDER_STYLE[line.kind])} />
        <li className="flex items-start gap-3 text-xs text-text-2">
          <span aria-hidden="true" className={cn(dot, 'border-bone')} />
          <span>Apps, through the gateway, ask for this name</span>
        </li>
        <li className="flex items-start gap-3 text-xs">
          <span aria-hidden="true" className={dot} />
          <span className="min-w-0">
            <span className="text-text-2">Public model name </span>
            <span className="font-mono text-bone [overflow-wrap:anywhere]">{r.model}</span>
            {r.provenance.detail ? <span className="block text-text-2">{r.provenance.detail}</span> : null}
          </span>
        </li>
        <li className="flex items-start gap-3 text-xs">
          <span aria-hidden="true" className={cn(dot, health ? BORDER[health.tone] : 'border-neutral')} />
          <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-text-2">Backend</span>
            <span className="font-mono text-bone [overflow-wrap:anywhere]">{r.backend_name || `#${r.backend_id}`}</span>
            <Stamp state={health?.state ?? 'neutral'} land={false}>
              {health?.word ?? 'unknown'}
            </Stamp>
          </span>
        </li>
        <li className="flex items-start gap-3 text-xs">
          <span aria-hidden="true" className={cn(dot, r.artifact_digest ? 'border-bone' : 'border-neutral')} />
          {r.artifact_digest ? (
            <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
              <span className="text-text-2">Imported file</span>
              <span className="text-bone">{artifactName(r.artifact_digest, models)}</span>
              <Digest value={r.artifact_digest} label={`pinned digest of ${r.model}`} />
            </span>
          ) : (
            <span className="text-text-2">Not pinned: the line ends at the backend.</span>
          )}
        </li>
      </ol>
    </li>
  );
}

export function RouteMap({ routes, backends, models }: { routes: Resource<ModelRoute[]>; backends: readonly Backend[]; models: readonly ModelArtifact[] }) {
  const items = routes.data;
  const lines = (items ?? []).map((r, i) => lineOf(r, i));
  const verified = lines.filter((l) => l.provenance.tone === 'ok').length;
  const down = backends.filter((b) => healthWord(b).tone === 'bad').length;

  const summary = items ? (
    <span className="text-xs text-text-2 tabular-nums">
      {lines.length} {lines.length === 1 ? 'line' : 'lines'} · {verified} verified
      {down ? (
        <>
          {' · '}
          <span className="text-bad">{down} backend down</span>
        </>
      ) : null}
    </span>
  ) : null;

  let body;
  if (items === null) {
    body = routes.error ? <ErrorState error={routes.error} onRetry={routes.reload} title="Could not draw the route map." /> : <PanelSkeleton lines={4} />;
  } else if (lines.length === 0) {
    body = (
      <EmptyState title="No lines to draw yet.">
        Each route becomes a line from the apps to a backend and the imported file it pins. Add a backend, then a route that pins an imported model.
      </EmptyState>
    );
  } else {
    const backendSt = backendStations(lines, backends);
    const artifactSt = artifactStations(lines, models);
    body = (
      <>
        <div className="hidden xl:block">
          <div className="px-3 pt-2">
            <MapSvg lines={lines} backends={backendSt} artifacts={artifactSt} />
          </div>
          <Legend />
          <div className="border-t border-hairline px-3 py-3">
            <Checklist label="Line checks" ariaLabel="Route lines">
              {lines.map((line) => {
                const r = line.route;
                const availability = availabilityWord(r);
                const detail = [r.provenance.detail, !r.enabled ? 'Route disabled.' : !r.available && r.reason ? r.reason : null].filter(Boolean).join(' ');
                return (
                  <ChecklistLine
                    key={r.id}
                    label={<span className="font-mono text-xs">{r.model}</span>}
                    state={line.provenance.state}
                    stamp={line.provenance.word}
                    value={
                      <>
                        <span className="font-mono">{r.backend_name || `#${r.backend_id}`}</span>
                        {' → '}
                        {r.artifact_digest ? (
                          <>
                            {models.some((a) => a.digest === r.artifact_digest) ? (
                              <span className="font-mono">{artifactName(r.artifact_digest, models)}</span>
                            ) : (
                              artifactName(r.artifact_digest, models)
                            )}{' '}
                            <span className="font-mono">{shortDigest(r.artifact_digest)}</span>
                          </>
                        ) : (
                          'not pinned'
                        )}
                        {` · ${availability.word}`}
                      </>
                    }
                    detail={detail || undefined}
                    drawKey={r.provenance.state}
                  />
                );
              })}
            </Checklist>
          </div>
        </div>
        <ol aria-label="Route lines" className="grid grid-cols-1 gap-3 px-3 py-3 md:grid-cols-2 xl:hidden">
          {lines.map((line) => (
            <Strip key={line.route.id} line={line} backends={backends} models={models} />
          ))}
        </ol>
      </>
    );
  }

  return (
    <Section
      title="Route map"
      description="How a request travels: apps ask the gateway for a public model name, its route sends it to a backend, and a pinned route checks the backend serves the imported file. Lines show provenance, backend stations show health."
      actions={summary}
      flush
    >
      {body}
    </Section>
  );
}
