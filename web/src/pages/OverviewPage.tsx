/**
 * Overview: the state of this installation as reported by GET /api/overview.
 * Every figure on this page is a value from that response or plain
 * arithmetic on it (shares, success rate).
 */

import {
  api,
  type Attention,
  type Overview,
  type OverviewBackend,
  type OverviewPolicy,
  type OverviewRoute,
  type Traffic,
  type TrafficByEnvironment,
} from '../api.ts';
import { formatInt, formatMs, formatPercent } from '../format.ts';
import { useAutoRefresh, useResource } from '../hooks.ts';
import { environmentSegments, OUTCOME_TEXT, trafficSegments } from '../metrics.ts';
import { paths, safeInternalHref, toHash } from '../router.ts';
import { useSession } from '../session.tsx';
import { severityRank } from '../status.ts';
import { Digest } from '../components/Digest.tsx';
import { Callout, DefList, Figure, PageHeader, Panel, RefreshButton } from '../components/Panel.tsx';
import { ShareBar, Swatch } from '../components/ShareBar.tsx';
import { Async, EmptyState } from '../components/States.tsx';
import { StatusBadge } from '../components/StatusBadge.tsx';
import { Time } from '../components/Time.tsx';

const REFRESH_MS = 30_000;

export function OverviewPage() {
  const { isAdmin } = useSession();
  const overview = useResource((signal) => api.overview(signal), []);
  useAutoRefresh(overview.reload, REFRESH_MS);
  const data = overview.data;
  return (
    <>
      <PageHeader
        title="Overview"
        meta={
          data ? (
            <>
              Ferry {data.version} · server started <Time value={data.started_at} /> · updates every 30 s
            </>
          ) : null
        }
        actions={<RefreshButton onClick={overview.reload} busy={overview.refreshing} />}
      />
      <Async resource={overview} loadingLabel="Loading overview…">
        {(o) => <OverviewBody overview={o} isAdmin={isAdmin} />}
      </Async>
    </>
  );
}

function OverviewBody({ overview: o, isAdmin }: { overview: Overview; isAdmin: boolean }) {
  return (
    <div className="stack">
      <AttentionPanel items={o.attention} />
      <CountTiles overview={o} />
      <div className="grid grid--2">
        <PolicyPanel policy={o.policy} isAdmin={isAdmin} />
        <AuditPanel audit={o.audit} />
      </div>
      <TrafficPanel traffic={o.traffic_24h} byEnv={o.traffic_by_environment_24h} />
      <div className="grid grid--2">
        <BackendsPanel backends={o.backends} isAdmin={isAdmin} />
        <RoutesPanel routes={o.routes} isAdmin={isAdmin} />
      </div>
    </div>
  );
}

function AttentionPanel({ items }: { items: readonly Attention[] }) {
  const sorted = [...items].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  return (
    <Panel title="Needs attention" flush>
      {sorted.length === 0 ? (
        <p className="panel-note">Nothing needs attention.</p>
      ) : (
        <ul className="attention">
          {sorted.map((item, i) => {
            const href = safeInternalHref(item.href);
            return (
              <li key={i}>
                <StatusBadge domain="severity" value={item.severity} />
                <span className="attention__message">{href ? <a href={href}>{item.message}</a> : item.message}</span>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function CountTiles({ overview: o }: { overview: Overview }) {
  const c = o.counts;
  const tiles: ReadonlyArray<{ label: string; value: number; href: string }> = [
    { label: 'Imported bundles', value: c.bundles, href: toHash(paths.bundles) },
    { label: 'In the inbox', value: o.inbox_pending, href: toHash(paths.bundles) },
    { label: 'Model artifacts', value: c.model_artifacts, href: toHash(paths.models) },
    { label: 'Routes', value: c.routes, href: toHash(paths.models) },
    { label: 'Backends', value: c.backends, href: toHash(paths.models) },
    { label: 'Apps', value: c.apps, href: toHash(paths.access()) },
    { label: 'Active API keys', value: c.active_keys, href: toHash(paths.access()) },
    { label: 'Trusted signing keys', value: c.trusted_keys, href: toHash(paths.bundles) },
  ];
  return (
    <section aria-label="Counts">
      <ul className="tiles">
        {tiles.map((t) => (
          <li key={t.label}>
            <a className="tile" href={t.href}>
              <span className="tile__label">{t.label}</span>
              <span className="tile__value">{formatInt(t.value)}</span>
            </a>
          </li>
        ))}
      </ul>
    </section>
  );
}

function PolicyPanel({ policy, isAdmin }: { policy: OverviewPolicy | null; isAdmin: boolean }) {
  return (
    <Panel title="Access policy" actions={<a href={toHash(paths.access('policy'))}>Open policy</a>}>
      {policy ? (
        <DefList
          items={[
            ['Active version', <span className="num">v{policy.version}</span>],
            ['Rules', <span className="num">{formatInt(policy.rule_count)}</span>],
            ['Activated', <Time value={policy.activated_at} exact />],
            ['SHA-256', <Digest value={policy.sha256} label="policy sha256" />],
          ]}
        />
      ) : (
        <Callout tone="bad" title="No active policy">
          <p>
            Every gateway request is denied until {isAdmin ? 'you activate' : 'an admin activates'} a policy on the Access
            page.
          </p>
        </Callout>
      )}
    </Panel>
  );
}

function AuditPanel({ audit }: { audit: Overview['audit'] }) {
  const last = audit.last_verify;
  return (
    <Panel title="Audit log" actions={<a href={toHash(paths.audit())}>Open audit log</a>}>
      <DefList
        items={[
          ['Latest event', audit.head_seq > 0 ? <span className="num">#{formatInt(audit.head_seq)}</span> : 'none yet'],
          ['Head hash', <Digest value={audit.head_hash} label="audit head hash" />],
          [
            'Last chain check',
            last ? (
              <span className="row">
                <StatusBadge domain="chain" value={last.ok ? 'intact' : 'broken'} />
                <Time value={last.verified_at} />
              </span>
            ) : (
              <span className="subtle">no check recorded; run one from the audit log</span>
            ),
          ],
          ['Problem', last && !last.ok ? (last.problem ?? 'not described') : null],
        ]}
      />
    </Panel>
  );
}

function TrafficPanel({ traffic, byEnv }: { traffic: Traffic; byEnv: TrafficByEnvironment }) {
  if (traffic.total === 0) {
    return (
      <Panel title="Gateway traffic, last 24 hours">
        <EmptyState title="No gateway requests in the last 24 hours.">
          Apps call <code>POST /v1/chat/completions</code> on this server with an API key issued on the Access page.
        </EmptyState>
      </Panel>
    );
  }
  const segments = trafficSegments(traffic);
  const environments = environmentSegments(byEnv);
  return (
    <Panel title="Gateway traffic, last 24 hours" description="Counted from gateway.chat.completions audit events.">
      <div className="stack stack--tight">
        <div className="figure-row">
          <Figure label="Requests" value={formatInt(traffic.total)} />
          <Figure label="Success rate" value={formatPercent(traffic.success, traffic.total)} />
          <Figure label="Latency p50" value={formatMs(traffic.p50_ms)} />
          <Figure label="Latency p95" value={formatMs(traffic.p95_ms)} />
        </div>
        <ShareBar segments={segments} />
        <div className="grid grid--split-even">
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="sr-only">Requests by outcome, last 24 hours</caption>
              <thead>
                <tr>
                  <th scope="col">Outcome</th>
                  <th scope="col" className="num">
                    Requests
                  </th>
                  <th scope="col" className="num">
                    Share
                  </th>
                </tr>
              </thead>
              <tbody>
                {segments.map((s) => (
                  <tr key={s.key}>
                    <th scope="row" className="row-head">
                      <span className="row row--nowrap">
                        <Swatch name={s.key} />
                        <span>
                          {OUTCOME_TEXT[s.key].label}
                          <span className="subtle small"> · {OUTCOME_TEXT[s.key].hint}</span>
                        </span>
                      </span>
                    </th>
                    <td className="num">{formatInt(s.count)}</td>
                    <td className="num">{formatPercent(s.count, traffic.total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="sr-only">Requests by app environment, last 24 hours</caption>
              <thead>
                <tr>
                  <th scope="col">App environment</th>
                  <th scope="col" className="num">
                    Requests
                  </th>
                  <th scope="col" className="num">
                    Share
                  </th>
                </tr>
              </thead>
              <tbody>
                {environments.map((e) => (
                  <tr key={e.key}>
                    <th scope="row" className="row-head">
                      {e.key}
                    </th>
                    <td className="num">{formatInt(e.count)}</td>
                    <td className="num">{formatPercent(e.count, traffic.total)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Panel>
  );
}

function BackendsPanel({ backends, isAdmin }: { backends: readonly OverviewBackend[]; isAdmin: boolean }) {
  return (
    <Panel title="Backend health" actions={<a href={toHash(paths.models)}>Open models</a>} flush>
      {backends.length === 0 ? (
        <EmptyState title="No inference backends configured.">
          {isAdmin ? 'Add one on the Models page' : 'An admin can add one on the Models page'}, or on the host with{' '}
          <code>ferry backend add NAME --kind llamacpp --url URL</code>.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Backend health</caption>
            <thead>
              <tr>
                <th scope="col">Backend</th>
                <th scope="col">Kind</th>
                <th scope="col">State</th>
                <th scope="col">Last check</th>
              </tr>
            </thead>
            <tbody>
              {backends.map((b) => (
                <tr key={b.id}>
                  <td>{b.name}</td>
                  <td>
                    <code>{b.kind}</code>
                  </td>
                  <td>
                    <StatusBadge domain="backend" value={b.state} label={b.state ?? 'not checked'} />
                  </td>
                  <td>
                    <Time value={b.checked_at} fallback="never" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function RoutesPanel({ routes, isAdmin }: { routes: readonly OverviewRoute[]; isAdmin: boolean }) {
  return (
    <Panel title="Route availability" actions={<a href={toHash(paths.models)}>Open models</a>} flush>
      {routes.length === 0 ? (
        <EmptyState title="No routes.">
          A route maps a public model name to a backend and a pinned artifact.{' '}
          {isAdmin ? 'Add one on the Models page.' : 'An admin can add one on the Models page.'}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">Route availability</caption>
            <thead>
              <tr>
                <th scope="col">Model</th>
                <th scope="col">Backend</th>
                <th scope="col">Provenance</th>
                <th scope="col">Availability</th>
              </tr>
            </thead>
            <tbody>
              {routes.map((r) => (
                <tr key={r.model}>
                  <td>
                    <code>{r.model}</code>
                  </td>
                  <td>{r.backend}</td>
                  <td>
                    <StatusBadge domain="provenance" value={r.provenance} />
                  </td>
                  <td>
                    <StatusBadge domain="availability" value={r.available ? 'available' : 'unavailable'} />
                    {!r.available && r.reason ? <div className="cell-note">{r.reason}</div> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
