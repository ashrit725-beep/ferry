/**
 * Evidence report (spec section 10) rendered as readable sections. The same
 * report downloads as Markdown or JSON. It records configuration and events;
 * it is not a compliance certification, and the page says so.
 */

import type { ReactNode } from 'react';
import { EVIDENCE_JSON_URL, EVIDENCE_MD_URL, api, type Evidence } from '../api.ts';
import { isObject, type JsonObject } from '../decode.ts';
import { numberOf, objectsOf, pick, provenanceOf, stringsOf, textOf } from '../evidence.ts';
import { formatBytes, formatInt, plural } from '../format.ts';
import { useResource } from '../hooks.ts';
import { Digest, KeyId } from '../components/Digest.tsx';
import { IconDownload } from '../components/Icons.tsx';
import { Callout, DefList, PageHeader, Panel, RefreshButton } from '../components/Panel.tsx';
import { Async, EmptyState } from '../components/States.tsx';
import { StatusBadge } from '../components/StatusBadge.tsx';
import { Time } from '../components/Time.tsx';
import { ObjectTable, RowsTable, Value } from '../components/Value.tsx';

const SECTIONS: ReadonlyArray<readonly [string, string]> = [
  ['trust', 'Trust anchors'],
  ['import-policy', 'Import policy'],
  ['bundles', 'Bundles'],
  ['routes', 'Routes'],
  ['access-policy', 'Access policy'],
  ['audit', 'Audit chain'],
  ['network', 'Network inventory'],
  ['dependencies', 'Dependencies'],
  ['config', 'Effective configuration'],
];

function sectionId(key: string): string {
  return `evidence-${key}`;
}

/** In-page jumps cannot use #fragments: the fragment is the console route. */
function jumpTo(key: string): void {
  const section = document.getElementById(sectionId(key));
  const heading = section?.querySelector<HTMLElement>('h2');
  if (!section || !heading) return;
  section.scrollIntoView({ block: 'start' });
  heading.setAttribute('tabindex', '-1');
  heading.focus({ preventScroll: true });
}

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
            <a className="button" href={EVIDENCE_MD_URL} download={`ferry-evidence-${stamp}.md`}>
              <IconDownload />
              Markdown
            </a>
            <a className="button" href={EVIDENCE_JSON_URL} download={`ferry-evidence-${stamp}.json`}>
              <IconDownload />
              JSON
            </a>
            <RefreshButton onClick={evidence.reload} busy={evidence.refreshing} />
          </>
        }
      />
      <Async resource={evidence} loadingLabel="Building the evidence report…">
        {(data) => <EvidenceBody evidence={data} />}
      </Async>
    </>
  );
}

function hostText(host: JsonObject): string {
  const platform = textOf(host['platform']);
  const python = textOf(host['python']);
  const parts = [platform, python ? `Python ${python}` : null].filter(Boolean);
  return parts.length ? ` on ${parts.join(', ')}` : '';
}

function EvidenceBody({ evidence: e }: { evidence: Evidence }) {
  return (
    <div className="stack">
      <nav aria-label="Evidence sections" className="toc">
        {SECTIONS.map(([key, label]) => (
          <button key={key} type="button" className="link-button" onClick={() => jumpTo(key)}>
            {label}
          </button>
        ))}
      </nav>

      <Section id="trust" title="Trust anchors" description="Keys this installation accepts bundle signatures from, and their status.">
        <TrustAnchors rows={e.trust_anchors} />
      </Section>

      <Section id="import-policy" title="Import policy" description="What an imported bundle must satisfy. Set in ferry.toml on the host.">
        {e.import_policy ? <ObjectTable value={e.import_policy} caption="Import policy" /> : <p className="table-note">Not reported.</p>}
      </Section>

      <Section id="bundles" title="Bundles" description="Imported bundles, who signed them, and their artifacts.">
        <Bundles rows={e.bundles} />
      </Section>

      <Section id="routes" title="Routes" description="Public model names, their backends, pinned artifacts and provenance at report time.">
        <Routes rows={e.routes} />
      </Section>

      <Section id="access-policy" title="Access policy">
        <AccessPolicy active={e.active_policy} history={e.policy_history} />
      </Section>

      <Section id="audit" title="Audit chain" description="The hash chain recomputed when this report was generated.">
        <AuditChain audit={e.audit} />
      </Section>

      <Section id="network" title="Network inventory" description="Connections Ferry is configured to accept or make: its listener and the configured backends.">

        <Inventory evidence={e} />
      </Section>

      <Section id="dependencies" title="Dependencies" description="Installed runtime packages and versions.">
        {e.dependencies.length === 0 ? (
          <p className="table-note">Not reported.</p>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="sr-only">Dependencies</caption>
              <thead>
                <tr>
                  <th scope="col">Package</th>
                  <th scope="col">Version</th>
                </tr>
              </thead>
              <tbody>
                {e.dependencies.map((d) => (
                  <tr key={d.name}>
                    <td>
                      <code>{d.name}</code>
                    </td>
                    <td>
                      <code>{d.version}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section id="config" title="Effective configuration" description="Settings in force, after defaults. Contains no secrets.">
        {e.config ? <Config config={e.config} /> : <p className="table-note">Not reported.</p>}
      </Section>
    </div>
  );
}

function Section({ id, title, description, children }: { id: string; title: string; description?: string; children: ReactNode }) {
  return (
    <Panel id={sectionId(id)} title={title} description={description}>
      {children}
    </Panel>
  );
}

function Roles({ value }: { value: unknown }) {
  const roles = stringsOf(value);
  if (roles.length === 0) return <span className="subtle">none</span>;
  return (
    <span className="inline-list">
      {roles.map((r) => (
        <span key={r} className="tag">
          {r}
        </span>
      ))}
    </span>
  );
}

function TimeOrText({ value, fallback, future = false }: { value: unknown; fallback: string; future?: boolean }) {
  const t = textOf(value);
  return t ? <Time value={t} future={future} /> : <span className="subtle">{fallback}</span>;
}

function TrustAnchors({ rows }: { rows: readonly JsonObject[] }) {
  if (rows.length === 0) {
    return (
      <EmptyState title="No trust anchors.">
        With an empty trust store every bundle is rejected. Keys are added on the host with <code>ferry trust add</code>.
      </EmptyState>
    );
  }
  if (!rows.some((r) => 'key_id' in r)) return <RowsTable rows={rows} caption="Trust anchors" />;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Trust anchors</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Key id</th>
            <th scope="col">Roles</th>
            <th scope="col">Status</th>
            <th scope="col">Valid from</th>
            <th scope="col">Valid until</th>
            <th scope="col">Revoked</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const keyId = textOf(r['key_id']);
            const reason = textOf(r['revocation_reason']);
            return (
              <tr key={keyId ?? i}>
                <td>{textOf(r['name']) ?? <span className="subtle">unnamed</span>}</td>
                <td className="nowrap">{keyId ? <KeyId value={keyId} /> : null}</td>
                <td>
                  <Roles value={r['roles']} />
                </td>
                <td>
                  <StatusBadge domain="trust" value={textOf(r['status'])} />
                </td>
                <td>
                  <TimeOrText value={r['not_before']} fallback="any time" future />
                </td>
                <td>
                  <TimeOrText value={r['not_after']} fallback="no expiry" future />
                </td>
                <td>
                  {textOf(r['revoked_at']) ? (
                    <>
                      <TimeOrText value={r['revoked_at']} fallback="" />
                      {reason ? <div className="cell-note">{reason}</div> : null}
                    </>
                  ) : (
                    <span className="subtle">no</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SignerList({ value }: { value: unknown }) {
  const signers = Array.isArray(value) ? value : [];
  if (signers.length === 0) return <span className="subtle">none recorded</span>;
  return (
    <ul className="signer-list">
      {signers.map((s, i) => {
        if (!isObject(s)) return <li key={i}>{textOf(s) ?? ''}</li>;
        const keyId = textOf(s['key_id']);
        return (
          <li key={keyId ?? i}>
            <span>{textOf(s['name']) ?? (keyId ? <KeyId value={keyId} /> : 'unnamed')}</span>
            <Roles value={s['roles']} />
          </li>
        );
      })}
    </ul>
  );
}

function Bundles({ rows }: { rows: readonly JsonObject[] }) {
  if (rows.length === 0) return <EmptyState title="No bundles imported." />;
  return (
    <div className="stack stack--tight">
      {rows.map((b, i) => {
        const id = textOf(pick(b, 'bundle_id', 'id'));
        const artifacts = objectsOf(b['artifacts']);
        const total = artifacts.reduce((n, a) => n + (numberOf(a['size']) ?? 0), 0);
        return (
          <div key={id ?? i} className="evidence-item">
            <div className="evidence-item__head">
              <span className="strong">
                {textOf(b['name']) ?? 'unnamed'} <span className="mono">{textOf(b['version']) ?? ''}</span>
              </span>
              {id ? <Digest value={id} label="bundle id" /> : null}
            </div>
            <DefList
              items={[
                ['Imported', <TimeOrText value={b['imported_at']} fallback="not recorded" />],
                ['Signers', <SignerList value={b['signers']} />],
                ['Artifacts', artifacts.length ? `${plural(artifacts.length, 'artifact')}, ${formatBytes(total)}` : <Value value={b['artifacts']} />],
              ]}
            />
            {artifacts.length ? (
              <div className="table-wrap">
                <table className="table table--compact">
                  <caption className="sr-only">Artifacts of this bundle</caption>
                  <thead>
                    <tr>
                      <th scope="col">Path</th>
                      <th scope="col">Kind</th>
                      <th scope="col">Format</th>
                      <th scope="col" className="num">
                        Size
                      </th>
                      <th scope="col">SHA-256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {artifacts.map((a, j) => {
                      const path = textOf(a['path']);
                      return (
                        <tr key={path ?? j}>
                          <td className="break">
                            <code>{path ?? ''}</code>
                          </td>
                          <td>{textOf(a['kind']) ?? ''}</td>
                          <td>
                            <code>{textOf(a['format']) ?? ''}</code>
                          </td>
                          <td className="num">{formatBytes(numberOf(a['size']))}</td>
                          <td className="nowrap">
                            <Digest value={textOf(pick(a, 'sha256', 'digest'))} label={`sha256 of ${path ?? 'artifact'}`} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function Routes({ rows }: { rows: readonly JsonObject[] }) {
  if (rows.length === 0) return <EmptyState title="No routes configured." />;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Routes</caption>
        <thead>
          <tr>
            <th scope="col">Model</th>
            <th scope="col">Backend</th>
            <th scope="col">Pinned artifact</th>
            <th scope="col">Provenance</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => {
            const pin = textOf(pick(r, 'pin', 'artifact_digest'));
            const prov = provenanceOf(r['provenance']);
            const backend = pick(r, 'backend', 'backend_name');
            return (
              <tr key={textOf(r['model']) ?? i}>
                <td>
                  <code>{textOf(r['model']) ?? ''}</code>
                </td>
                <td>{isObject(backend) ? (textOf(backend['name']) ?? <Value value={backend} />) : (textOf(backend) ?? '')}</td>
                <td className="nowrap">{pin ? <Digest value={pin} label="pinned digest" /> : <span className="tag">not pinned</span>}</td>
                <td>
                  <StatusBadge domain="provenance" value={prov.state} />
                  {prov.detail ? <div className="cell-note">{prov.detail}</div> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function AccessPolicy({ active, history }: { active: JsonObject | null; history: readonly JsonObject[] }) {
  return (
    <div className="stack stack--tight">
      {active ? (
        <DefList
          items={[
            ['Active version', <span className="num">v{textOf(active['version']) ?? '?'}</span>],
            ['SHA-256', <Digest value={textOf(active['sha256'])} label="policy sha256" />],
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
        <div className="subsection">
          <h3>Version history</h3>
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="sr-only">Policy version history</caption>
              <thead>
                <tr>
                  <th scope="col" className="num">
                    Version
                  </th>
                  <th scope="col">Created</th>
                  <th scope="col">By</th>
                  <th scope="col">Comment</th>
                  <th scope="col">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={textOf(h['version']) ?? i}>
                    <td className="num">v{textOf(h['version']) ?? '?'}</td>
                    <td>
                      <TimeOrText value={h['created_at']} fallback="" />
                    </td>
                    <td>{textOf(h['created_by']) ?? ''}</td>
                    <td className="break">{textOf(h['comment']) || <span className="subtle">none</span>}</td>
                    <td className="nowrap">
                      <Digest value={textOf(h['sha256'])} label="policy sha256" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function AuditChain({ audit }: { audit: JsonObject | null }) {
  if (!audit) return <p className="table-note">Not reported.</p>;
  const ok = audit['ok'] === true;
  const firstBad = numberOf(audit['first_bad_seq']);
  return (
    <div className="stack stack--tight">
      <Callout tone={ok ? 'ok' : 'bad'} title={ok ? 'Chain intact' : `Chain broken${firstBad !== null ? ` at event #${firstBad}` : ''}`}>
        {!ok && textOf(audit['problem']) ? <p>{textOf(audit['problem'])}</p> : null}
      </Callout>
      <DefList
        items={[
          ['Events checked', numberOf(audit['events_checked']) !== null ? formatInt(numberOf(audit['events_checked'])) : null],
          ['Head', numberOf(audit['head_seq']) !== null ? `#${formatInt(numberOf(audit['head_seq']))}` : null],
          ['Head hash', textOf(audit['head_hash']) ? <Digest value={textOf(audit['head_hash'])} label="head hash" /> : null],
          ['Checked', <TimeOrText value={audit['verified_at']} fallback="not recorded" />],
        ]}
      />
    </div>
  );
}

function Inventory({ evidence }: { evidence: Evidence }) {
  const rows = evidence.network_inventory;
  if (rows.length === 0) return <p className="table-note">Not reported.</p>;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="sr-only">Network inventory</caption>
        <thead>
          <tr>
            <th scope="col">Component</th>
            <th scope="col">Direction</th>
            <th scope="col">Destination</th>
            <th scope="col">Purpose</th>
            <th scope="col">Configurable</th>
            <th scope="col">Notes</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.component}-${r.destination}-${i}`}>
              <td>{r.component}</td>
              <td>
                <span className="tag">{r.direction}</span>
              </td>
              <td className="break">
                <code>{r.destination}</code>
              </td>
              <td>{r.purpose}</td>
              <td>{r.configurable === null ? <span className="subtle">—</span> : r.configurable ? 'yes' : 'no'}</td>
              <td className="break">{r.notes || <span className="subtle">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Config({ config }: { config: JsonObject }) {
  const scalars = Object.entries(config).filter(([, v]) => !isObject(v));
  const sections = Object.entries(config).filter((entry): entry is [string, JsonObject] => isObject(entry[1]));
  return (
    <div className="stack stack--tight">
      {scalars.length ? (
        <DefList wide items={scalars.map(([k, v]) => [k, <Value value={v} name={k} />] as const)} />
      ) : null}
      {sections.map(([name, value]) => (
        <div key={name} className="subsection">
          <h3>
            <code>[{name}]</code>
          </h3>
          <ObjectTable value={value} caption={`[${name}] settings`} />
        </div>
      ))}
    </div>
  );
}
