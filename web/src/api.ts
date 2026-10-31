/**
 * Typed client for the Ferry admin API (spec section 9).
 *
 * Conventions enforced here so pages cannot get them wrong:
 * - the session travels in the HttpOnly cookie (credentials 'same-origin');
 * - every non-GET request carries `X-Ferry-CSRF: 1` and a JSON body;
 * - redirects are refused and responses are never cached;
 * - every response body is decoded against the contract before use;
 * - a 401 from any call (except the session probe and login) signs the
 *   console out through the registered handler.
 */

import {
  DecodeError,
  array,
  bool,
  decode,
  either,
  extend,
  flag,
  idString,
  int,
  isObject,
  jsonObject,
  jsonText,
  map,
  maybe,
  num,
  object,
  str,
  unknownValue,
  withDefault,
  type Decoder,
  type JsonObject,
} from './decode.ts';

/* ------------------------------------------------------------------ errors */

export const NETWORK_ERROR = 'network_error';
export const BAD_RESPONSE = 'bad_response';

export interface ApiErrorInit {
  status: number;
  code: string;
  message: string;
  details?: unknown;
  body?: unknown;
  retryAfterS?: number | null;
}

/** Failure of an API call. `status` is 0 when the server could not be reached. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly body: unknown;
  readonly retryAfterS: number | null;

  constructor(init: ApiErrorInit) {
    super(init.message);
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.details = init.details;
    this.body = init.body;
    this.retryAfterS = init.retryAfterS ?? null;
  }
}

const DEFAULT_MESSAGES: Record<number, string> = {
  400: 'The request was not valid.',
  401: 'You are not signed in.',
  403: 'This action requires the admin role.',
  404: 'Not found.',
  409: 'The request conflicts with the current state.',
  413: 'The request is too large.',
  422: 'The request did not pass validation.',
  429: 'Too many attempts. Wait and try again.',
};

function positiveNumber(value: unknown): number | null {
  const n = typeof value === 'string' ? Number(value) : value;
  return typeof n === 'number' && Number.isFinite(n) && n >= 0 ? n : null;
}

/** Builds an ApiError from a non-2xx response in either the Ferry error shape or FastAPI's default. */
export function errorFromResponse(status: number, payload: unknown, retryAfterHeader: string | null = null): ApiError {
  let code = `http_${status}`;
  let message = '';
  let details: unknown;
  let retryAfterS = positiveNumber(retryAfterHeader);

  if (isObject(payload)) {
    const err = payload['error'];
    if (isObject(err)) {
      if (typeof err['code'] === 'string' && err['code']) code = err['code'];
      if (typeof err['message'] === 'string') message = err['message'];
      details = err['details'];
    } else if ('detail' in payload) {
      const detail = payload['detail'];
      if (typeof detail === 'string') {
        message = detail;
      } else if (Array.isArray(detail)) {
        code = 'validation_failed';
        details = { errors: detail };
      }
    }
    if (isObject(details)) retryAfterS = positiveNumber(details['retry_after_s']) ?? retryAfterS;
    retryAfterS = positiveNumber(payload['retry_after_s']) ?? retryAfterS;
  } else if (typeof payload === 'string' && payload.trim() && payload.length <= 300 && !payload.includes('<')) {
    message = payload.trim();
  }
  if (!message) message = DEFAULT_MESSAGES[status] ?? (status >= 500 ? `The server failed (HTTP ${status}).` : `Request failed (HTTP ${status}).`);
  return new ApiError({ status, code, message, details, body: payload, retryAfterS });
}

/* ------------------------------------------------------------------ transport */

export type Method = 'GET' | 'POST' | 'PATCH' | 'DELETE';
export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions<T> {
  decoder: Decoder<T>;
  body?: unknown;
  query?: Record<string, QueryValue>;
  signal?: AbortSignal;
  /** The session probe and login handle 401 themselves instead of signing out. */
  quiet401?: boolean;
}

let unauthorizedHandler: (() => void) | null = null;

/** Registers what happens when any call reports that the session is gone. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

/** Path segment encoding; bundle ids contain ':' and must not be read as a scheme. */
export function seg(value: string | number): string {
  return encodeURIComponent(String(value));
}

export function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException ? err.name === 'AbortError' : err instanceof Error && err.name === 'AbortError';
}

async function readBody(res: Response): Promise<unknown> {
  if (res.status === 204) return undefined;
  const text = await res.text();
  if (text === '') return undefined;
  const type = res.headers.get('content-type') ?? '';
  if (type.includes('json')) {
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }
  return text;
}

export async function request<T>(method: Method, path: string, opts: RequestOptions<T>): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: string | undefined;
  if (method !== 'GET') {
    headers['X-Ferry-CSRF'] = '1';
    if (method !== 'DELETE' || opts.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.body ?? {});
    }
  }
  const init: RequestInit = { method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
  if (body !== undefined) init.body = body;
  if (opts.signal) init.signal = opts.signal;

  let res: Response;
  try {
    res = await globalThis.fetch(buildUrl(path, opts.query), init);
  } catch (err) {
    if (isAbortError(err)) throw err;
    throw new ApiError({
      status: 0,
      code: NETWORK_ERROR,
      message: 'Cannot reach the Ferry server. Check that it is running and reachable from this browser.',
    });
  }

  let payload: unknown;
  try {
    payload = await readBody(res);
  } catch (err) {
    if (isAbortError(err)) throw err;
    throw new ApiError({ status: 0, code: NETWORK_ERROR, message: 'The connection to the Ferry server was interrupted.' });
  }

  if (!res.ok) {
    const error = errorFromResponse(res.status, payload, res.headers.get('retry-after'));
    if (res.status === 401 && !opts.quiet401) unauthorizedHandler?.();
    throw error;
  }
  try {
    return decode(opts.decoder, payload);
  } catch (err) {
    if (!(err instanceof DecodeError)) throw err;
    throw new ApiError({
      status: res.status,
      code: BAD_RESPONSE,
      message: `The server's response to ${method} ${path.split('?')[0]} does not match what this console expects (${err.message}). The console and server versions may differ.`,
    });
  }
}

/** For 204 responses; any body is ignored. */
export const noContent: Decoder<void> = () => undefined;

/* ------------------------------------------------------------------ shared */

const text = withDefault(str, '');
const optText = maybe(str);
const strings = withDefault(array(str), [] as string[]);
const details = withDefault(jsonText(jsonObject), {} as JsonObject);

/** Validation paths may arrive as "rules[0].id" or as ["rules", 0, "id"]. */
const pathString: Decoder<string> = either(
  withDefault(str, ''),
  map(array(either(str, num)), (parts) =>
    parts.reduce<string>((acc, part) => (typeof part === 'number' ? `${acc}[${part}]` : acc ? `${acc}.${part}` : part), ''),
  ),
);

/** Free-form scalar fields (versions, build info) rendered as text. */
const display: Decoder<string | null> = (v) => {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
};

const displayText: Decoder<string> = (v, p) => display(v, p) ?? '';

/* ------------------------------------------------------------------ auth */

/** Only the exact role "admin" unlocks admin controls; any other value is read-only. */
export interface User {
  username: string;
  role: string;
}

const userD: Decoder<User> = object({ username: str, role: str });
const userEnvelope = object({ user: userD });

/* ------------------------------------------------------------------ overview */

export interface Counts {
  apps: number;
  active_keys: number;
  backends: number;
  routes: number;
  bundles: number;
  model_artifacts: number;
  trusted_keys: number;
}

export interface OverviewPolicy {
  version: number;
  sha256: string;
  activated_at: string;
  rule_count: number;
}

export interface OverviewBackend {
  id: number;
  name: string;
  kind: string;
  state: string | null;
  checked_at: string | null;
}

export interface OverviewRoute {
  model: string;
  backend: string;
  provenance: string;
  available: boolean;
  reason: string | null;
}

export interface Traffic {
  total: number;
  success: number;
  denied: number;
  error: number;
  unavailable: number;
  rejected: number;
  unauthenticated: number;
  p50_ms: number | null;
  p95_ms: number | null;
}

export type TrafficOutcome = 'success' | 'denied' | 'error' | 'unavailable' | 'rejected' | 'unauthenticated';
export const TRAFFIC_OUTCOMES: readonly TrafficOutcome[] = ['success', 'denied', 'error', 'unavailable', 'rejected', 'unauthenticated'];

export interface TrafficByEnvironment {
  test: number;
  pilot: number;
  production: number;
}

export interface LastAuditVerify {
  ok: boolean;
  verified_at: string;
  problem: string | null;
  /** The last event seq the recorded check covered (null on older records). */
  head_seq: number | null;
  /** The seq of the audit.verify event itself (appended right after head_seq). */
  seq: number | null;
}

export interface Attention {
  severity: string;
  message: string;
  href: string | null;
}

export interface Overview {
  version: string;
  started_at: string;
  policy: OverviewPolicy | null;
  counts: Counts;
  backends: OverviewBackend[];
  routes: OverviewRoute[];
  traffic_24h: Traffic;
  traffic_by_environment_24h: TrafficByEnvironment;
  inbox_pending: number;
  audit: { head_seq: number; head_hash: string; last_verify: LastAuditVerify | null };
  attention: Attention[];
}

/** Overview rows may carry the provenance state alone or the full provenance object. */
const provenanceState: Decoder<string> = either(str, map(object({ state: str }), (p) => p.state));

const overviewD: Decoder<Overview> = object({
  version: str,
  started_at: str,
  policy: maybe(object({ version: int, sha256: str, activated_at: str, rule_count: int })),
  counts: object({
    apps: int,
    active_keys: int,
    backends: int,
    routes: int,
    bundles: int,
    model_artifacts: int,
    trusted_keys: int,
  }),
  backends: array(object({ id: int, name: str, kind: str, state: optText, checked_at: optText })),
  routes: array(object({ model: str, backend: idString, provenance: provenanceState, available: flag, reason: optText })),
  traffic_24h: object({
    total: int,
    success: int,
    denied: int,
    error: int,
    unavailable: int,
    rejected: int,
    unauthenticated: int,
    p50_ms: maybe(num),
    p95_ms: maybe(num),
  }),
  traffic_by_environment_24h: object({ test: int, pilot: int, production: int }),
  inbox_pending: int,
  audit: object({
    head_seq: int,
    head_hash: str,
    last_verify: maybe(object({ ok: bool, verified_at: str, problem: optText, head_seq: maybe(int), seq: maybe(int) })),
  }),
  attention: array(object({ severity: str, message: str, href: optText })),
});

/* ------------------------------------------------------------------ verification reports */

export interface ReportSignature {
  key_id: string;
  name: string | null;
  roles: string[];
  status: string;
  detail: string;
}

export interface ReportArtifact {
  path: string;
  kind: string | null;
  declared_format: string | null;
  detected_format: string | null;
  size: number | null;
  expected_sha256: string | null;
  actual_sha256: string | null;
  status: string;
  detail: string;
  metadata: JsonObject;
}

export interface ReportCheck {
  id: string;
  status: string;
  message: string;
}

/** `ferry verify` report, report_version 1 (spec section 4). Early rejections omit most fields. */
export interface VerificationReport {
  report_version: number | null;
  verdict: string;
  bundle_id: string | null;
  bundle: { name: string | null; version: string | null; created_at: string | null } | null;
  source: { name: string | null; type: string | null; size: number | null } | null;
  verified_at: string | null;
  tool_version: string | null;
  policy: JsonObject | null;
  signatures: ReportSignature[];
  artifacts: ReportArtifact[];
  checks: ReportCheck[];
  errors: string[];
  warnings: string[];
}

export const REPORT_VERSION = 1;

const reportD: Decoder<VerificationReport> = jsonText(
  object({
    report_version: maybe(int),
    verdict: str,
    bundle_id: optText,
    bundle: maybe(object({ name: optText, version: optText, created_at: optText })),
    source: maybe(object({ name: optText, type: optText, size: maybe(num) })),
    verified_at: optText,
    tool_version: optText,
    policy: maybe(jsonObject),
    signatures: withDefault(
      array(object({ key_id: str, name: optText, roles: strings, status: str, detail: text })),
      [] as ReportSignature[],
    ),
    artifacts: withDefault(
      array(
        object({
          path: str,
          kind: optText,
          declared_format: optText,
          detected_format: optText,
          size: maybe(num),
          expected_sha256: optText,
          actual_sha256: optText,
          status: str,
          detail: text,
          metadata: withDefault(jsonObject, {} as JsonObject),
        }),
      ),
      [] as ReportArtifact[],
    ),
    checks: withDefault(array(object({ id: str, status: str, message: text })), [] as ReportCheck[]),
    errors: strings,
    warnings: strings,
  }),
);

/* ------------------------------------------------------------------ inbox and jobs */

export interface InboxItem {
  name: string;
  type: string;
  size: number | null;
  modified_at: string | null;
  last_verification: { verdict: string; created_at: string; bundle_id: string | null } | null;
}

export interface Inbox {
  inbox_dir: string;
  items: InboxItem[];
}

const inboxD: Decoder<Inbox> = object({
  inbox_dir: str,
  items: array(
    object({
      name: str,
      type: str,
      size: maybe(num),
      modified_at: optText,
      last_verification: maybe(object({ verdict: str, created_at: str, bundle_id: optText })),
    }),
  ),
});

export type JobKind = 'verify' | 'import';
export type JobState = 'queued' | 'running' | 'succeeded' | 'failed';

export interface JobResult {
  verdict: string;
  bundle_id: string | null;
  report: VerificationReport | null;
  already_imported: boolean;
}

export interface Job {
  job_id: string;
  kind: string;
  source_name: string;
  state: string;
  progress: { bytes_done: number; bytes_total: number | null };
  started_at: string | null;
  finished_at: string | null;
  result: JobResult | null;
  error: string | null;
}

export function isJobFinished(state: string): boolean {
  return state === 'succeeded' || state === 'failed';
}

const jobRefD = object({ job_id: idString });

const jobD: Decoder<Job> = object({
  job_id: idString,
  kind: str,
  source_name: str,
  state: str,
  progress: withDefault(object({ bytes_done: withDefault(num, 0), bytes_total: maybe(num) }), {
    bytes_done: 0,
    bytes_total: null,
  }),
  started_at: optText,
  finished_at: optText,
  result: maybe(
    object({
      verdict: str,
      bundle_id: optText,
      report: maybe(reportD),
      already_imported: withDefault(flag, false),
    }),
  ),
  error: optText,
});

/* ------------------------------------------------------------------ verifications and bundles */

export interface VerificationSummary {
  id: number;
  source_name: string;
  bundle_id: string | null;
  bundle_name: string | null;
  bundle_version: string | null;
  verdict: string;
  mode: string;
  created_at: string;
  actor: string;
  error_count: number;
  warning_count: number;
}

export interface VerificationRecord extends VerificationSummary {
  report: VerificationReport;
}

const verificationSummaryD: Decoder<VerificationSummary> = object({
  id: int,
  source_name: str,
  bundle_id: optText,
  bundle_name: optText,
  bundle_version: optText,
  verdict: str,
  mode: str,
  created_at: str,
  actor: str,
  error_count: withDefault(int, 0),
  warning_count: withDefault(int, 0),
});

const verificationRecordD: Decoder<VerificationRecord> = extend(verificationSummaryD, { report: reportD });

export interface Signer {
  key_id: string;
  name: string | null;
  roles: string[];
}

export interface BundleSummary {
  bundle_id: string;
  name: string;
  version: string;
  imported_at: string;
  imported_by: string;
  source_name: string;
  signers: Signer[];
  artifact_count: number;
  total_bytes: number;
}

export interface ManifestModel {
  name: string | null;
  license: string | null;
  source_uri: string | null;
  source_revision: string | null;
  upstream_sha256: string | null;
}

export interface ManifestArtifact {
  path: string;
  size: number | null;
  sha256: string | null;
  kind: string | null;
  format: string | null;
  model: ManifestModel | null;
}

/** The parts of manifest.json the console summarises; the raw document is kept alongside. */
export interface Manifest {
  schema: string | null;
  bundle: { name: string | null; version: string | null; created_at: string | null; description: string | null } | null;
  requires: {
    ferry_min_version: string | null;
    runtime: string | null;
    runtime_min_version: string | null;
    min_memory_bytes: number | null;
  } | null;
  artifacts: ManifestArtifact[];
}

/** Bundle artifact rows; the contract names the list but not its columns, so only common ones are read. */
export interface BundleArtifactRow {
  path: string;
  digest: string | null;
  size: number | null;
  kind: string | null;
  format: string | null;
  model_name: string | null;
}

export interface BundleDetail extends BundleSummary {
  manifest: Manifest | null;
  manifest_raw: unknown;
  report: VerificationReport | null;
  artifacts: BundleArtifactRow[];
}

const signerD: Decoder<Signer> = object({ key_id: str, name: optText, roles: strings });

const bundleSummaryD: Decoder<BundleSummary> = object({
  bundle_id: str,
  name: str,
  version: str,
  imported_at: str,
  imported_by: str,
  source_name: str,
  signers: withDefault(jsonText(array(signerD)), [] as Signer[]),
  artifact_count: int,
  total_bytes: num,
});

const manifestD: Decoder<Manifest> = object({
  schema: optText,
  bundle: maybe(object({ name: optText, version: optText, created_at: optText, description: optText })),
  requires: maybe(
    object({
      ferry_min_version: optText,
      runtime: optText,
      runtime_min_version: optText,
      min_memory_bytes: maybe(num),
    }),
  ),
  artifacts: withDefault(
    array(
      object({
        path: str,
        size: maybe(num),
        sha256: optText,
        kind: optText,
        format: optText,
        model: maybe(
          object({
            name: optText,
            license: optText,
            source_uri: optText,
            source_revision: optText,
            upstream_sha256: optText,
          }),
        ),
      }),
    ),
    [] as ManifestArtifact[],
  ),
});

const bundleArtifactRowD: Decoder<BundleArtifactRow> = (v, p) => {
  const o = jsonObject(v, p);
  const digest = maybe(str)(o['digest'] ?? o['sha256'], `${p}.digest`);
  return {
    path: str(o['path'], `${p}.path`),
    digest,
    size: maybe(num)(o['size'], `${p}.size`),
    kind: optText(o['kind'], `${p}.kind`),
    format: optText(o['format'], `${p}.format`),
    model_name: optText(o['model_name'], `${p}.model_name`),
  };
};

/** Summarises the manifest when it has the v1 shape; otherwise only the raw JSON is shown. */
function tryManifest(raw: unknown): Manifest | null {
  try {
    return manifestD(raw, 'manifest');
  } catch {
    return null;
  }
}

const bundleDetailD: Decoder<BundleDetail> = (v, p) => {
  const base = bundleSummaryD(v, p);
  const rest = object({
    manifest: maybe(jsonText(unknownValue)),
    report: maybe(reportD),
    artifacts: withDefault(array(bundleArtifactRowD), [] as BundleArtifactRow[]),
  })(v, p);
  return { ...base, manifest_raw: rest.manifest, manifest: tryManifest(rest.manifest), report: rest.report, artifacts: rest.artifacts };
};

/* ------------------------------------------------------------------ trust */

export interface TrustKey {
  key_id: string;
  name: string;
  roles: string[];
  not_before: string | null;
  not_after: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
  status: string;
}

export interface TrustStore {
  trust_dir: string;
  required_roles: string[];
  distinct_signers: boolean;
  items: TrustKey[];
  problems: string[];
}

const trustD: Decoder<TrustStore> = object({
  trust_dir: str,
  required_roles: strings,
  distinct_signers: flag,
  items: array(
    object({
      key_id: str,
      name: text,
      roles: strings,
      not_before: optText,
      not_after: optText,
      revoked_at: optText,
      revocation_reason: optText,
      status: str,
    }),
  ),
  problems: strings,
});

/* ------------------------------------------------------------------ models, backends, routes */

export interface ModelArtifact {
  digest: string;
  model_name: string | null;
  size: number;
  format: string;
  metadata: JsonObject;
  license: string | null;
  first_bundle_id: string;
  bundle_name: string | null;
  bundle_version: string | null;
  imported_at: string;
  /** Public model names of routes pinned to this artifact. */
  routes: string[];
}

const routeName: Decoder<string> = either(str, map(object({ model: str }), (r) => r.model));

const modelArtifactD: Decoder<ModelArtifact> = object({
  digest: str,
  model_name: optText,
  size: num,
  format: str,
  metadata: details,
  license: optText,
  first_bundle_id: str,
  bundle_name: optText,
  bundle_version: optText,
  imported_at: str,
  routes: withDefault(array(routeName), [] as string[]),
});

export type BackendKind = 'llamacpp' | 'ollama' | 'openai';
export const BACKEND_KINDS: readonly BackendKind[] = ['llamacpp', 'ollama', 'openai'];

export interface ServedFile {
  model_id: string | null;
  path: string | null;
  digest: string | null;
}

export interface BackendStatus {
  state: string;
  checked_at: string | null;
  latency_ms: number | null;
  http_status: number | null;
  version: string | null;
  models: string[];
  served: ServedFile[];
  error: string | null;
}

export interface Backend {
  id: number;
  name: string;
  kind: string;
  base_url: string;
  has_token: boolean;
  timeout_s: number;
  max_concurrency: number;
  enabled: boolean;
  last_status: BackendStatus | null;
  last_checked_at: string | null;
}

export interface BackendInput {
  name: string;
  kind: BackendKind;
  base_url: string;
  auth_token_file?: string;
  timeout_s?: number;
  max_concurrency?: number;
}

export type BackendPatch = Partial<BackendInput> & { enabled?: boolean };

const backendStatusD: Decoder<BackendStatus> = jsonText(
  object({
    state: str,
    checked_at: optText,
    latency_ms: maybe(num),
    http_status: maybe(int),
    version: display,
    models: withDefault(array(idString), [] as string[]),
    served: withDefault(array(object({ model_id: maybe(idString), path: optText, digest: optText })), [] as ServedFile[]),
    error: display,
  }),
);

const backendD: Decoder<Backend> = object({
  id: int,
  name: str,
  kind: str,
  base_url: str,
  has_token: flag,
  timeout_s: num,
  max_concurrency: int,
  enabled: flag,
  last_status: maybe(backendStatusD),
  last_checked_at: optText,
});

export interface BackendCheck {
  status: BackendStatus;
  checked_at: string | null;
}

const backendCheckD: Decoder<BackendCheck> = object({ status: backendStatusD, checked_at: optText });

export type ProvenanceState = 'verified' | 'mismatch' | 'unverified' | 'not_pinned' | 'unknown';

export interface Provenance {
  state: string;
  detail: string | null;
  served_digest: string | null;
}

export interface ModelRoute {
  id: number;
  model: string;
  backend_id: number;
  backend_name: string;
  upstream_model: string;
  artifact_digest: string | null;
  require_verified: boolean;
  enabled: boolean;
  provenance: Provenance;
  available: boolean;
  reason: string | null;
}

export interface RouteInput {
  model: string;
  backend_id: number;
  upstream_model: string;
  artifact_digest?: string;
  require_verified?: boolean;
}

export type RoutePatch = Partial<RouteInput> & { enabled?: boolean };

const provenanceD: Decoder<Provenance> = either(
  object({ state: str, detail: optText, served_digest: optText }),
  map(str, (state) => ({ state, detail: null, served_digest: null })),
);

const routeD: Decoder<ModelRoute> = object({
  id: int,
  model: str,
  backend_id: int,
  backend_name: text,
  upstream_model: str,
  artifact_digest: optText,
  require_verified: flag,
  enabled: flag,
  provenance: provenanceD,
  available: flag,
  reason: optText,
});

/* ------------------------------------------------------------------ apps and keys */

export type Environment = 'test' | 'pilot' | 'production';
export const ENVIRONMENTS: readonly Environment[] = ['test', 'pilot', 'production'];

export interface ApiKeySummary {
  key_id: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface App {
  id: number;
  name: string;
  environment: string;
  description: string;
  disabled: boolean;
  created_at: string;
  keys: ApiKeySummary[];
}

/** The only response that ever contains a key secret; never store or log it. */
export interface IssuedKey {
  key_id: string;
  api_key: string;
  expires_at: string | null;
}

export interface AppInput {
  name: string;
  environment: Environment;
  description?: string;
}

export interface AppPatch {
  disabled?: boolean;
  description?: string;
  environment?: Environment;
}

const apiKeyD: Decoder<ApiKeySummary> = object({
  key_id: str,
  created_at: str,
  expires_at: optText,
  revoked_at: optText,
  last_used_at: optText,
});

const appD: Decoder<App> = object({
  id: int,
  name: str,
  environment: str,
  description: text,
  disabled: flag,
  created_at: str,
  keys: withDefault(array(apiKeyD), [] as ApiKeySummary[]),
});

const issuedKeyD: Decoder<IssuedKey> = object({ key_id: str, api_key: str, expires_at: optText });

/* ------------------------------------------------------------------ policy */

export const POLICY_SCHEMA = 'ferry.dev/access-policy/v1';
export const POLICY_ACTIONS = ['chat.completions'] as const;
export type PolicyAction = (typeof POLICY_ACTIONS)[number];

export interface PolicyActive {
  version: number;
  sha256: string;
  document: JsonObject;
  created_at: string;
  created_by: string;
  activated_at: string;
  activated_by: string;
  comment: string;
}

export interface PolicyHistoryItem {
  version: number;
  sha256: string;
  created_at: string;
  created_by: string;
  comment: string;
  active: boolean;
}

export interface PolicyState {
  active: PolicyActive | null;
  history: PolicyHistoryItem[];
}

export interface PolicyVersion {
  version: number;
  sha256: string;
  document: JsonObject;
  created_at: string;
  created_by: string;
  comment: string;
  active: boolean;
}

export interface ValidationIssue {
  path: string;
  message: string;
}

export interface ValidationWarning {
  rule_id: string | null;
  message: string;
}

export interface PolicyValidation {
  valid: boolean;
  errors: ValidationIssue[];
  warnings: ValidationWarning[];
}

export interface Activation {
  version: number;
  sha256: string;
  /** ferry.policy.activate_policy also returns the warnings of the stored document. */
  warnings: ValidationWarning[];
}

/** Per-rule match detail from ferry.policy.trace. */
export interface TraceRow {
  id: string;
  effect: string;
  matched: boolean;
  principal_matched: boolean | null;
  action_matched: boolean | null;
  model_matched: boolean | null;
}

export interface Decision {
  allowed: boolean;
  decisive_rule: string | null;
  matched_rules: { id: string; effect: string }[];
  reason: string;
  limits: { max_tokens: number | null; allow_stream: boolean } | null;
  policy_version: number | null;
  policy_sha256: string | null;
  principal: string | null;
  /**
   * Beyond the section 9 table, ferry.policy.explain reports whether the app
   * exists and is enabled (a disabled app is rejected before policy), the bare
   * policy outcome, and a per-rule trace. Absent fields decode to null / [].
   */
  principal_status: string | null;
  policy_allowed: boolean | null;
  trace: TraceRow[];
}

const policyDocument = jsonText(jsonObject);

const policyStateD: Decoder<PolicyState> = object({
  active: maybe(
    object({
      version: int,
      sha256: str,
      document: policyDocument,
      created_at: str,
      created_by: str,
      activated_at: str,
      activated_by: str,
      comment: text,
    }),
  ),
  history: array(
    object({ version: int, sha256: str, created_at: str, created_by: str, comment: text, active: withDefault(flag, false) }),
  ),
});

const policyVersionD: Decoder<PolicyVersion> = object({
  version: int,
  sha256: str,
  document: policyDocument,
  created_at: str,
  created_by: str,
  comment: text,
  active: withDefault(flag, false),
});

const warningsD = withDefault(array(object({ rule_id: optText, message: str })), [] as ValidationWarning[]);

export const policyValidationD: Decoder<PolicyValidation> = object({
  valid: bool,
  errors: withDefault(array(object({ path: pathString, message: str })), [] as ValidationIssue[]),
  warnings: warningsD,
});

const activationD: Decoder<Activation> = object({ version: int, sha256: str, warnings: warningsD });

const optFlag = maybe(flag);

const decisionD: Decoder<Decision> = object({
  allowed: bool,
  decisive_rule: optText,
  matched_rules: withDefault(array(object({ id: str, effect: str })), [] as { id: string; effect: string }[]),
  reason: text,
  limits: maybe(object({ max_tokens: maybe(int), allow_stream: withDefault(bool, true) })),
  policy_version: maybe(int),
  policy_sha256: optText,
  principal: optText,
  principal_status: optText,
  policy_allowed: optFlag,
  trace: withDefault(
    array(
      object({
        id: str,
        effect: str,
        matched: flag,
        principal_matched: optFlag,
        action_matched: optFlag,
        model_matched: optFlag,
      }),
    ),
    [] as TraceRow[],
  ),
});

/**
 * The validation result attached to a 422 from POST /api/policy/activate.
 * Section 9 puts it next to `error`; ferry.policy raises it as
 * `ValidationFailed(details={"validation": ...})`, which serialises under
 * `error.details`. Both places are accepted.
 */
export function activationValidation(err: ApiError): PolicyValidation | null {
  if (err.status !== 422) return null;
  const candidates: unknown[] = [];
  if (isObject(err.body)) candidates.push(err.body['validation']);
  if (isObject(err.details)) candidates.push(err.details['validation']);
  for (const candidate of candidates) {
    if (candidate === undefined || candidate === null) continue;
    try {
      return policyValidationD(candidate, 'validation');
    } catch {
      // Try the next location.
    }
  }
  return null;
}

/* ------------------------------------------------------------------ audit */

export interface AuditEvent {
  seq: number;
  event_id: string;
  ts: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource: string;
  outcome: string;
  correlation_id: string | null;
  policy_version: number | null;
  details: JsonObject;
  prev_hash: string;
  hash: string;
}

export interface AuditPage {
  items: AuditEvent[];
  next_before_seq: number | null;
}

export interface AuditFacets {
  actions: string[];
  outcomes: string[];
  actor_types: string[];
}

export interface AuditQuery {
  action?: string;
  outcome?: string;
  actor_id?: string;
  actor_type?: string;
  resource?: string;
  correlation_id?: string;
  q?: string;
  since?: string;
  until?: string;
  before_seq?: number;
  limit?: number;
}

/** ferry.audit.OUTCOMES and ACTOR_TYPES; used when /api/audit/facets is unavailable. */
export const AUDIT_OUTCOMES = ['success', 'failure', 'denied', 'error', 'unavailable', 'rejected', 'unauthenticated', 'accepted'] as const;
export const AUDIT_ACTOR_TYPES = ['admin', 'app', 'cli', 'system'] as const;

export const AUDIT_FILTER_KEYS = [
  'action',
  'outcome',
  'actor_type',
  'actor_id',
  'resource',
  'correlation_id',
  'q',
  'since',
  'until',
] as const;

export interface ChainVerification {
  ok: boolean;
  events_checked: number;
  head_seq: number;
  head_hash: string;
  first_bad_seq: number | null;
  problem: string | null;
  checkpoint_verified: boolean;
  verified_at: string;
}

const auditEventD: Decoder<AuditEvent> = object({
  seq: int,
  event_id: str,
  ts: str,
  actor_type: str,
  actor_id: str,
  action: str,
  resource: str,
  outcome: str,
  correlation_id: optText,
  policy_version: maybe(int),
  details,
  prev_hash: str,
  hash: str,
});

const auditPageD: Decoder<AuditPage> = object({ items: array(auditEventD), next_before_seq: maybe(int) });

const auditFacetsD: Decoder<AuditFacets> = object({ actions: strings, outcomes: strings, actor_types: strings });

const chainD: Decoder<ChainVerification> = object({
  ok: bool,
  events_checked: int,
  head_seq: int,
  head_hash: str,
  first_bad_seq: maybe(int),
  problem: optText,
  checkpoint_verified: withDefault(bool, false),
  verified_at: str,
});

/* ------------------------------------------------------------------ evidence and system */

export interface NetworkInventoryEntry {
  component: string;
  direction: string;
  destination: string;
  purpose: string;
  configurable: boolean | null;
  notes: string;
}

export interface Dependency {
  name: string;
  version: string;
}

/**
 * Evidence report (spec section 10). Sections whose columns the spec does not
 * fix are kept as JSON objects and rendered generically.
 */
export interface Evidence {
  generated_at: string;
  ferry_version: string;
  host: JsonObject | null;
  config: JsonObject | null;
  import_policy: JsonObject | null;
  trust_anchors: JsonObject[];
  bundles: JsonObject[];
  routes: JsonObject[];
  active_policy: JsonObject | null;
  policy_history: JsonObject[];
  audit: JsonObject | null;
  network_inventory: NetworkInventoryEntry[];
  dependencies: Dependency[];
}

export interface SystemInfo {
  version: string;
  python: string;
  platform: string;
  config: JsonObject;
  network_inventory: NetworkInventoryEntry[];
  dependencies: Dependency[];
}

const inventoryD: Decoder<NetworkInventoryEntry[]> = withDefault(
  array(
    object({
      component: displayText,
      direction: displayText,
      destination: displayText,
      purpose: displayText,
      configurable: maybe(flag),
      notes: displayText,
    }),
  ),
  [] as NetworkInventoryEntry[],
);

const dependenciesD: Decoder<Dependency[]> = withDefault(
  array(object({ name: str, version: displayText })),
  [] as Dependency[],
);

const objects = withDefault(array(jsonObject), [] as JsonObject[]);

const evidenceD: Decoder<Evidence> = object({
  generated_at: str,
  ferry_version: str,
  host: maybe(jsonObject),
  config: maybe(jsonObject),
  import_policy: maybe(jsonObject),
  trust_anchors: objects,
  bundles: objects,
  routes: objects,
  active_policy: maybe(jsonObject),
  policy_history: objects,
  audit: maybe(jsonObject),
  network_inventory: inventoryD,
  dependencies: dependenciesD,
});

const systemD: Decoder<SystemInfo> = object({
  version: str,
  python: text,
  platform: text,
  config: withDefault(jsonObject, {} as JsonObject),
  network_inventory: inventoryD,
  dependencies: dependenciesD,
});

/* ------------------------------------------------------------------ endpoints */

const items = <T>(d: Decoder<T>): Decoder<T[]> => map(object({ items: array(d) }), (r) => r.items);

export const AUDIT_EXPORT_URL = '/api/audit/export';
export const EVIDENCE_JSON_URL = '/api/evidence';
export const EVIDENCE_MD_URL = '/api/evidence.md';

type Signal = AbortSignal | undefined;

const get = <T>(path: string, decoder: Decoder<T>, signal: Signal, query?: Record<string, QueryValue>): Promise<T> =>
  request('GET', path, { decoder, signal, ...(query ? { query } : {}) });

export const api = {
  login: (username: string, password: string): Promise<User> =>
    request('POST', '/api/auth/login', { body: { username, password }, decoder: userEnvelope, quiet401: true }).then(
      (r) => r.user,
    ),
  logout: (): Promise<void> => request('POST', '/api/auth/logout', { decoder: noContent, quiet401: true }),
  me: (signal?: AbortSignal): Promise<User> =>
    request('GET', '/api/auth/me', { decoder: userEnvelope, quiet401: true, ...(signal ? { signal } : {}) }).then(
      (r) => r.user,
    ),

  overview: (signal?: AbortSignal) => get('/api/overview', overviewD, signal),

  inbox: (signal?: AbortSignal) => get('/api/inbox', inboxD, signal),
  verifyInbox: (name: string) =>
    request('POST', '/api/inbox/verify', { body: { name }, decoder: jobRefD }).then((r) => r.job_id),
  importInbox: (name: string) =>
    request('POST', '/api/inbox/import', { body: { name }, decoder: jobRefD }).then((r) => r.job_id),
  job: (jobId: string, signal?: AbortSignal) => get(`/api/jobs/${seg(jobId)}`, jobD, signal),

  verifications: (limit: number, signal?: AbortSignal) =>
    get('/api/verifications', items(verificationSummaryD), signal, { limit }),
  verification: (id: number, signal?: AbortSignal) => get(`/api/verifications/${seg(id)}`, verificationRecordD, signal),
  bundles: (signal?: AbortSignal) => get('/api/bundles', items(bundleSummaryD), signal),
  bundle: (bundleId: string, signal?: AbortSignal) => get(`/api/bundles/${seg(bundleId)}`, bundleDetailD, signal),
  trust: (signal?: AbortSignal) => get('/api/trust', trustD, signal),

  models: (signal?: AbortSignal) => get('/api/models', items(modelArtifactD), signal),
  backends: (signal?: AbortSignal) => get('/api/backends', items(backendD), signal),
  createBackend: (input: BackendInput) => request('POST', '/api/backends', { body: input, decoder: backendD }),
  updateBackend: (id: number, patch: BackendPatch) =>
    request('PATCH', `/api/backends/${seg(id)}`, { body: patch, decoder: backendD }),
  deleteBackend: (id: number) => request('DELETE', `/api/backends/${seg(id)}`, { decoder: noContent }),
  checkBackend: (id: number) => request('POST', `/api/backends/${seg(id)}/check`, { decoder: backendCheckD }),
  routes: (signal?: AbortSignal) => get('/api/routes', items(routeD), signal),
  createRoute: (input: RouteInput) => request('POST', '/api/routes', { body: input, decoder: routeD }),
  updateRoute: (id: number, patch: RoutePatch) =>
    request('PATCH', `/api/routes/${seg(id)}`, { body: patch, decoder: routeD }),
  deleteRoute: (id: number) => request('DELETE', `/api/routes/${seg(id)}`, { decoder: noContent }),

  apps: (signal?: AbortSignal) => get('/api/apps', items(appD), signal),
  createApp: (input: AppInput) => request('POST', '/api/apps', { body: input, decoder: appD }),
  updateApp: (id: number, patch: AppPatch) => request('PATCH', `/api/apps/${seg(id)}`, { body: patch, decoder: appD }),
  issueKey: (appId: number, expiresInDays: number | null) =>
    request('POST', `/api/apps/${seg(appId)}/keys`, {
      body: expiresInDays === null ? {} : { expires_in_days: expiresInDays },
      decoder: issuedKeyD,
    }),
  revokeKey: (keyId: string) => request('POST', `/api/keys/${seg(keyId)}/revoke`, { decoder: apiKeyD }),

  policy: (signal?: AbortSignal) => get('/api/policy', policyStateD, signal),
  policyVersion: (version: number, signal?: AbortSignal) => get(`/api/policy/${seg(version)}`, policyVersionD, signal),
  validatePolicy: (document: unknown) =>
    request('POST', '/api/policy/validate', { body: { document }, decoder: policyValidationD }),
  activatePolicy: (document: unknown, comment: string) =>
    request('POST', '/api/policy/activate', { body: { document, comment }, decoder: activationD }),
  explain: (input: { app: string; action: PolicyAction; model: string }) =>
    request('POST', '/api/policy/explain', { body: input, decoder: decisionD }),

  audit: (query: AuditQuery, signal?: AbortSignal) =>
    get('/api/audit', auditPageD, signal, query as Record<string, QueryValue>),
  auditFacets: (signal?: AbortSignal) => get('/api/audit/facets', auditFacetsD, signal),
  auditEvent: (seq: number, signal?: AbortSignal) => get(`/api/audit/${seg(seq)}`, auditEventD, signal),
  verifyAudit: () => request('POST', '/api/audit/verify', { decoder: chainD }),

  evidence: (signal?: AbortSignal) => get(EVIDENCE_JSON_URL, evidenceD, signal),
  system: (signal?: AbortSignal) => get('/api/system', systemD, signal),
};
