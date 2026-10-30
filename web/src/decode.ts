/**
 * Runtime validation at the JSON boundary.
 *
 * Every API response passes through a decoder before the UI sees it, so a
 * server that drifts from the contract produces an explicit error naming the
 * offending field instead of a console that silently renders wrong numbers.
 * Unknown extra fields are ignored (forward compatible); missing or mistyped
 * required fields are errors.
 */

export class DecodeError extends Error {
  readonly path: string;

  constructor(path: string, problem: string) {
    super(`${path}: ${problem}`);
    this.name = 'DecodeError';
    this.path = path;
  }
}

export type Decoder<T> = (value: unknown, path: string) => T;

export type JsonObject = Record<string, unknown>;

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

export function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export const str: Decoder<string> = (v, p) => {
  if (typeof v !== 'string') throw new DecodeError(p, `expected string, got ${describe(v)}`);
  return v;
};

export const num: Decoder<number> = (v, p) => {
  if (typeof v !== 'number' || !Number.isFinite(v)) throw new DecodeError(p, `expected number, got ${describe(v)}`);
  return v;
};

export const int: Decoder<number> = (v, p) => {
  const n = num(v, p);
  if (!Number.isInteger(n)) throw new DecodeError(p, `expected integer, got ${n}`);
  return n;
};

export const bool: Decoder<boolean> = (v, p) => {
  if (typeof v !== 'boolean') throw new DecodeError(p, `expected boolean, got ${describe(v)}`);
  return v;
};

/** SQLite stores booleans as 0/1; accept those as well as true/false. */
export const flag: Decoder<boolean> = (v, p) => {
  if (v === 0 || v === 1) return v === 1;
  return bool(v, p);
};

/** Identifiers that may be serialised as numbers or strings (job ids, backend names). */
export const idString: Decoder<string> = (v, p) => {
  if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  return str(v, p);
};

export const unknownValue: Decoder<unknown> = (v) => v;

export const jsonObject: Decoder<JsonObject> = (v, p) => {
  if (!isObject(v)) throw new DecodeError(p, `expected object, got ${describe(v)}`);
  return v;
};

/** Accepts null explicitly; a missing key is still an error. */
export function nullable<T>(d: Decoder<T>): Decoder<T | null> {
  return (v, p) => (v === null ? null : d(v, p));
}

/** Accepts a missing key or null, both normalised to null. */
export function maybe<T>(d: Decoder<T>): Decoder<T | null> {
  return (v, p) => (v === null || v === undefined ? null : d(v, p));
}

/** Uses `fallback` when the key is missing or null. */
export function withDefault<T>(d: Decoder<T>, fallback: T): Decoder<T> {
  return (v, p) => (v === null || v === undefined ? fallback : d(v, p));
}

export function array<T>(d: Decoder<T>): Decoder<T[]> {
  return (v, p) => {
    if (!Array.isArray(v)) throw new DecodeError(p, `expected array, got ${describe(v)}`);
    return v.map((item, i) => d(item, `${p}[${i}]`));
  };
}

/**
 * Defines an own property. Plain assignment would treat a key named
 * "__proto__" (which JSON.parse produces as an ordinary key) as the
 * prototype setter.
 */
function put(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

export function record<T>(d: Decoder<T>): Decoder<Record<string, T>> {
  return (v, p) => {
    const o = jsonObject(v, p);
    const out: Record<string, T> = {};
    for (const key of Object.keys(o)) put(out, key, d(o[key], `${p}.${key}`));
    return out;
  };
}

type Shape = Record<string, Decoder<unknown>>;
export type Decoded<S extends Shape> = { [K in keyof S]: ReturnType<S[K]> };

export function object<S extends Shape>(shape: S): Decoder<Decoded<S>> {
  return (v, p) => {
    const o = jsonObject(v, p);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(shape)) {
      const d = shape[key] as Decoder<unknown>;
      put(out, key, d(Object.prototype.hasOwnProperty.call(o, key) ? o[key] : undefined, `${p}.${key}`));
    }
    return out as Decoded<S>;
  };
}

/** Adds fields from a second shape to an object decoder (detail = summary + extras). */
export function extend<A, S extends Shape>(base: Decoder<A>, extra: S): Decoder<A & Decoded<S>> {
  const more = object(extra);
  return (v, p) => ({ ...base(v, p), ...more(v, p) });
}

export function oneOf<T extends string>(values: readonly T[]): Decoder<T> {
  return (v, p) => {
    const s = str(v, p);
    if (!(values as readonly string[]).includes(s)) {
      throw new DecodeError(p, `expected one of ${values.join(', ')}, got ${JSON.stringify(s).slice(0, 40)}`);
    }
    return s as T;
  };
}

/** Tries decoders in order; reports the first failure if none match. */
export function either<A, B>(a: Decoder<A>, b: Decoder<B>): Decoder<A | B> {
  return (v, p) => {
    try {
      return a(v, p);
    } catch (first) {
      try {
        return b(v, p);
      } catch {
        throw first;
      }
    }
  };
}

export function map<A, B>(d: Decoder<A>, f: (a: A) => B): Decoder<B> {
  return (v, p) => f(d(v, p));
}

/** Some columns are stored as JSON text; accept either the text or the parsed value. */
export function jsonText<T>(d: Decoder<T>): Decoder<T> {
  return (v, p) => {
    if (typeof v === 'string') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(v);
      } catch {
        throw new DecodeError(p, 'expected JSON text that parses');
      }
      return d(parsed, p);
    }
    return d(v, p);
  };
}

export function decode<T>(d: Decoder<T>, value: unknown, root = 'response'): T {
  return d(value, root);
}
