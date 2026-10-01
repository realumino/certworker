import { b64uEncode } from "../crypto/base64url";

export const DEFAULT_DOH_RESOLVERS = [
  { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { name: "Google", url: "https://dns.google/resolve" },
] as const;

export interface TxtTarget {
  name: string;
  values: string[];
}

export interface DnsResolver {
  name: string;
  url: string;
}

export interface PropagationOptions {
  fetch?: typeof fetch;
  wait?: (ms: number) => Promise<void>;
  now?: () => number;
  resolvers?: readonly DnsResolver[];
  timeoutMs?: number;
  pollIntervalMs?: number;
  settleMs?: number;
  requestTimeoutMs?: number;
}

export class DnsPropagationError extends Error {
  constructor(readonly missingByResolver: Record<string, string[]>) {
    const detail = Object.entries(missingByResolver)
      .map(([resolver, missing]) => `${resolver}: ${missing.join(", ") || "resolver unavailable"}`)
      .join("; ");
    super(`DNS-01 TXT records did not propagate to all resolvers (${detail})`);
    this.name = "DnsPropagationError";
  }
}

export function normalizeDomainName(input: string): string {
  const value = input.trim();
  const wildcard = value.startsWith("*.");
  const name = wildcard ? value.slice(2) : value;

  if (
    name.length === 0 ||
    name.includes("*") ||
    /[\s/\\?#@:%]/.test(name) ||
    name.startsWith(".")
  ) {
    throw new TypeError(`Invalid DNS name: ${input}`);
  }

  const withoutTrailingDot = name.endsWith(".") ? name.slice(0, -1) : name;
  if (withoutTrailingDot.length === 0) throw new TypeError(`Invalid DNS name: ${input}`);

  let ascii: string;
  try {
    ascii = new URL(`https://${withoutTrailingDot}`).hostname.toLowerCase();
  } catch {
    throw new TypeError(`Invalid DNS name: ${input}`);
  }

  if (ascii.endsWith(".")) ascii = ascii.slice(0, -1);
  const labels = ascii.split(".");
  const validLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (
    ascii.length > 253 ||
    labels.length < 2 ||
    labels.some((label) => label.length > 63 || !validLabel.test(label)) ||
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ascii)
  ) {
    throw new TypeError(`Invalid DNS name: ${input}`);
  }

  return wildcard ? `*.${ascii}` : ascii;
}

export function dns01RecordName(identifier: string): string {
  const normalized = normalizeDomainName(identifier);
  const name = normalized.startsWith("*.") ? normalized.slice(2) : normalized;
  return `_acme-challenge.${name}`;
}

export async function dns01Value(token: string, thumbprint: string): Promise<string> {
  if (!/^[A-Za-z0-9_-]+$/.test(token) || !/^[A-Za-z0-9_-]+$/.test(thumbprint)) {
    throw new TypeError("DNS-01 token and JWK thumbprint must be unpadded base64url strings");
  }

  const keyAuthorization = new TextEncoder().encode(`${token}.${thumbprint}`);
  const digest = await crypto.subtle.digest("SHA-256", keyAuthorization);
  return b64uEncode(new Uint8Array(digest));
}

export async function waitForTxtPropagation(
  targets: readonly TxtTarget[],
  options: PropagationOptions = {},
): Promise<void> {
  if (targets.length === 0) throw new TypeError("At least one DNS-01 TXT target is required");
  if (targets.some(({ name, values }) => !name || values.length === 0 || values.some((value) => !value))) {
    throw new TypeError("Every DNS-01 TXT target must have a name and at least one value");
  }

  const fetcher = options.fetch ?? globalThis.fetch;
  const wait = options.wait ?? sleep;
  const now = options.now ?? Date.now;
  const resolvers = options.resolvers ?? DEFAULT_DOH_RESOLVERS;
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  const pollIntervalMs = options.pollIntervalMs ?? 5_000;
  const settleMs = options.settleMs ?? 10_000;
  const requestTimeoutMs = options.requestTimeoutMs ?? 10_000;

  if (resolvers.length === 0) throw new TypeError("At least one DNS-over-HTTPS resolver is required");
  if (
    !Number.isFinite(timeoutMs) ||
    !Number.isFinite(pollIntervalMs) ||
    !Number.isFinite(settleMs) ||
    !Number.isFinite(requestTimeoutMs) ||
    timeoutMs < 0 ||
    pollIntervalMs <= 0 ||
    settleMs < 0 ||
    requestTimeoutMs <= 0
  ) {
    throw new RangeError("DNS propagation timeout/settle values must be non-negative; intervals must be positive");
  }

  const deadline = now() + timeoutMs;
  const maxAttempts = Math.max(1, Math.ceil(timeoutMs / Math.max(pollIntervalMs, 1)) + 2);
  const missingByResolver: Record<string, string[]> = {};
  let visibleSince: number | undefined;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const observations = await Promise.all(
      resolvers.map(async (resolver) => {
        try {
          const records = await Promise.all(
            targets.map(async (target) => ({
              target,
              records: await queryTxtRecords(target.name, resolver, fetcher, requestTimeoutMs),
            })),
          );
          const missing = records.flatMap(({ target, records: visible }) =>
            target.values
              .filter((value) => !visible.has(value))
              .map((value) => `${target.name}=${value}`),
          );
          return { name: resolver.name, missing };
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          return { name: resolver.name, missing: [`resolver error: ${message}`] };
        }
      }),
    );

    for (const observation of observations) {
      missingByResolver[observation.name] = observation.missing;
    }

    const allVisible = observations.every(({ missing }) => missing.length === 0);
    const currentTime = now();
    if (allVisible) {
      visibleSince ??= currentTime;
      if (currentTime - visibleSince >= settleMs) return;
    } else {
      visibleSince = undefined;
    }

    const remaining = deadline - currentTime;
    if (remaining <= 0) break;

    const settleRemaining = visibleSince === undefined ? pollIntervalMs : settleMs - (currentTime - visibleSince);
    await wait(Math.max(0, Math.min(pollIntervalMs, settleRemaining, remaining)));
  }

  throw new DnsPropagationError(missingByResolver);
}

async function queryTxtRecords(
  name: string,
  resolver: DnsResolver,
  fetcher: typeof fetch,
  requestTimeoutMs: number,
): Promise<Set<string>> {
  const url = new URL(resolver.url);
  if (url.protocol !== "https:") throw new TypeError("DNS-over-HTTPS resolvers must use HTTPS");
  url.searchParams.set("name", name);
  url.searchParams.set("type", "TXT");
  const response = await fetcher(url, {
    headers: { Accept: "application/dns-json" },
    cache: "no-store",
    signal: AbortSignal.timeout(requestTimeoutMs),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const body: unknown = await response.json();
  if (!isObject(body) || !Array.isArray(body.Answer)) return new Set();

  const values = body.Answer.flatMap((answer) => {
    if (!isObject(answer) || (answer.type !== 16 && answer.type !== "TXT") || typeof answer.data !== "string") {
      return [];
    }
    return [unquoteTxtData(answer.data)];
  });
  return new Set(values);
}

function unquoteTxtData(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\([\\"])/g, "$1");
  }
  return trimmed;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
