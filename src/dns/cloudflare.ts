import { normalizeDomainName } from "../acme/dns01";

const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";

export interface CloudflareApiErrorItem {
  code?: number;
  message: string;
}

export class CloudflareApiError extends Error {
  constructor(
    readonly status: number,
    readonly errors: CloudflareApiErrorItem[],
    message?: string,
  ) {
    const detail = errors.map((error) => error.message).filter(Boolean).join("; ");
    super(message || detail || `Cloudflare DNS API returned HTTP ${status}`);
    this.name = "CloudflareApiError";
  }
}

export interface CloudflareRequestOptions {
  apiToken: string;
  fetch?: typeof fetch;
  apiBaseUrl?: string;
  requestTimeoutMs?: number;
}

export interface FindZoneOptions extends CloudflareRequestOptions {
  domain: string;
}

export interface CreateTxtRecordOptions extends CloudflareRequestOptions {
  zoneId: string;
  name: string;
  value: string;
  ttl?: number;
}

export interface DeleteTxtRecordOptions extends CloudflareRequestOptions {
  zoneId: string;
  recordId: string;
}

interface CloudflareEnvelope {
  success: boolean;
  errors?: CloudflareApiErrorItem[];
  messages?: CloudflareApiErrorItem[];
  result?: unknown;
}

interface CloudflareZone {
  id: string;
  name: string;
  status?: string;
}
export type { CloudflareZone };

interface CloudflareDnsRecord {
  id: string;
  name: string;
  content: string;
  type: string;
}

export async function findZoneId(options: FindZoneOptions): Promise<string> {
  const normalized = normalizeDomainName(options.domain).replace(/^\*\./, "");
  const labels = normalized.split(".");

  for (let index = 0; index <= labels.length - 2; index += 1) {
    const candidate = labels.slice(index).join(".");
    const url = makeUrl(options.apiBaseUrl, `/zones?name=${encodeURIComponent(candidate)}&per_page=50`);
    const zones = await cloudflareRequest(
      options,
      url,
      { method: "GET" },
      "Zone:Zone:Read",
      isCloudflareZoneList,
    );
    const zone = zones.find((entry) => entry.name.toLowerCase() === candidate);
    if (zone) {
      if (zone.status !== undefined && zone.status !== "active") {
        throw new CloudflareApiError(409, [], `Cloudflare zone ${candidate} is ${zone.status}, not active`);
      }
      return zone.id;
    }
  }

  throw new CloudflareApiError(
    404,
    [],
    `No Cloudflare zone found for ${normalized}; check Zone:Zone:Read access and the token's zone scope`,
  );
}

export interface ListZonesOptions extends CloudflareRequestOptions {
  perPage?: number;
}

export interface GetZoneOptions extends CloudflareRequestOptions {
  zoneId: string;
}

export async function listZones(options: ListZonesOptions): Promise<CloudflareZone[]> {
  const perPage = options.perPage ?? 50;
  const url = makeUrl(options.apiBaseUrl, `/zones?per_page=${perPage}`);
  return cloudflareRequest(
    options,
    url,
    { method: "GET" },
    "Zone:Zone:Read",
    isCloudflareZoneList,
  );
}

export async function getZone(options: GetZoneOptions): Promise<CloudflareZone> {
  const url = makeUrl(options.apiBaseUrl, `/zones/${encodeURIComponent(options.zoneId)}`);
  return cloudflareRequest(
    options,
    url,
    { method: "GET" },
    "Zone:Zone:Read",
    isCloudflareZone,
  );
}

export async function createTxtRecord(options: CreateTxtRecordOptions): Promise<string> {
  const url = makeUrl(options.apiBaseUrl, `/zones/${encodeURIComponent(options.zoneId)}/dns_records`);
  const record = await cloudflareRequest(
    options,
    url,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "TXT",
        name: options.name,
        content: options.value,
        ttl: options.ttl ?? 60,
      }),
    },
    "Zone:DNS:Edit",
    isCloudflareDnsRecord,
  );

  if (typeof record.id !== "string" || record.id.length === 0) {
    throw new CloudflareApiError(502, [], "Cloudflare DNS API created a TXT record without returning its ID");
  }
  return record.id;
}

export async function deleteTxtRecord(options: DeleteTxtRecordOptions): Promise<void> {
  const url = makeUrl(
    options.apiBaseUrl,
    `/zones/${encodeURIComponent(options.zoneId)}/dns_records/${encodeURIComponent(options.recordId)}`,
  );
  const response = await fetchCloudflare(options, url, { method: "DELETE" });
  if (response.status === 404) return;

  const envelope = await readEnvelope(response);
  if (!response.ok || envelope.success !== true) {
    throw cloudflareError(response.status, envelope, "Zone:DNS:Edit");
  }
}

async function cloudflareRequest<T>(
  options: CloudflareRequestOptions,
  url: string,
  init: RequestInit,
  permission: string,
  isResult: (value: unknown) => value is T,
): Promise<T> {
  const response = await fetchCloudflare(options, url, init);
  const envelope = await readEnvelope(response);
  if (!response.ok || envelope.success !== true || !isResult(envelope.result)) {
    throw cloudflareError(response.status, envelope, permission);
  }
  return envelope.result;
}

async function fetchCloudflare(
  options: CloudflareRequestOptions,
  url: string,
  init: RequestInit,
): Promise<Response> {
  if (!options.apiToken.trim()) throw new TypeError("A Cloudflare API token is required");
  const fetcher = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.requestTimeoutMs ?? 30_000;
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${options.apiToken}`);
  const response = await fetcher(url, {
    ...init,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (response.status >= 300 && response.status < 400) {
    throw new CloudflareApiError(response.status || 502, [], "Cloudflare DNS API unexpectedly redirected the request");
  }
  return response;
}

async function readEnvelope(response: Response): Promise<CloudflareEnvelope> {
  const text = await response.text();
  try {
    const value: unknown = JSON.parse(text);
    if (!isObject(value)) throw new TypeError("Cloudflare response is not an object");
    return {
      success: value.success === true,
      errors: Array.isArray(value.errors) ? value.errors.filter(isApiErrorItem) : [],
      messages: Array.isArray(value.messages) ? value.messages.filter(isApiErrorItem) : [],
      result: value.result,
    };
  } catch {
    return {
      success: false,
      errors: [{ message: text || `Cloudflare DNS API returned HTTP ${response.status}` }],
    };
  }
}

function cloudflareError(
  status: number,
  envelope: CloudflareEnvelope,
  permission: string,
): CloudflareApiError {
  const errors = envelope.errors ?? [];
  const hint = status === 403 ? `Check the API token's ${permission} permission and its zone scope.` : undefined;
  const message = [errors.map((error) => error.message).filter(Boolean).join("; "), hint]
    .filter(Boolean)
    .join(" ");
  return new CloudflareApiError(status, errors, message || undefined);
}

function makeUrl(apiBaseUrl: string | undefined, path: string): string {
  const base = (apiBaseUrl ?? DEFAULT_API_BASE_URL).replace(/\/$/, "");
  return new URL(path.replace(/^\/+/, ""), `${base}/`).toString();
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isApiErrorItem(value: unknown): value is CloudflareApiErrorItem {
  return isObject(value) && typeof value.message === "string";
}

function isCloudflareZoneList(value: unknown): value is CloudflareZone[] {
  return Array.isArray(value) && value.every(isCloudflareZone);
}

function isCloudflareZone(value: unknown): value is CloudflareZone {
  return isObject(value) && typeof value.id === "string" && typeof value.name === "string" &&
    (value.status === undefined || typeof value.status === "string");
}

function isCloudflareDnsRecord(value: unknown): value is CloudflareDnsRecord {
  return isObject(value) && typeof value.id === "string" && typeof value.name === "string" &&
    typeof value.content === "string" && typeof value.type === "string";
}
