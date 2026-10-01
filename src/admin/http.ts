export interface Pagination {
  limit: number;
  offset: number;
}

const MAX_LIMIT = 200;

export function jsonResponse(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
}

export function errorResponse(status: number, code: string, message?: string, headers?: HeadersInit): Response {
  return Response.json(
    message === undefined ? { error: code } : { error: code, message },
    { status, headers: { "Cache-Control": "no-store", ...headers } },
  );
}

export async function parseJsonBody(request: Request): Promise<Record<string, unknown> | Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "invalid_json", "Request body must be valid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return errorResponse(400, "invalid_json", "Request body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

export function parsePagination(url: URL): Pagination | Response {
  const limit = coercePaginationValue(url.searchParams.get("limit"), 50);
  const offset = coercePaginationValue(url.searchParams.get("offset"), 0);
  if (limit === null || limit < 1 || limit > MAX_LIMIT) {
    return errorResponse(400, "invalid_request", `limit must be an integer between 1 and ${MAX_LIMIT}`);
  }
  if (offset === null || offset < 0) {
    return errorResponse(400, "invalid_request", "offset must be a non-negative integer");
  }
  return { limit, offset };
}

/** Absent parameters fall back to the default; present-but-invalid ones are rejected. */
function coercePaginationValue(raw: string | null, fallback: number): number | null {
  if (raw === null || raw.length === 0) return fallback;
  if (!/^-?\d+$/.test(raw)) return null;
  return Number.parseInt(raw, 10);
}

export function parseJsonValue(value: string | null): unknown {
  if (value === null || value.length === 0) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function parseJsonArray(value: string | null): string[] {
  const parsed = parseJsonValue(value);
  if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "string")) return [];
  return parsed;
}

/**
 * Mutations are JSON-only and same-origin. Browsers always send `Origin` (and
 * `Sec-Fetch-Site`) on unsafe methods, so a request with neither header is a
 * non-browser client and is allowed through — the Access JWT is still required.
 */
export function checkMutationGuard(request: Request): Response | null {
  if (request.method === "GET" || request.method === "HEAD") return null;

  const contentType = (request.headers.get("Content-Type") ?? "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    return errorResponse(415, "unsupported_media_type", "Admin mutations must send Content-Type: application/json");
  }

  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  if (origin !== null && origin !== `${url.protocol}//${url.host}`) {
    return errorResponse(403, "cross_origin_rejected", "Cross-origin admin mutations are not allowed");
  }

  const site = request.headers.get("Sec-Fetch-Site");
  if (site !== null && site !== "same-origin") {
    return errorResponse(403, "cross_origin_rejected", "Cross-site admin mutations are not allowed");
  }

  return null;
}

export { matchRoute } from "../http/route";

export function rejectUnknownFields(body: Record<string, unknown>, allowed: readonly string[]): Response | null {
  const unknown = Object.keys(body).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    return errorResponse(400, "invalid_request", `Unknown fields: ${unknown.join(", ")}`);
  }
  return null;
}

export function requireString(body: Record<string, unknown>, key: string): string | Response {
  const value = body[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    return errorResponse(400, "invalid_request", `${key} must be a non-empty string`);
  }
  return value.trim();
}

export function optionalString(body: Record<string, unknown>, key: string): string | undefined | Response {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim().length === 0) {
    return errorResponse(400, "invalid_request", `${key} must be a non-empty string`);
  }
  return value.trim();
}

export function optionalBoolean(body: Record<string, unknown>, key: string): boolean | undefined | Response {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") {
    return errorResponse(400, "invalid_request", `${key} must be a boolean`);
  }
  return value;
}

export function optionalIntegerInRange(
  body: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
): number | undefined | Response {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    return errorResponse(400, "invalid_request", `${key} must be an integer between ${min} and ${max}`);
  }
  return value;
}
