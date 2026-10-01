/**
 * Typed client for the admin API (src/admin/*). The contract in brief: JSON in
 * and out, `Cache-Control: no-store` everywhere, errors shaped `{error, message}`,
 * list endpoints paging with `limit`/`offset`, mutations JSON-only + same-origin
 * (the Worker enforces both — see src/admin/http.ts `checkMutationGuard`).
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  /** Serialized as a JSON object body with the content type the mutation guard requires. */
  body?: unknown;
  signal?: AbortSignal;
}

type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

/** App-level hook: a 401 at any point means the Access session is gone. */
export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export async function apiFetch<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  const response = await fetch(path, {
    method,
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });

  if (response.status === 401) {
    for (const listener of unauthorizedListeners) listener();
  }

  const payload = await readJson(response);
  if (!response.ok) {
    const { error, message } = extractError(payload);
    throw new ApiError(response.status, error, message);
  }
  return payload as T;
}

/** Build a query string, skipping empty/undefined values (`{a: 1}` → `a=1`). */
export function query(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") params.set(key, String(value));
  }
  return params.toString();
}

/** Normalize any thrown value into an ApiError for display. */
export function asApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError(0, "network_error", error instanceof Error ? error.message : String(error));
}

async function readJson(response: Response): Promise<unknown> {
  if (response.status === 204) return null;
  const text = await response.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function extractError(payload: unknown): { error: string; message: string } {
  if (typeof payload === "object" && payload !== null) {
    const body = payload as Record<string, unknown>;
    const code = typeof body.error === "string" ? body.error : "request_failed";
    const message = typeof body.message === "string" ? body.message : `Request failed (${code})`;
    return { error: code, message };
  }
  return { error: "request_failed", message: "The admin request failed" };
}
