/** Test support: a hand-rolled fetch stub (no MSW) that records requests. */
import { vi } from "vitest";

export interface RecordedRequest {
  method: string;
  path: string;
  body: unknown;
}

export type RouteResponder = (request: RecordedRequest) => Response;

export interface FetchStub {
  requests: RecordedRequest[];
}

export function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Install a global fetch stub. `routes` maps `"GET /api/keys"` to a responder;
 * unstubbed requests throw so a test never passes on a silent 404.
 */
export function installFetchStub(routes: Record<string, RouteResponder>): FetchStub {
  const requests: RecordedRequest[] = [];

  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "https://certworker.example.org");
    const method = (init?.method ?? "GET").toUpperCase();
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
    const request: RecordedRequest = { method, path: url.pathname + url.search, body };
    requests.push(request);

    const responder = routes[`${method} ${url.pathname}`];
    if (!responder) throw new Error(`Unstubbed request: ${method} ${url.pathname}`);
    return responder(request);
  });

  return { requests };
}
