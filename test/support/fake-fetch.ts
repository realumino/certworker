export interface CapturedRequest {
  request: Request;
  url: URL;
  body: string;
}

export type FetchHandler = (request: CapturedRequest, index: number) => Response | Promise<Response>;

export function createScriptedFetch(handler: FetchHandler): {
  fetch: typeof globalThis.fetch;
  requests: CapturedRequest[];
} {
  const requests: CapturedRequest[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const request = input instanceof Request && init === undefined ? input : new Request(input, init);
    const body = request.method === "GET" || request.method === "HEAD" ? "" : await request.clone().text();
    const captured = { request, url: new URL(request.url), body };
    const index = requests.push(captured) - 1;
    return handler(captured, index);
  };
  return { fetch, requests };
}

export function jsonResponse(
  value: unknown,
  options: { status?: number; headers?: HeadersInit } = {},
): Response {
  const headers = new Headers(options.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(value), { status: options.status ?? 200, headers });
}

/** Read a Response body as JSON with an expected shape. */
export async function readJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}
