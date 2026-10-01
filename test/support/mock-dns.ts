import type { CapturedRequest } from "./fake-fetch";

interface MockTxtRecord {
  id: string;
  zoneId: string;
  name: string;
  content: string;
}

export class MockCloudflareDns {
  private readonly entries = new Map<string, MockTxtRecord>();

  get records(): MockTxtRecord[] {
    return [...this.entries.values()];
  }

  async handle({ request, url }: CapturedRequest): Promise<Response | undefined> {
    if (url.origin === "https://api.cloudflare.com") {
      const recordPath = url.pathname.match(/^\/client\/v4\/zones\/([^/]+)\/dns_records(?:\/([^/]+))?$/);
      if (!recordPath) return undefined;
      const zoneId = decodeURIComponent(recordPath[1]);

      if (request.method === "POST" && !recordPath[2]) {
        const body: unknown = await request.json();
        if (!isObject(body) || body.type !== "TXT" || typeof body.name !== "string" || typeof body.content !== "string") {
          return json({ success: false, errors: [{ message: "Invalid TXT record request" }] }, 400);
        }
        const record: MockTxtRecord = {
          id: crypto.randomUUID(),
          zoneId,
          name: body.name,
          content: body.content,
        };
        this.entries.set(record.id, record);
        return json({
          success: true,
          result: { ...record, type: "TXT" },
        }, 200);
      }

      if (request.method === "DELETE" && recordPath[2]) {
        const id = decodeURIComponent(recordPath[2]);
        if (!this.entries.delete(id)) return json({ success: false, errors: [] }, 404);
        return json({ success: true, result: { id } });
      }
      return undefined;
    }

    if (
      (url.origin === "https://cloudflare-dns.com" && url.pathname === "/dns-query") ||
      (url.origin === "https://dns.google" && url.pathname === "/resolve")
    ) {
      const name = url.searchParams.get("name");
      if (!name) return json({ Status: 1, Answer: [] });
      const answer = this.records
        .filter((record) => record.name.toLowerCase() === name.toLowerCase())
        .map(({ content }) => ({ type: 16, data: `"${content}"` }));
      return json({ Status: 0, Answer: answer });
    }

    return undefined;
  }
}

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
