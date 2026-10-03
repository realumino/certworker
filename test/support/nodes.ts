/** Helpers for node pull API tests (bearer tokens + a collecting waitUntil). */
import { vi } from "vitest";

/** Build a `cw_<id>.<secret>` token from the parts a seeded row was created with. */
export function bearerToken(id: string, secret: string): string {
  return `cw_${id}.${secret}`;
}

/** Node pull request (no Access headers — app B is bypassed; only the token matters). */
export function pullRequest(path: string, token?: string, init: RequestInit = {}): Request {
  const headers: Record<string, string> = {
    "CF-Connecting-IP": "203.0.113.10",
    "User-Agent": "certworker-pull/1.0",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  return new Request(`https://ssl.example.com${path}`, { ...init, headers });
}

/**
 * Collects `waitUntil` promises so background writes (pull events, last-use
 * bumps) can be awaited deterministically in tests.
 */
export function collectingContext() {
  const promises: Promise<unknown>[] = [];
  return {
    promises,
    ctx: {
      waitUntil(promise: Promise<unknown>): void {
        promises.push(promise);
      },
    },
    async settled(): Promise<void> {
      await Promise.all(promises);
    },
  };
}

/** Permissive rate limiter stub; swap in a rejecting one to test 429. */
export function stubLimiter(success = true) {
  return { limit: vi.fn(async () => ({ success })) };
}
