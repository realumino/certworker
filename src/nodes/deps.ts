export interface PullOptions {
  /** Test seam: rate limit implementation (defaults to `env.PULL_LIMITER`). */
  limiter?: RateLimit;
  /** Test seam: background queue (defaults to `ctx.waitUntil`). */
  waitUntil?: (promise: Promise<unknown>) => void;
}

export interface PullDependencies {
  db: D1Database;
  bucket: R2Bucket;
  limiter: RateLimit;
  envelopeKey: string;
  /** Queue follow-up work (pull events, last-use bumps) without blocking the response. */
  background: (promise: Promise<unknown>) => void;
}

export function createPullDependencies(
  env: Env,
  ctx: Pick<ExecutionContext, "waitUntil"> | undefined,
  options: PullOptions = {},
): PullDependencies {
  return {
    db: env.DB,
    bucket: env.CERTS,
    limiter: options.limiter ?? env.PULL_LIMITER,
    envelopeKey: env.ENVELOPE_KEY,
    background: options.waitUntil ?? ((promise) => ctx?.waitUntil(promise)),
  };
}
