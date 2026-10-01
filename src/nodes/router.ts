import { authenticateApiKey, type ApiKeyIdentity } from "../auth/api-key";
import { matchRoute } from "../http/route";
import { createPullDependencies, type PullDependencies, type PullOptions } from "./deps";
import {
  certificateManifestHandler,
  listPullDomainsHandler,
  meHandler,
  pullError,
  pullFileHandler,
  resolveScopedDomain,
  type PullContext,
} from "./handlers";

interface Route {
  pattern: string;
  handler: (context: PullContext, params: Record<string, string>) => Promise<Response>;
}

/**
 * Per-domain handlers need the resolved row (scope check, pull events), so the
 * route table wraps them with `withScopedDomain`.
 */
const ROUTES: Route[] = [
  { pattern: "/v1/me", handler: (context) => meHandler(context.deps, context.identity) },
  { pattern: "/v1/domains", handler: (context) => listPullDomainsHandler(context.deps, context.identity) },
  {
    pattern: "/v1/domains/:name/cert",
    handler: async (context, params) => {
      const scoped = await resolveScopedDomain(context, params.name);
      return scoped.response ?? certificateManifestHandler(context, scoped.domain);
    },
  },
  {
    pattern: "/v1/domains/:name/files/:file",
    handler: async (context, params) => {
      const scoped = await resolveScopedDomain(context, params.name);
      return scoped.response ?? pullFileHandler(context, scoped.domain, params.file);
    },
  },
];

/** Node pull API — Access app B (bypass). Bearer key auth, ETags, rate limit. */
export async function handlePullApi(
  request: Request,
  env: Env,
  ctx?: Pick<ExecutionContext, "waitUntil">,
  options: PullOptions = {},
): Promise<Response> {
  const deps = createPullDependencies(env, ctx, options);
  try {
    return await dispatch(deps, request);
  } catch (error) {
    console.error(JSON.stringify({
      event: "pull.request_failed",
      method: request.method,
      path: new URL(request.url).pathname,
      error: error instanceof Error ? error.message : String(error),
    }));
    return pullError(500, "internal_error", "The pull request failed");
  }
}

async function dispatch(deps: PullDependencies, request: Request): Promise<Response> {
  if (request.method !== "GET") {
    return pullError(405, "method_not_allowed", "Only GET is supported", { Allow: "GET" });
  }

  const identity = await authenticateApiKey(request, deps.db);
  if (identity instanceof Response) return identity;

  // Applied after authentication so the limit is charged to a real key.
  const outcome = await deps.limiter.limit({ key: `pull:${identity.key.id}` });
  if (!outcome.success) {
    return pullError(429, "rate_limited", "Too many pull requests for this API key", { "Retry-After": "60" });
  }

  const context: PullContext = { deps, identity, request };
  const pathname = new URL(request.url).pathname;
  for (const route of ROUTES) {
    const params = matchRoute(route.pattern, pathname);
    if (params === null) continue;
    return route.handler(context, params);
  }
  return pullError(404, "not_found");
}
