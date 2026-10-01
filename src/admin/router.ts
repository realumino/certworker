import { accessConfigFromEnv, verifyAccessRequest } from "../auth/access";
import { listAuditHandler } from "./audit";
import { createDomainHandler, deleteDomainHandler, getDomainHandler, issueDomainHandler, listDomainsHandler, listZonesHandler, updateDomainHandler } from "./domains";
import { downloadCertificateHandler, getCertificateHandler, listCertificatesHandler } from "./certificates";
import { createAdminDependencies, type AdminHandler, type AdminOptions } from "./deps";
import { checkMutationGuard, errorResponse, matchRoute } from "./http";
import { getOverviewHandler } from "./overview";
import { createKeyHandler, listKeysHandler, revokeKeyHandler, rotateKeyHandler } from "./keys";
import { listPullsHandler } from "./pulls";
import { getRunHandler, listRunsHandler } from "./runs";

interface Route {
  method: string;
  pattern: string;
  handler: AdminHandler;
}

const ROUTES: Route[] = [
  { method: "GET", pattern: "/api/overview", handler: getOverviewHandler },
  { method: "GET", pattern: "/api/zones", handler: listZonesHandler },
  { method: "GET", pattern: "/api/domains", handler: listDomainsHandler },
  { method: "POST", pattern: "/api/domains", handler: createDomainHandler },
  { method: "GET", pattern: "/api/domains/:id", handler: getDomainHandler },
  { method: "PATCH", pattern: "/api/domains/:id", handler: updateDomainHandler },
  { method: "DELETE", pattern: "/api/domains/:id", handler: deleteDomainHandler },
  { method: "POST", pattern: "/api/domains/:id/issue", handler: issueDomainHandler },
  { method: "GET", pattern: "/api/certificates", handler: listCertificatesHandler },
  { method: "GET", pattern: "/api/certificates/:id", handler: getCertificateHandler },
  { method: "GET", pattern: "/api/certificates/:id/download", handler: downloadCertificateHandler },
  { method: "GET", pattern: "/api/runs", handler: listRunsHandler },
  { method: "GET", pattern: "/api/runs/:id", handler: getRunHandler },
  { method: "GET", pattern: "/api/keys", handler: listKeysHandler },
  { method: "POST", pattern: "/api/keys", handler: createKeyHandler },
  { method: "POST", pattern: "/api/keys/:id/revoke", handler: revokeKeyHandler },
  { method: "POST", pattern: "/api/keys/:id/rotate", handler: rotateKeyHandler },
  { method: "GET", pattern: "/api/pulls", handler: listPullsHandler },
  { method: "GET", pattern: "/api/audit", handler: listAuditHandler },
];

/** Admin API — Access app A (JWT re-verified in the Worker) + mutation audit. */
export async function handleAdminApi(request: Request, env: Env, options: AdminOptions = {}): Promise<Response> {
  const identity = await verifyAccessRequest(
    request,
    options.access ?? accessConfigFromEnv(env),
    { fetcher: options.fetcher },
  );
  if (identity instanceof Response) return identity;

  const denied = checkMutationGuard(request);
  if (denied) return denied;

  const deps = createAdminDependencies(env, identity.actor, options);

  const url = new URL(request.url);
  const allowed: string[] = [];
  for (const route of ROUTES) {
    const params = matchRoute(route.pattern, url.pathname);
    if (params === null) continue;
    if (route.method !== request.method) {
      allowed.push(route.method);
      continue;
    }
    try {
      return await route.handler(deps, request, params);
    } catch (error) {
      console.error(JSON.stringify({
        event: "admin.request_failed",
        method: request.method,
        path: url.pathname,
        error: error instanceof Error ? error.message : String(error),
      }));
      return errorResponse(500, "internal_error", "The admin request failed");
    }
  }

  if (allowed.length > 0) {
    return errorResponse(405, "method_not_allowed", undefined, { Allow: allowed.join(", ") });
  }
  return errorResponse(404, "not_found");
}
