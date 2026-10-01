import { getOverview } from "../store/d1";
import type { AdminDependencies } from "./deps";
import { jsonResponse } from "./http";

export async function getOverviewHandler(deps: AdminDependencies, _request: Request): Promise<Response> {
  const stats = await getOverview(deps.db, new Date());
  return jsonResponse({
    domains: stats.domains,
    certificates: {
      current: stats.certificates.current,
      expiring_within_30_days: stats.certificates.expiringSoon,
      next_expiry: stats.certificates.nextExpiry,
    },
    runs: {
      queued: stats.runs.queued,
      running: stats.runs.running,
      failed_last_24h: stats.runs.failedLastDay,
      latest_failure: stats.runs.latestFailure,
    },
    keys: {
      active: stats.keys.active,
      revoked: stats.keys.revoked,
      last_used_at: stats.keys.lastUsedAt,
    },
  });
}
