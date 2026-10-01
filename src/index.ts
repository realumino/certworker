export { CertificateWorkflow } from "./issue/workflow";

import { handleAdminApi } from "./admin/router";
import { runCron } from "./issue/cron";
import { handlePullApi } from "./nodes/router";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/api" || pathname.startsWith("/api/")) {
      return handleAdminApi(request, env);
    }
    if (pathname === "/v1" || pathname.startsWith("/v1/")) {
      return handlePullApi(request, env, ctx);
    }

    // Only reached when the worker is invoked for a non-API path; the asset
    // router normally answers these directly (run_worker_first in wrangler.jsonc).
    return env.ASSETS.fetch(request);
  },

  async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    try {
      const outcome = await runCron(env, { now: new Date(controller.scheduledTime) });
      console.log(JSON.stringify({
        event: "cron.complete",
        cron: controller.cron,
        date: outcome.date,
        due: outcome.due,
        started: outcome.started.length,
        skipped: outcome.skipped.length,
        sweeper: outcome.sweeper,
      }));
    } catch (error) {
      console.error(JSON.stringify({
        event: "cron.failed",
        cron: controller.cron,
        error: error instanceof Error ? error.message : String(error),
      }));
      // Retrying is safe: renewal IDs are date-scoped and the sweeper is idempotent.
      throw error;
    }
  },
} satisfies ExportedHandler<Env>;
