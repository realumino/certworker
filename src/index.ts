export { CertificateWorkflow } from "./issue/workflow";

import { handleAdminApi } from "./admin/router";
import { handlePullApi } from "./nodes/router";

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const { pathname } = new URL(request.url);

    if (pathname === "/api" || pathname.startsWith("/api/")) {
      return handleAdminApi(request, env);
    }
    if (pathname === "/v1" || pathname.startsWith("/v1/")) {
      return handlePullApi(request, env);
    }

    // Only reached when the worker is invoked for a non-API path; the asset
    // router normally answers these directly (run_worker_first in wrangler.jsonc).
    return env.ASSETS.fetch(request);
  },

  async scheduled(controller: ScheduledController, _env: Env, _ctx: ExecutionContext): Promise<void> {
    // M7: create workflow instances for due domains + run the sweeper.
    console.log(JSON.stringify({ event: "cron.stub", cron: controller.cron, at: controller.scheduledTime }));
  },
} satisfies ExportedHandler<Env>;
