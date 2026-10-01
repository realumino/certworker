import { findIssueRunByWorkflowId, listDueDomains } from "../store/d1";
import { ActiveIssueRunError, startIssueRun, type IssueWorkflowCreator } from "./trigger";
import { sweep, type SweepResult } from "./sweeper";

export interface CronOptions {
  now?: Date;
  /** Test seam; defaults to the `ISSUANCE` workflow binding. */
  issuance?: IssueWorkflowCreator;
  /** Test seam for the sweeper's Cloudflare DNS calls. */
  fetcher?: typeof fetch;
  /** Test seam: pass 0 to disable the random start jitter. */
  jitterMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

export interface CronOutcome {
  /** UTC date the workflow IDs were scoped to. */
  date: string;
  due: number;
  started: string[];
  skipped: Array<{ domainId: string; reason: string }>;
  sweeper: SweepResult;
}

const JITTER_MAX_MS = 60_000;

/**
 * Daily renewal trigger: create one issuance workflow per due domain, then run
 * the sweeper. Instance IDs are `renew-<domainId>-<yyyy-mm-dd>` (UTC), so a
 * repeated invocation on the same day skips instead of reissuing; the
 * `idx_run_active` partial unique index additionally serializes against manual
 * runs. Failures are per-domain: one broken domain never blocks the others or
 * the sweeper.
 */
export async function runCron(env: Env, options: CronOptions = {}): Promise<CronOutcome> {
  const now = options.now ?? new Date();
  const date = now.toISOString().slice(0, 10);
  const jitter = options.jitterMs ?? randomInt(JITTER_MAX_MS);
  if (jitter > 0) await (options.sleep ?? defaultSleep)(jitter);

  const issuance = options.issuance ?? env.ISSUANCE;
  const fetcher = options.fetcher ?? globalThis.fetch;
  const due = await listDueDomains(env.DB, now.toISOString());

  const started: string[] = [];
  const skipped: Array<{ domainId: string; reason: string }> = [];
  for (const domain of due) {
    const workflowId = `renew-${domain.id}-${date}`;
    try {
      if (await findIssueRunByWorkflowId(env.DB, workflowId)) {
        skipped.push({ domainId: domain.id, reason: "already_started" });
        continue;
      }
      await startIssueRun(env.DB, issuance, domain.id, { trigger: "cron", workflowId });
      started.push(domain.id);
    } catch (error) {
      if (error instanceof ActiveIssueRunError) {
        skipped.push({ domainId: domain.id, reason: "already_running" });
        continue;
      }
      skipped.push({ domainId: domain.id, reason: "workflow_create_failed" });
      console.error(JSON.stringify({
        event: "cron.workflow_create_failed",
        domainId: domain.id,
        workflowId,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }

  const sweeper = await sweep({
    db: env.DB,
    bucket: env.CERTS,
    dnsApiToken: env.CF_DNS_API_TOKEN,
    fetcher,
    now: () => now,
  });

  return { date, due: due.length, started, skipped, sweeper };
}

function randomInt(maxExclusive: number): number {
  return crypto.getRandomValues(new Uint32Array(1))[0] % maxExclusive;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
