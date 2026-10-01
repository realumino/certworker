import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { getIssueRun } from "../src/store/d1";
import {
  ActiveIssueRunError,
  IssueDomainNotActiveError,
  IssueDomainNotFoundError,
  startIssueRun,
} from "../src/issue/trigger";
import type { IssuePayload } from "../src/issue/types";
import { seedDomain } from "./support/fixtures";

describe("manual issue trigger", () => {
  it("inserts a queued run before creating the workflow with a stable id", async () => {
    const domain = await seedDomain(env.DB);
    const created: Array<{ id: string; params: IssuePayload }> = [];
    const workflow = {
      async create(options: { id: string; params: IssuePayload }): Promise<unknown> {
        created.push(options);
        return { id: options.id };
      },
    };

    const started = await startIssueRun(env.DB, workflow, domain.id);

    expect(started.workflowId).toBe(`manual-${started.runId}`);
    expect(created).toEqual([{ id: started.workflowId, params: { runId: started.runId, domainId: domain.id } }]);
    expect(await getIssueRun(env.DB, started.runId)).toMatchObject({
      domain_id: domain.id,
      workflow_id: started.workflowId,
      trigger: "manual",
      status: "queued",
    });
  });

  it("rejects missing, inactive, and already-running domains", async () => {
    const workflow = { async create(): Promise<unknown> { return {}; } };
    await expect(startIssueRun(env.DB, workflow, crypto.randomUUID())).rejects.toBeInstanceOf(IssueDomainNotFoundError);

    const paused = await seedDomain(env.DB, { status: "paused" });
    await expect(startIssueRun(env.DB, workflow, paused.id)).rejects.toBeInstanceOf(IssueDomainNotActiveError);

    const active = await seedDomain(env.DB);
    const first = await startIssueRun(env.DB, workflow, active.id);
    expect(first.runId).toBeTruthy();
    await expect(startIssueRun(env.DB, workflow, active.id)).rejects.toBeInstanceOf(ActiveIssueRunError);
  });

  it("marks the D1 run failed if workflow creation fails", async () => {
    const domain = await seedDomain(env.DB);
    const workflow = {
      async create(): Promise<unknown> {
        throw new Error("workflow binding unavailable");
      },
    };

    await expect(startIssueRun(env.DB, workflow, domain.id)).rejects.toThrow("workflow binding unavailable");
    const { results } = await env.DB.prepare(
      "SELECT id FROM issue_runs WHERE domain_id = ?",
    ).bind(domain.id).all<{ id: string }>();
    const run = await getIssueRun(env.DB, results[0].id);
    expect(run).toMatchObject({ status: "failed", error: "workflow binding unavailable" });
  });
});
