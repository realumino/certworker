import {
  ActiveIssueRunError,
  createIssueRun,
  finishIssueRun,
  getDomain,
} from "../store/d1";
import type { IssuePayload, IssueTrigger } from "./types";

export interface IssueWorkflowCreator {
  create(options: { id: string; params: IssuePayload }): Promise<unknown>;
}

export interface StartIssueRunOptions {
  trigger: IssueTrigger;
  workflowId?: string;
}

export class IssueDomainNotFoundError extends Error {
  constructor(domainId: string) {
    super(`Domain ${domainId} does not exist`);
    this.name = "IssueDomainNotFoundError";
  }
}

export class IssueDomainNotActiveError extends Error {
  constructor(domainId: string, status: string) {
    super(`Domain ${domainId} is ${status}, not active`);
    this.name = "IssueDomainNotActiveError";
  }
}

export async function startIssueRun(
  db: D1Database,
  workflow: IssueWorkflowCreator,
  domainId: string,
  options: StartIssueRunOptions = { trigger: "manual" },
): Promise<{ runId: string; workflowId: string }> {
  const domain = await getDomain(db, domainId);
  if (!domain) throw new IssueDomainNotFoundError(domainId);
  if (domain.status !== "active") throw new IssueDomainNotActiveError(domainId, domain.status);

  const runId = crypto.randomUUID();
  const workflowId = options.workflowId ?? `${options.trigger}-${runId}`;
  await createIssueRun(db, {
    id: runId,
    domain_id: domainId,
    workflow_id: workflowId,
    trigger: options.trigger,
  });

  try {
    await workflow.create({ id: workflowId, params: { runId, domainId } });
  } catch (error) {
    try {
      await finishIssueRun(db, runId, domainId, { status: "failed", error: errorMessage(error) });
    } catch (finishError) {
      throw new AggregateError([error, finishError], "Workflow creation and issue-run failure recording both failed");
    }
    throw error;
  }

  return { runId, workflowId };
}

export { ActiveIssueRunError };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
