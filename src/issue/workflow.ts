import {
  WorkflowEntrypoint,
  type WorkflowEvent,
  type WorkflowStep,
  type WorkflowStepConfig,
} from "cloudflare:workers";
import { finishIssueRun, recordRunPhase, type CertificateRow } from "../store/d1";
import {
  acceptChallenges,
  awaitAuthorizations,
  cleanupFailedArtifacts,
  cleanupTxtRecords,
  createIssueDependencies,
  createLeafKeyAndCsr,
  createOrder,
  ensureAcmeAccount,
  finalizeAndStore,
  issueErrorMessage,
  loadIssue,
  publishTxtChallenges,
  purgePreviousCertificate,
  waitForPropagation,
} from "./steps";
import type { IssuePayload } from "./types";

const NEW_ORDER_CONFIG: WorkflowStepConfig = {
  retries: { limit: 3, delay: 10_000, backoff: "exponential" },
  timeout: "10 minutes",
};

const PURGE_CONFIG: WorkflowStepConfig = {
  retries: { limit: 2, delay: 10_000, backoff: "exponential" },
  timeout: "10 minutes",
};

export interface IssueWorkflowOutput {
  runId: string;
  status: "succeeded" | "failed";
  certificateId?: string;
  error?: string;
}

/** Durable ACME DNS-01 issuance, artifact persistence, and cleanup pipeline. */
export class CertificateWorkflow extends WorkflowEntrypoint<Env, IssuePayload> {
  async run(
    event: Readonly<WorkflowEvent<IssuePayload>>,
    step: WorkflowStep,
  ): Promise<IssueWorkflowOutput> {
    const { runId, domainId } = event.payload;
    const deps = createIssueDependencies(this.env);
    let previousCertificate: CertificateRow | null = null;
    let domainName: string | undefined;
    let certificateId: string | undefined;
    let failure: unknown;
    let hasFailure = false;

    try {
      await this.phase(step, runId, "load");
      const loaded = await step.do("load", async () => loadIssue(deps, runId, domainId));
      domainName = loaded.domain.name;
      previousCertificate = loaded.previousCertificate;

      await this.phase(step, runId, "ensure-account");
      const account = await step.do("ensure-account", async () => ensureAcmeAccount(deps));

      await this.phase(step, runId, "new-order");
      const order = await step.do(
        "new-order",
        NEW_ORDER_CONFIG,
        async () => createOrder(deps, account, loaded.identifiers),
      );

      await this.phase(step, runId, "publish-txt");
      const published = await step.do(
        "publish-txt",
        async () => publishTxtChallenges(deps, runId, loaded.domain, account, order.authorizations),
      );

      await this.phase(step, runId, "wait-propagation");
      await step.do("wait-propagation", async () => waitForPropagation(deps, published));

      await this.phase(step, runId, "accept-challenges");
      await step.do("accept-challenges", async () => acceptChallenges(deps, account, published));

      await this.phase(step, runId, "await-authz");
      await step.do("await-authz", async () => awaitAuthorizations(deps, account, published));

      await this.phase(step, runId, "key+csr");
      const leaf = await step.do(
        "key+csr",
        async () => createLeafKeyAndCsr(deps, runId, loaded.domain, loaded.identifiers),
      );

      await this.phase(step, runId, "finalize+store");
      const certificate = await step.do(
        "finalize+store",
        async () => finalizeAndStore(deps, loaded.domain, loaded.identifiers, account, order, leaf),
      );
      certificateId = certificate.certificateId;

      try {
        await this.phase(step, runId, "purge-previous");
      } catch (error) {
        console.warn(JSON.stringify({
          event: "certificate.previous_purge_phase_failed",
          runId,
          error: issueErrorMessage(error),
        }));
      }
      try {
        const result = await step.do(
          "purge-previous",
          PURGE_CONFIG,
          async () => purgePreviousCertificate(deps, previousCertificate),
        );
        if (previousCertificate && !result.purged) {
          console.warn(JSON.stringify({ event: "certificate.previous_not_purged", runId }));
        }
      } catch (error) {
        // The M7 sweeper retries superseded prefixes whose purged_at is still NULL.
        console.warn(JSON.stringify({
          event: "certificate.previous_purge_failed",
          runId,
          error: issueErrorMessage(error),
        }));
      }
    } catch (error) {
      failure = error;
      hasFailure = true;
    }

    try {
      await this.phase(step, runId, "cleanup-txt");
    } catch (error) {
      failure = appendFailure(failure, error, hasFailure);
      hasFailure = true;
    }
    try {
      await step.do("cleanup-txt", async () => cleanupTxtRecords(deps, runId));
    } catch (error) {
      failure = appendFailure(failure, error, hasFailure);
      hasFailure = true;
    }

    if (hasFailure && domainName) {
      try {
        await this.phase(step, runId, "cleanup-failed-artifacts");
      } catch (error) {
        failure = appendFailure(failure, error, true);
      }
      try {
        await step.do("cleanup-failed-artifacts", async () => cleanupFailedArtifacts(deps, domainName, runId));
      } catch (error) {
        failure = appendFailure(failure, error, true);
      }
    }

    const status = hasFailure ? "failed" : "succeeded";
    const errorMessage = hasFailure ? issueErrorMessage(failure) : undefined;
    await step.do("finish-run", async () => finishIssueRun(
      deps.db,
      runId,
      domainId,
      hasFailure ? { status: "failed", error: errorMessage ?? "Issuance failed" } : { status: "succeeded" },
    ));

    return {
      runId,
      status,
      ...(certificateId ? { certificateId } : {}),
      ...(errorMessage ? { error: errorMessage } : {}),
    };
  }

  private async phase(step: WorkflowStep, runId: string, phase: string): Promise<void> {
    await step.do(`phase-${phase}`, async () => recordRunPhase(this.env.DB, runId, phase));
  }
}

function appendFailure(current: unknown, next: unknown, hasCurrent: boolean): unknown {
  return hasCurrent ? new AggregateError([current, next], "Issuance and cleanup both failed") : next;
}
