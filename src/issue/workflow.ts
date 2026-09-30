import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";

/** Certificate issuance workflow. Full pipeline (PLAN.md section 8) lands in M3. */
export class CertificateWorkflow extends WorkflowEntrypoint<Env> {
  async run(_event: Readonly<WorkflowEvent<unknown>>, _step: WorkflowStep): Promise<void> {
    // M3: load -> ensure-account -> new-order -> publish-txt -> wait-propagation ->
    // accept-challenges -> await-authz -> key+csr -> finalize+store -> purge-previous -> cleanup-txt.
  }
}
