import { useState } from "react";
import { apiFetch, query } from "../api/client";
import type { IssueRun, IssueRunStatus } from "../api/types";
import { EmptyRow, ErrorBanner, Link, Page, Pager, StatusBadge } from "../components";
import { formatDateTime, truncate } from "../format";
import { useAsync, usePaged, usePolling } from "../hooks";

const STATUSES: (IssueRunStatus | "")[] = ["", "queued", "running", "succeeded", "failed"];

export function RunsView() {
  const [status, setStatus] = useState<IssueRunStatus | "">("");
  const list = usePaged<IssueRun>(
    (offset, limit) => `/api/runs?${query({ status: status || undefined, offset, limit })}`,
    [status],
  );
  usePolling(list.reload, 5_000);

  return (
    <Page title="Issue runs" actions={<button type="button" className="secondary" onClick={list.reload}>Refresh</button>}>
      <ErrorBanner error={list.error} />
      <div className="filters">
        <label htmlFor="run-status">Status</label>
        <select id="run-status" value={status} onChange={(event) => setStatus(event.target.value as IssueRunStatus | "")}>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value === "" ? "all" : value}
            </option>
          ))}
        </select>
        <span className="muted">auto-refreshes every 5 s</span>
      </div>

      <table>
        <thead>
          <tr>
            <th>Started</th>
            <th>Domain</th>
            <th>Trigger</th>
            <th>Status</th>
            <th>Phase</th>
            <th>Error</th>
          </tr>
        </thead>
        <tbody>
          {list.rows.map((run) => (
            <tr key={run.id}>
              <td>
                <Link to={`/runs/${run.id}`}>{formatDateTime(run.started_at ?? run.finished_at)}</Link>
              </td>
              <td>
                <Link to={`/certificates?domain_id=${run.domain_id}`}>{run.domain_name ?? run.domain_id}</Link>
              </td>
              <td>{run.trigger}</td>
              <td>
                <StatusBadge status={run.status} />
              </td>
              <td>{run.phase ?? "—"}</td>
              <td title={run.error ?? undefined}>{truncate(run.error, 60)}</td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={6}>No issue runs yet.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />
    </Page>
  );
}

export function RunDetailView({ runId }: { runId: string }) {
  const { data: run, error, loading, reload } = useAsync<IssueRun>(
    (signal) => apiFetch(`/api/runs/${runId}`, { signal }),
    [runId],
  );
  const finished = run !== null && run.finished_at !== null;
  usePolling(reload, finished ? null : 5_000);

  return (
    <Page title="Issue run" actions={<button type="button" className="secondary" onClick={reload}>Refresh</button>}>
      <ErrorBanner error={error} />
      {loading && !run ? <p className="muted">Loading…</p> : null}
      {run ? (
        <>
          <div className="detail">
            <dl>
              <dt>Run</dt>
              <dd>
                <code>{run.id}</code>
              </dd>
              <dt>Domain</dt>
              <dd>
                <Link to={`/certificates?domain_id=${run.domain_id}`}>{run.domain_name ?? run.domain_id}</Link>
              </dd>
              <dt>Status</dt>
              <dd>
                <StatusBadge status={run.status} /> <span className="muted">{run.phase ?? ""}</span>
              </dd>
              <dt>Trigger</dt>
              <dd>{run.trigger}</dd>
              <dt>Workflow</dt>
              <dd>
                <code>{run.workflow_id}</code>
              </dd>
              <dt>Started</dt>
              <dd>{formatDateTime(run.started_at)}</dd>
              <dt>Finished</dt>
              <dd>{formatDateTime(run.finished_at)}</dd>
            </dl>
          </div>

          <div className="detail">
            <h2>Steps</h2>
            {run.steps.length === 0 ? (
              <p className="muted">No steps recorded yet.</p>
            ) : (
              <ul className="steps">
                {run.steps.map((step, index) => (
                  <li key={`${step.phase}-${index}`}>
                    <span className="phase">{step.phase}</span>
                    <span className="muted">{formatDateTime(step.at)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {run.error ? (
            <div className="detail">
              <h2>CA error (verbatim)</h2>
              <pre className="pre-error">{run.error}</pre>
            </div>
          ) : null}
        </>
      ) : null}
    </Page>
  );
}
