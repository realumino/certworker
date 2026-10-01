import { apiFetch } from "../api/client";
import type { Overview } from "../api/types";
import { ErrorBanner, Link, Page } from "../components";
import { formatDateTime, formatExpiry, truncate } from "../format";
import { useAsync, usePolling } from "../hooks";

export function OverviewView() {
  const { data, error, loading, reload } = useAsync<Overview>((signal) => apiFetch("/api/overview", { signal }), []);
  usePolling(reload, 30_000);

  return (
    <Page title="Overview" actions={<button type="button" className="secondary" onClick={reload}>Refresh</button>}>
      <ErrorBanner error={error} />
      {data ? (
        <div className="cards">
          <div className="card">
            <h2>Domains</h2>
            <Stat label="Active" value={data.domains.active} />
            <Stat label="Paused" value={data.domains.paused} />
            <Stat label="Deleted" value={data.domains.deleted} />
            <p>
              <Link to="/domains">All domains →</Link>
            </p>
          </div>

          <div className="card">
            <h2>Certificates</h2>
            <Stat label="Current" value={data.certificates.current} />
            <Stat label="Expiring within 30 days" value={data.certificates.expiring_within_30_days} />
            <Stat label="Next expiry" value={formatExpiry(data.certificates.next_expiry)} />
            <p>
              <Link to="/certificates">Certificate history →</Link>
            </p>
          </div>

          <div className="card">
            <h2>Issue runs</h2>
            <Stat label="Queued" value={data.runs.queued} />
            <Stat label="Running" value={data.runs.running} />
            <Stat label="Failed (24 h)" value={data.runs.failed_last_24h} />
            {data.runs.latest_failure ? (
              <p className="muted">
                Latest failure <Link to={`/runs/${data.runs.latest_failure.id}`}>{truncate(data.runs.latest_failure.error, 60)}</Link>
                {" · "}
                {formatDateTime(data.runs.latest_failure.finished_at)}
              </p>
            ) : (
              <p className="muted">No failures in the last 24 h.</p>
            )}
            <p>
              <Link to="/runs">All runs →</Link>
            </p>
          </div>

          <div className="card">
            <h2>API keys</h2>
            <Stat label="Active" value={data.keys.active} />
            <Stat label="Revoked" value={data.keys.revoked} />
            <Stat label="Last pull" value={formatDateTime(data.keys.last_used_at)} />
            <p>
              <Link to="/keys">Manage keys →</Link>
            </p>
          </div>
        </div>
      ) : loading ? (
        <p className="muted">Loading…</p>
      ) : null}
    </Page>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="stat">
      <span className="muted">{label}</span>
      <b>{value}</b>
    </div>
  );
}
