import { usePaged } from "../hooks";
import type { PullEvent } from "../api/types";
import { EmptyRow, ErrorBanner, Page, Pager } from "../components";
import { formatDateTime, truncate } from "../format";

export function PullsView() {
  const list = usePaged<PullEvent>((offset, limit) => `/api/pulls?offset=${offset}&limit=${limit}`, []);

  return (
    <Page title="Pulls" actions={<button type="button" className="secondary" onClick={list.reload}>Refresh</button>}>
      <ErrorBanner error={list.error} />
      <p className="muted">Node pull events (the pull log is in D1 — Cloudflare Access does not log bypassed traffic).</p>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Key</th>
            <th>Domain</th>
            <th>HTTP</th>
            <th>IP</th>
            <th>User agent</th>
          </tr>
        </thead>
        <tbody>
          {list.rows.map((pull) => (
            <tr key={pull.id}>
              <td>{formatDateTime(pull.created_at)}</td>
              <td>{pull.api_key_label}</td>
              <td>{pull.domain_name}</td>
              <td>
                <span className={`badge tone-${pull.status < 300 ? "ok" : "bad"}`}>{pull.status}</span>
              </td>
              <td>{pull.ip ?? "—"}</td>
              <td title={pull.user_agent ?? undefined}>{truncate(pull.user_agent, 48)}</td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? (
            <EmptyRow colSpan={6}>No pulls recorded yet (the node pull API lands in M6).</EmptyRow>
          ) : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />
    </Page>
  );
}
