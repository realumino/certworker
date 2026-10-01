import { useState } from "react";
import { query } from "../api/client";
import type { AuditEntry } from "../api/types";
import { EmptyRow, ErrorBanner, Page, Pager } from "../components";
import { formatDateTime, truncate } from "../format";
import { usePaged } from "../hooks";

export function AuditView() {
  const [action, setAction] = useState("");
  const list = usePaged<AuditEntry>(
    (offset, limit) => `/api/audit?${query({ action: action.trim() || undefined, offset, limit })}`,
    [action],
  );

  return (
    <Page title="Audit" actions={<button type="button" className="secondary" onClick={list.reload}>Refresh</button>}>
      <ErrorBanner error={list.error} />
      <div className="filters">
        <label htmlFor="audit-action">Action contains</label>
        <input
          id="audit-action"
          value={action}
          onChange={(event) => setAction(event.target.value)}
          placeholder="domain.create"
          size={20}
        />
      </div>

      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {list.rows.map((entry) => (
            <tr key={entry.id}>
              <td>{formatDateTime(entry.created_at)}</td>
              <td>{entry.actor}</td>
              <td>
                <code>{entry.action}</code>
              </td>
              <td>
                <code>{truncate(entry.target, 24)}</code>
              </td>
              <td title={formatMeta(entry.meta) ?? undefined}>{truncate(formatMeta(entry.meta), 60)}</td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={5}>No audit entries yet.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />
    </Page>
  );
}

function formatMeta(meta: unknown): string | null {
  if (meta === null || meta === undefined) return null;
  return JSON.stringify(meta);
}
