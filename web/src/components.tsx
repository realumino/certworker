/** Small shared UI pieces: layout, banners, badges, modal, paging, links. */
import type { ReactNode } from "react";
import { navigate } from "./router";

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="page">
      <header className="page-header">
        <h1>{title}</h1>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

export function Link({ to, className, children }: { to: string; className?: string; children: ReactNode }) {
  return (
    <a
      href={to}
      className={className}
      onClick={(event) => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
        event.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export function ErrorBanner({ error }: { error: { code: string; message: string } | null }) {
  if (!error) return null;
  return (
    <div className="banner banner-error" role="alert">
      <strong>{error.code}</strong> {error.message}
    </div>
  );
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td className="empty" colSpan={colSpan}>
        {children}
      </td>
    </tr>
  );
}

const BADGE_TONES: Record<string, string> = {
  active: "ok",
  current: "ok",
  succeeded: "ok",
  valid: "ok",
  running: "pending",
  queued: "pending",
  paused: "pending",
  superseded: "pending",
  failed: "bad",
  revoked: "bad",
  deleted: "bad",
  invalid: "bad",
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge tone-${BADGE_TONES[status] ?? "neutral"}`}>{status}</span>;
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="modal-overlay" role="presentation" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={(event) => event.stopPropagation()}>
        <header className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        {children}
      </div>
    </div>
  );
}

export function Pager({
  hasMore,
  loading,
  onLoadMore,
}: {
  hasMore: boolean;
  loading: boolean;
  onLoadMore: () => void;
}) {
  if (!hasMore) return null;
  return (
    <div className="pager">
      <button type="button" onClick={onLoadMore} disabled={loading}>
        {loading ? "Loading…" : "Load more"}
      </button>
    </div>
  );
}
