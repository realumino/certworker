import { useState } from "react";
import { apiFetch, asApiError, type ApiError } from "../api/client";
import type { ApiKey, CreatedApiKey } from "../api/types";
import { EmptyRow, ErrorBanner, Modal, Page, Pager, StatusBadge } from "../components";
import { formatDateTime, truncate } from "../format";
import { usePaged } from "../hooks";

export function KeysView() {
  const list = usePaged<ApiKey>((offset, limit) => `/api/keys?offset=${offset}&limit=${limit}`, []);
  // The plaintext token exists only in this state while the modal is open.
  const [revealed, setRevealed] = useState<CreatedApiKey | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  async function revoke(key: ApiKey) {
    if (!window.confirm(`Revoke ${key.label} (${key.key_hint})? The node using it stops working immediately.`)) return;
    setActionError(null);
    try {
      await apiFetch(`/api/keys/${key.id}/revoke`, { method: "POST" });
      list.reload();
    } catch (cause) {
      setActionError(asApiError(cause));
    }
  }

  async function rotate(key: ApiKey) {
    if (!window.confirm(`Rotate ${key.label}? A replacement key is created and the current one is revoked immediately.`)) return;
    setActionError(null);
    try {
      setRevealed(await apiFetch<CreatedApiKey>(`/api/keys/${key.id}/rotate`, { method: "POST" }));
      list.reload();
    } catch (cause) {
      setActionError(asApiError(cause));
    }
  }

  return (
    <Page title="API keys">
      <ErrorBanner error={actionError ?? list.error} />
      <CreateKeyForm
        onCreated={(created) => {
          setRevealed(created);
          list.reload();
        }}
        onError={setActionError}
      />

      <table>
        <thead>
          <tr>
            <th>Label</th>
            <th>Hint</th>
            <th>Status</th>
            <th>Created</th>
            <th>Last used</th>
            <th>Revoked</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {list.rows.map((key) => (
            <tr key={key.id}>
              <td>{key.label}</td>
              <td>
                <code>{key.key_hint}</code>
              </td>
              <td>
                <StatusBadge status={key.status} />
              </td>
              <td>{formatDateTime(key.created_at)}</td>
              <td>{formatDateTime(key.last_used_at)}</td>
              <td>{formatDateTime(key.revoked_at)}</td>
              <td className="actions">
                <div className="row-actions">
                  <button type="button" className="secondary" onClick={() => rotate(key)}>
                    Rotate
                  </button>
                  <button type="button" className="danger" onClick={() => revoke(key)} disabled={key.status === "revoked"}>
                    Revoke
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={7}>No API keys yet.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />

      {revealed ? <TokenDialog created={revealed} onClose={() => setRevealed(null)} /> : null}
    </Page>
  );
}

function CreateKeyForm({
  onCreated,
  onError,
}: {
  onCreated: (created: CreatedApiKey) => void;
  onError: (error: ApiError) => void;
}) {
  const [label, setLabel] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      onCreated(await apiFetch<CreatedApiKey>("/api/keys", { method: "POST", body: { label: label.trim() } }));
      setLabel("");
    } catch (cause) {
      onError(asApiError(cause));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <fieldset>
        <legend>Create key</legend>
        <div className="filters">
          <div className="field">
            <label htmlFor="key-label">Label (node name)</label>
            <input
              id="key-label"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="web-01"
              size={24}
              maxLength={64}
              required
            />
          </div>
          <div className="field inline">
            <button type="submit" disabled={submitting || label.trim().length === 0}>
              {submitting ? "Creating…" : "Create key"}
            </button>
          </div>
        </div>
      </fieldset>
    </form>
  );
}

function TokenDialog({ created, onClose }: { created: CreatedApiKey; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      // Clipboard access can be denied; the input is selectable for manual copy.
    }
  }

  return (
    <Modal title="API key created" onClose={onClose}>
      <div className="banner banner-info" role="alert">
        This token is shown <strong>only once</strong>. Copy it now and store it on the node
        (<code>/etc/certworker/token</code>); it cannot be retrieved later — only rotated.
      </div>
      <div className="field">
        <label htmlFor="token-value">Token for {created.key.label}</label>
        <div className="token-row">
          <input id="token-value" readOnly value={created.token} onFocus={(event) => event.target.select()} />
          <button type="button" onClick={copy}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
      <p className="muted">
        Hint shown in listings: <code>{truncate(created.key.key_hint, 64)}</code>
      </p>
      <button type="button" className="secondary" onClick={onClose}>
        Close — I stored the token
      </button>
    </Modal>
  );
}
