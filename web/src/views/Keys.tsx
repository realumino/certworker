import { useState } from "react";
import { apiFetch, asApiError, type ApiError } from "../api/client";
import type { ApiKey, CreatedApiKey, Domain } from "../api/types";
import { EmptyRow, ErrorBanner, Modal, Page, Pager, StatusBadge } from "../components";
import { formatDateTime, truncate } from "../format";
import { useAsync, usePaged } from "../hooks";

export function KeysView() {
  const list = usePaged<ApiKey>((offset, limit) => `/api/keys?offset=${offset}&limit=${limit}`, []);
  // Picker source for scope editing; the admin install scale makes one page enough.
  const domains = useAsync<Domain[]>((signal) => apiFetch("/api/domains?limit=200", { signal }), []);
  // The plaintext token exists only in this state while the modal is open.
  const [revealed, setRevealed] = useState<CreatedApiKey | null>(null);
  const [scoping, setScoping] = useState<ApiKey | null>(null);
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

  function scopeText(key: ApiKey): string {
    if (key.allowed_domains === null) return "All domains";
    return key.allowed_domains.length === 0 ? "None" : key.allowed_domains.join(", ");
  }

  return (
    <Page title="API keys">
      <ErrorBanner error={actionError ?? list.error ?? domains.error} />
      <CreateKeyForm
        domains={domains.data ?? []}
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
            <th>Scope</th>
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
              <td title={scopeText(key)}>{truncate(scopeText(key), 40)}</td>
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
                  <button type="button" className="secondary" onClick={() => setScoping(key)} disabled={key.status === "revoked"}>
                    Edit scope
                  </button>
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
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={8}>No API keys yet.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />

      {revealed ? <TokenDialog created={revealed} onClose={() => setRevealed(null)} /> : null}
      {scoping ? (
        <EditScopeDialog
          apiKey={scoping}
          domains={domains.data ?? []}
          onClose={() => setScoping(null)}
          onSaved={() => {
            setScoping(null);
            list.reload();
          }}
          onError={setActionError}
        />
      ) : null}
    </Page>
  );
}

/**
 * Shared scope picker: "All domains" (`null` on the API) or an explicit
 * allowlist of registered domain row names. Exact names only — `example.com`
 * and `*.example.com` are separate rows.
 */
function ScopeEditor({
  domains,
  allDomains,
  selected,
  onAllDomains,
  onToggle,
  idPrefix,
}: {
  domains: Domain[];
  allDomains: boolean;
  selected: string[];
  onAllDomains: (all: boolean) => void;
  onToggle: (name: string, checked: boolean) => void;
  idPrefix: string;
}) {
  return (
    <>
      <div className="field inline">
        <input
          id={`${idPrefix}-all-domains`}
          type="checkbox"
          checked={allDomains}
          onChange={(event) => onAllDomains(event.target.checked)}
        />
        <label htmlFor={`${idPrefix}-all-domains`}>All domains</label>
      </div>
      <fieldset disabled={allDomains}>
        <legend>Allowed domains</legend>
        {domains.length === 0 ? <p className="muted">No domains registered yet.</p> : null}
        {domains.map((domain) => (
          <div key={domain.id} className="field inline">
            <input
              id={`${idPrefix}-domain-${domain.id}`}
              type="checkbox"
              checked={selected.includes(domain.name)}
              onChange={(event) => onToggle(domain.name, event.target.checked)}
            />
            <label htmlFor={`${idPrefix}-domain-${domain.id}`}>{domain.name}</label>
          </div>
        ))}
      </fieldset>
    </>
  );
}

function CreateKeyForm({
  domains,
  onCreated,
  onError,
}: {
  domains: Domain[];
  onCreated: (created: CreatedApiKey) => void;
  onError: (error: ApiError) => void;
}) {
  const [label, setLabel] = useState("");
  const [allDomains, setAllDomains] = useState(true);
  const [selected, setSelected] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);

  function toggle(name: string, checked: boolean) {
    setSelected((previous) => (checked ? [...previous, name] : previous.filter((item) => item !== name)));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      const created = await apiFetch<CreatedApiKey>("/api/keys", {
        method: "POST",
        body: { label: label.trim(), allowed_domains: allDomains ? null : selected },
      });
      onCreated(created);
      setLabel("");
      setAllDomains(true);
      setSelected([]);
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
            <button type="submit" disabled={submitting || label.trim().length === 0 || (!allDomains && selected.length === 0)}>
              {submitting ? "Creating…" : "Create key"}
            </button>
          </div>
        </div>
        <ScopeEditor
          idPrefix="key"
          domains={domains}
          allDomains={allDomains}
          selected={selected}
          onAllDomains={setAllDomains}
          onToggle={toggle}
        />
      </fieldset>
    </form>
  );
}

function EditScopeDialog({
  apiKey,
  domains,
  onClose,
  onSaved,
  onError,
}: {
  apiKey: ApiKey;
  domains: Domain[];
  onClose: () => void;
  onSaved: () => void;
  onError: (error: ApiError) => void;
}) {
  const [allDomains, setAllDomains] = useState(apiKey.allowed_domains === null);
  const [selected, setSelected] = useState<string[]>(apiKey.allowed_domains ?? []);
  const [submitting, setSubmitting] = useState(false);

  function toggle(name: string, checked: boolean) {
    setSelected((previous) => (checked ? [...previous, name] : previous.filter((item) => item !== name)));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await apiFetch(`/api/keys/${apiKey.id}`, {
        method: "PATCH",
        body: { allowed_domains: allDomains ? null : selected },
      });
      onSaved();
    } catch (cause) {
      onError(asApiError(cause));
      setSubmitting(false);
    }
  }

  return (
    <Modal title={`Scope for ${apiKey.label}`} onClose={onClose}>
      <form onSubmit={submit}>
        <ScopeEditor
          idPrefix="edit-key"
          domains={domains}
          allDomains={allDomains}
          selected={selected}
          onAllDomains={setAllDomains}
          onToggle={toggle}
        />
        <p className="muted">A node can pull certificates only for the listed names; everything else answers 403.</p>
        <div className="row-actions">
          <button type="submit" disabled={submitting || (!allDomains && selected.length === 0)}>
            {submitting ? "Saving…" : "Save"}
          </button>
          <button type="button" className="secondary" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </Modal>
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
