import { useState } from "react";
import { apiFetch, asApiError, query, type ApiError } from "../api/client";
import type { Domain, DomainStatus, IssuedRun, Zone } from "../api/types";
import { EmptyRow, ErrorBanner, Link, Modal, Page, Pager, StatusBadge } from "../components";
import { formatExpiry, truncate } from "../format";
import { useAsync, usePaged } from "../hooks";
import { navigate } from "../router";

const STATUSES: (DomainStatus | "")[] = ["", "active", "paused", "deleted"];

export function DomainsView() {
  const [status, setStatus] = useState<DomainStatus | "">("");
  const [editing, setEditing] = useState<Domain | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const list = usePaged<Domain>(
    (offset, limit) => `/api/domains?${query({ status: status || undefined, offset, limit })}`,
    [status],
  );

  async function issue(domain: Domain) {
    setActionError(null);
    try {
      const started = await apiFetch<IssuedRun>(`/api/domains/${domain.id}/issue`, { method: "POST" });
      navigate(`/runs/${started.run_id}`);
    } catch (cause) {
      setActionError(asApiError(cause));
    }
  }

  async function remove(domain: Domain) {
    if (!window.confirm(`Delete ${domain.name}? History and audit entries are kept (revocation lands in M7).`)) return;
    setActionError(null);
    try {
      await apiFetch(`/api/domains/${domain.id}`, { method: "DELETE" });
      list.reload();
    } catch (cause) {
      setActionError(asApiError(cause));
    }
  }

  return (
    <Page title="Domains">
      <ErrorBanner error={actionError ?? list.error} />
      <AddDomainForm onCreated={list.reload} onError={setActionError} />

      <div className="filters">
        <label htmlFor="domain-status">Status</label>
        <select id="domain-status" value={status} onChange={(event) => setStatus(event.target.value as DomainStatus | "")}>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value === "" ? "non-deleted (default)" : value}
            </option>
          ))}
        </select>
      </div>

      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Status</th>
            <th>Wildcard</th>
            <th>Renew before</th>
            <th>Current certificate</th>
            <th>Last error</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {list.rows.map((domain) => (
            <tr key={domain.id}>
              <td>
                {domain.current_certificate ? (
                  <Link to={`/certificates/${domain.current_certificate.id}`}>{domain.name}</Link>
                ) : (
                  domain.name
                )}
              </td>
              <td>
                <StatusBadge status={domain.status} />
              </td>
              <td>{domain.name.startsWith("*.") ? "—" : domain.include_wildcard ? "on" : "off"}</td>
              <td>{domain.renew_before_days} days</td>
              <td>{domain.current_certificate ? formatExpiry(domain.current_certificate.not_after) : "—"}</td>
              <td title={domain.last_error ?? undefined}>{truncate(domain.last_error, 60)}</td>
              <td className="actions">
                <div className="row-actions">
                  <button type="button" className="secondary" onClick={() => issue(domain)} disabled={domain.status !== "active"}>
                    Issue
                  </button>
                  <button type="button" className="secondary" onClick={() => setEditing(domain)} disabled={domain.status === "deleted"}>
                    Edit
                  </button>
                  <button type="button" className="danger" onClick={() => remove(domain)} disabled={domain.status === "deleted"}>
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={7}>No domains yet — add one above.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />

      {editing ? (
        <EditDomainDialog
          domain={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            list.reload();
          }}
          onError={setActionError}
        />
      ) : null}
    </Page>
  );
}

function AddDomainForm({ onCreated, onError }: { onCreated: () => void; onError: (error: ApiError) => void }) {
  const [name, setName] = useState("");
  // Wildcard on by default (PLAN §3); wildcard-only rows (`*.`) issue just that SAN.
  const [includeWildcard, setIncludeWildcard] = useState(true);
  const [renewBefore, setRenewBefore] = useState(30);
  const [zoneId, setZoneId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const zones = useAsync<Zone[]>((signal) => apiFetch("/api/zones", { signal }), []);

  const wildcardOnly = name.trim().startsWith("*.");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await apiFetch("/api/domains", {
        method: "POST",
        body: {
          name: name.trim(),
          include_wildcard: wildcardOnly ? false : includeWildcard,
          renew_before_days: renewBefore,
          ...(zoneId ? { zone_id: zoneId } : {}),
        },
      });
      setName("");
      setIncludeWildcard(true);
      setRenewBefore(30);
      setZoneId("");
      onCreated();
    } catch (cause) {
      onError(asApiError(cause));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <fieldset>
        <legend>Add domain</legend>
        <div className="filters">
          <div className="field">
            <label htmlFor="domain-name">DNS name</label>
            <input
              id="domain-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="example.com"
              size={28}
              required
            />
          </div>
          <div className="field inline">
            <input
              id="domain-wildcard"
              type="checkbox"
              checked={wildcardOnly ? false : includeWildcard}
              disabled={wildcardOnly}
              onChange={(event) => setIncludeWildcard(event.target.checked)}
            />
            <label htmlFor="domain-wildcard">Include wildcard SAN</label>
          </div>
          <div className="field">
            <label htmlFor="domain-renew">Renew before (days)</label>
            <input
              id="domain-renew"
              type="number"
              min={1}
              max={90}
              value={renewBefore}
              onChange={(event) => setRenewBefore(Number(event.target.value))}
            />
          </div>
          <div className="field">
            <label htmlFor="domain-zone">Zone</label>
            <select id="domain-zone" value={zoneId} onChange={(event) => setZoneId(event.target.value)}>
              <option value="">Auto-detect</option>
              {zones.data?.map((zone) => (
                <option key={zone.id} value={zone.id}>
                  {zone.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field inline">
            <button type="submit" disabled={submitting || name.trim().length === 0}>
              {submitting ? "Adding…" : "Add domain"}
            </button>
          </div>
        </div>
        {wildcardOnly ? <p className="muted">Wildcard-only row: exactly the `*.` SAN is issued; the toggle does not apply.</p> : null}
      </fieldset>
    </form>
  );
}

function EditDomainDialog({
  domain,
  onClose,
  onSaved,
  onError,
}: {
  domain: Domain;
  onClose: () => void;
  onSaved: () => void;
  onError: (error: ApiError) => void;
}) {
  const wildcardOnly = domain.name.startsWith("*.");
  const [includeWildcard, setIncludeWildcard] = useState(domain.include_wildcard);
  const [renewBefore, setRenewBefore] = useState(domain.renew_before_days);
  const [status, setStatus] = useState<"active" | "paused">(domain.status === "paused" ? "paused" : "active");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    try {
      await apiFetch(`/api/domains/${domain.id}`, {
        method: "PATCH",
        body: {
          ...(wildcardOnly ? {} : { include_wildcard: includeWildcard }),
          renew_before_days: renewBefore,
          status,
        },
      });
      onSaved();
    } catch (cause) {
      onError(asApiError(cause));
      setSubmitting(false);
    }
  }

  return (
    <Modal title={`Edit ${domain.name}`} onClose={onClose}>
      <form onSubmit={submit}>
        <div className="field inline">
          <input
            id="edit-wildcard"
            type="checkbox"
            checked={wildcardOnly ? false : includeWildcard}
            disabled={wildcardOnly}
            onChange={(event) => setIncludeWildcard(event.target.checked)}
          />
          <label htmlFor="edit-wildcard">Include wildcard SAN</label>
        </div>
        <div className="field">
          <label htmlFor="edit-renew">Renew before (days)</label>
          <input
            id="edit-renew"
            type="number"
            min={1}
            max={90}
            value={renewBefore}
            onChange={(event) => setRenewBefore(Number(event.target.value))}
          />
        </div>
        <div className="field">
          <label htmlFor="edit-status">Status</label>
          <select id="edit-status" value={status} onChange={(event) => setStatus(event.target.value as "active" | "paused")}>
            <option value="active">active</option>
            <option value="paused">paused</option>
          </select>
        </div>
        <div className="row-actions">
          <button type="submit" disabled={submitting}>
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
