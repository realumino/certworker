import { useState } from "react";
import { apiFetch, query } from "../api/client";
import type { Certificate, CertificateStatus, Domain } from "../api/types";
import { EmptyRow, ErrorBanner, Link, Page, Pager, StatusBadge } from "../components";
import { formatDateTime, formatExpiry, shortId, truncate } from "../format";
import { useAsync, usePaged } from "../hooks";
import { navigate, useSearch } from "../router";

const STATUSES: (CertificateStatus | "")[] = ["", "current", "superseded", "revoked"];
const DOWNLOAD_FILES = ["fullchain", "cert", "chain", "key", "bundle"] as const;

export function CertificatesView() {
  const search = useSearch();
  const domainId = new URLSearchParams(search).get("domain_id") ?? "";
  const [status, setStatus] = useState<CertificateStatus | "">("");
  const list = usePaged<Certificate>(
    (offset, limit) => `/api/certificates?${query({ domain_id: domainId || undefined, status: status || undefined, offset, limit })}`,
    [domainId, status],
  );
  const domain = useAsync<Domain | null>(
    (signal) => (domainId ? apiFetch<Domain>(`/api/domains/${domainId}`, { signal }) : Promise.resolve(null)),
    [domainId],
  );

  return (
    <Page title="Certificates">
      <ErrorBanner error={list.error} />
      <div className="filters">
        <label htmlFor="cert-status">Status</label>
        <select id="cert-status" value={status} onChange={(event) => setStatus(event.target.value as CertificateStatus | "")}>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value === "" ? "all" : value}
            </option>
          ))}
        </select>
        {domainId ? (
          <>
            <span className="muted">domain: {domain.data?.name ?? shortId(domainId)}</span>
            <button type="button" className="ghost" onClick={() => navigate("/certificates")}>
              clear filter ✕
            </button>
          </>
        ) : null}
      </div>

      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Env</th>
            <th>Status</th>
            <th>Serial</th>
            <th>Not after</th>
            <th>Issued</th>
          </tr>
        </thead>
        <tbody>
          {list.rows.map((certificate) => (
            <tr key={certificate.id}>
              <td>
                <Link to={`/certificates/${certificate.id}`}>{certificate.domain_name ?? shortId(certificate.domain_id)}</Link>
              </td>
              <td>{certificate.env}</td>
              <td>
                <StatusBadge status={certificate.status} />
              </td>
              <td>
                <code>{truncate(certificate.serial, 18)}</code>
              </td>
              <td>{formatExpiry(certificate.not_after)}</td>
              <td>{formatDateTime(certificate.issued_at)}</td>
            </tr>
          ))}
          {list.rows.length === 0 && !list.loading ? <EmptyRow colSpan={6}>No certificates match.</EmptyRow> : null}
        </tbody>
      </table>
      <Pager hasMore={list.hasMore} loading={list.loading} onLoadMore={list.loadMore} />
    </Page>
  );
}

export function CertificateDetailView({ certificateId }: { certificateId: string }) {
  const { data: certificate, error, loading } = useAsync<Certificate>(
    (signal) => apiFetch(`/api/certificates/${certificateId}`, { signal }),
    [certificateId],
  );

  return (
    <Page title="Certificate">
      <ErrorBanner error={error} />
      {loading && !certificate ? <p className="muted">Loading…</p> : null}
      {certificate ? (
        <>
          <div className="detail">
            <dl>
              <dt>Domain</dt>
              <dd>
                <Link to={`/certificates?domain_id=${certificate.domain_id}`}>
                  {certificate.domain_name ?? certificate.domain_id}
                </Link>
              </dd>
              <dt>Status</dt>
              <dd>
                <StatusBadge status={certificate.status} />
              </dd>
              <dt>Environment</dt>
              <dd>{certificate.env}</dd>
              <dt>SANs</dt>
              <dd>{certificate.sans.join(", ")}</dd>
              <dt>Serial</dt>
              <dd>
                <code>{certificate.serial}</code>
              </dd>
              <dt>SHA-256 fingerprint</dt>
              <dd>
                <code>{certificate.fingerprint_sha256}</code>
              </dd>
              <dt>Valid</dt>
              <dd>
                {formatDateTime(certificate.not_before)} → {formatDateTime(certificate.not_after)}
              </dd>
              <dt>Issued</dt>
              <dd>{formatDateTime(certificate.issued_at)}</dd>
              <dt>R2 prefix</dt>
              <dd>
                <code>{certificate.r2_prefix}</code>
              </dd>
              {certificate.purged_at ? (
                <>
                  <dt>Artifacts purged</dt>
                  <dd>{formatDateTime(certificate.purged_at)}</dd>
                </>
              ) : null}
            </dl>
          </div>

          {certificate.purged_at ? (
            <div className="banner banner-info">
              This certificate's PEMs and private key were purged from R2 after being superseded; the metadata above
              is kept for audit. Nothing is downloadable.
            </div>
          ) : (
            <div className="detail">
              <h2>Download</h2>
              <div className="row-actions">
                {DOWNLOAD_FILES.map((file) => (
                  <a
                    key={file}
                    className="button"
                    href={`/api/certificates/${certificate.id}/download?file=${file}`}
                  >
                    {file === "key" ? "private key" : file}
                  </a>
                ))}
              </div>
              <p className="muted">
                <code>bundle</code> is the fullchain followed by the private key (HAProxy-style). The private key
                leaves the server only through this authenticated download or the node pull API.
              </p>
            </div>
          )}
        </>
      ) : null}
    </Page>
  );
}
