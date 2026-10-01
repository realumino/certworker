/** Display formatting for API timestamps (ISO strings) and identifiers. */

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function daysUntil(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return Math.ceil((date.getTime() - Date.now()) / 86_400_000);
}

/** Human summary of an expiry, e.g. `2026-12-01 (in 61 days)`. */
export function formatExpiry(iso: string | null | undefined): string {
  const days = daysUntil(iso);
  if (days === null) return "—";
  const date = new Date(iso!).toISOString().slice(0, 10);
  return `${date} (${days >= 0 ? `in ${days} days` : `${-days} days ago`})`;
}

export function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 12) : id;
}

/** Truncate long single-line strings (errors, user agents) for table cells. */
export function truncate(text: string | null, limit = 80): string {
  if (!text) return "—";
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}
