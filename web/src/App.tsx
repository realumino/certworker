import { useEffect, useState } from "react";
import { onUnauthorized } from "./api/client";
import { Link } from "./components";
import { useRoute } from "./router";
import { AuditView } from "./views/Audit";
import { CertificateDetailView, CertificatesView } from "./views/Certificates";
import { DomainsView } from "./views/Domains";
import { KeysView } from "./views/Keys";
import { OverviewView } from "./views/Overview";
import { PullsView } from "./views/Pulls";
import { RunDetailView, RunsView } from "./views/Runs";

const ROUTES = [
  "/",
  "/domains",
  "/runs",
  "/runs/:id",
  "/certificates",
  "/certificates/:id",
  "/keys",
  "/pulls",
  "/audit",
] as const;

const NAV = [
  { to: "/", label: "Overview", pattern: "/" },
  { to: "/domains", label: "Domains", pattern: "/domains" },
  { to: "/runs", label: "Runs", pattern: "/runs" },
  { to: "/certificates", label: "Certificates", pattern: "/certificates" },
  { to: "/keys", label: "API Keys", pattern: "/keys" },
  { to: "/pulls", label: "Pulls", pattern: "/pulls" },
  { to: "/audit", label: "Audit", pattern: "/audit" },
] as const;

export function App() {
  const { pattern, params } = useRoute(ROUTES);
  const [unauthorized, setUnauthorized] = useState(false);
  useEffect(() => onUnauthorized(() => setUnauthorized(true)), []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <h1>ssl-cert-worker</h1>
        <nav>
          {NAV.map((item) => (
            <Link key={item.to} to={item.to} className={pattern === item.pattern ? "active" : undefined}>
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="content">
        {unauthorized ? (
          <UnauthorizedNotice />
        ) : (
          <RouteView pattern={pattern} params={params} />
        )}
      </main>
    </div>
  );
}

function RouteView({ pattern, params }: { pattern: string; params: Record<string, string> }) {
  switch (pattern) {
    case "/domains":
      return <DomainsView />;
    case "/runs":
      return <RunsView />;
    case "/runs/:id":
      return <RunDetailView runId={params.id} />;
    case "/certificates":
      return <CertificatesView />;
    case "/certificates/:id":
      return <CertificateDetailView certificateId={params.id} />;
    case "/keys":
      return <KeysView />;
    case "/pulls":
      return <PullsView />;
    case "/audit":
      return <AuditView />;
    default:
      return <OverviewView />;
  }
}

function UnauthorizedNotice() {
  return (
    <div className="banner banner-error" role="alert">
      <strong>unauthorized</strong> The admin API rejected the request because no valid Cloudflare Access
      session is present. Reload the page to sign in again. Running locally? Set <code>DEV_ACCESS_EMAIL</code>{" "}
      in <code>.dev.vars</code> and open the panel through <code>wrangler dev</code>.
    </div>
  );
}
