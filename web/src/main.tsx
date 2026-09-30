import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <main style={{ fontFamily: "system-ui", padding: "2rem" }}>
      <h1>ssl-cert-worker</h1>
      <p>Admin SPA placeholder — built out in M5.</p>
    </main>
  </StrictMode>,
);
