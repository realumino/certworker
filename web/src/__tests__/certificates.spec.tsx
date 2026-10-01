import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Certificate } from "../api/types";
import { CertificateDetailView } from "../views/Certificates";
import { installFetchStub, json } from "./support";

const CERTIFICATE: Certificate = {
  id: "c1",
  domain_id: "d1",
  domain_name: "example.com",
  env: "staging",
  serial: "00aa",
  fingerprint_sha256: "aa:bb",
  sans: ["example.com", "*.example.com"],
  not_before: "2026-09-01T00:00:00.000Z",
  not_after: "2026-11-30T00:00:00.000Z",
  issued_at: "2026-09-01T00:00:00.000Z",
  r2_prefix: "certs/example.com/c1",
  status: "current",
  purged_at: null,
  created_at: "2026-09-01T00:00:00.000Z",
};

describe("certificate detail", () => {
  it("offers downloads for the stored PEMs and the private key", async () => {
    installFetchStub({
      "GET /api/certificates/c1": () => json(CERTIFICATE),
    });
    render(<CertificateDetailView certificateId="c1" />);

    expect(await screen.findByText("example.com, *.example.com")).toBeTruthy();
    for (const file of ["fullchain", "cert", "chain", "key", "bundle"]) {
      const link = screen.getByRole("link", { name: file === "key" ? "private key" : file });
      expect(link.getAttribute("href")).toBe(`/api/certificates/c1/download?file=${file}`);
    }
  });

  it("hides downloads once the artifacts are purged", async () => {
    installFetchStub({
      "GET /api/certificates/c1": () => json({ ...CERTIFICATE, status: "superseded", purged_at: "2026-09-02T00:00:00.000Z" }),
    });
    render(<CertificateDetailView certificateId="c1" />);

    expect(await screen.findByText(/PEMs and private key were purged/)).toBeTruthy();
    expect(screen.queryByRole("link", { name: "fullchain" })).toBeNull();
    expect(screen.queryByRole("link", { name: "private key" })).toBeNull();
  });
});
