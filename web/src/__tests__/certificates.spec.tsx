import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
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

/** happy-dom implements no window.confirm; install a controllable one. */
function stubConfirm(result: boolean): ReturnType<typeof vi.fn> {
  const mock = vi.fn(() => result);
  Object.defineProperty(window, "confirm", { value: mock, writable: true, configurable: true });
  return mock;
}

afterEach(() => {
  Reflect.deleteProperty(window, "confirm");
});

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
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("revokes on confirm, refreshes, and skips without confirmation", async () => {
    let certificate = CERTIFICATE;
    const confirmMock = stubConfirm(true);
    const stub = installFetchStub({
      "GET /api/certificates/c1": () => json(certificate),
      "POST /api/certificates/c1/revoke": () => {
        certificate = { ...CERTIFICATE, status: "revoked", purged_at: "2026-09-03T00:00:00.000Z" };
        return json({ certificate, status: "revoked", purged: true });
      },
    });
    render(<CertificateDetailView certificateId="c1" />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));

    expect(confirmMock).toHaveBeenCalledTimes(1);
    expect(stub.requests).toEqual([
      { method: "GET", path: "/api/certificates/c1", body: null },
      { method: "POST", path: "/api/certificates/c1/revoke", body: {} },
    ]);
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
    });
    expect(await screen.findByText("revoked")).toBeTruthy();
  });

  it("offers no revoke action for an already-revoked certificate", async () => {
    installFetchStub({
      "GET /api/certificates/c1": () => json({ ...CERTIFICATE, status: "revoked", purged_at: "2026-09-03T00:00:00.000Z" }),
    });
    render(<CertificateDetailView certificateId="c1" />);

    await screen.findByText("revoked");
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });
});
