import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Domain } from "../api/types";
import { DomainsView } from "../views/Domains";
import { installFetchStub, json } from "./support";

const DOMAIN: Domain = {
  id: "d1",
  name: "example.com",
  zone_id: "z1",
  include_wildcard: true,
  key_type: "ecdsa_p256",
  renew_before_days: 30,
  preferred_chain: null,
  status: "active",
  last_error: null,
  created_at: "2026-09-01T00:00:00.000Z",
  updated_at: "2026-09-01T00:00:00.000Z",
  current_certificate: null,
};

function stubList(domains: Domain[] = []) {
  return installFetchStub({
    "GET /api/zones": () => json([{ id: "z1", name: "example.com", status: "active" }]),
    "GET /api/domains": () => json(domains),
  });
}

describe("domains view", () => {
  it("lists domains with the wildcard state per row", async () => {
    const stub = stubList([DOMAIN, { ...DOMAIN, id: "d2", name: "*.example.org", include_wildcard: true }]);
    render(<DomainsView />);

    const table = within(await screen.findByRole("table"));
    const apexRow = table.getByText("example.com").closest("tr")!;
    const wildcardRow = table.getByText("*.example.org").closest("tr")!;
    // Wildcard-only rows ignore the toggle (they issue exactly the `*.` SAN).
    expect(within(apexRow).getAllByRole("cell")[2].textContent).toBe("on");
    expect(within(wildcardRow).getAllByRole("cell")[2].textContent).toBe("—");
    expect(stub.requests.filter((request) => request.method === "POST")).toEqual([]);
  });

  it("creates a domain with the wildcard SAN on by default", async () => {
    const stub = installFetchStub({
      "GET /api/zones": () => json([]),
      "GET /api/domains": () => json([]),
      "POST /api/domains": () => json(DOMAIN, 201),
    });
    render(<DomainsView />);

    const checkbox = (await screen.findByLabelText("Include wildcard SAN")) as HTMLInputElement;
    expect(checkbox.checked).toBe(true);
    expect(checkbox.disabled).toBe(false);

    fireEvent.change(screen.getByLabelText("DNS name"), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));

    await waitFor(() => {
      const created = stub.requests.find((request) => request.method === "POST");
      expect(created?.body).toEqual({
        name: "example.com",
        include_wildcard: true,
        renew_before_days: 30,
      });
    });
  });

  it("forces the wildcard SAN off for `*.` rows", async () => {
    const stub = installFetchStub({
      "GET /api/zones": () => json([]),
      "GET /api/domains": () => json([]),
      "POST /api/domains": () => json(DOMAIN, 201),
    });
    render(<DomainsView />);

    const checkbox = (await screen.findByLabelText("Include wildcard SAN")) as HTMLInputElement;
    fireEvent.change(screen.getByLabelText("DNS name"), { target: { value: "*.example.com" } });
    expect(checkbox.checked).toBe(false);
    expect(checkbox.disabled).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));
    await waitFor(() => {
      const created = stub.requests.find((request) => request.method === "POST");
      expect(created?.body).toEqual({
        name: "*.example.com",
        include_wildcard: false,
        renew_before_days: 30,
      });
    });
  });

  it("surfaces server-side validation messages", async () => {
    installFetchStub({
      "GET /api/zones": () => json([]),
      "GET /api/domains": () => json([]),
      "POST /api/domains": () => json({ error: "invalid_domain_name", message: "nope is not a valid DNS name" }, 400),
    });
    render(<DomainsView />);

    fireEvent.change(await screen.findByLabelText("DNS name"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: "Add domain" }));

    expect(await screen.findByText(/nope is not a valid DNS name/)).toBeTruthy();
  });
});
