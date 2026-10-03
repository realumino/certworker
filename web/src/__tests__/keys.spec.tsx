import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiKey, CreatedApiKey, Domain } from "../api/types";
import { KeysView } from "../views/Keys";
import { installFetchStub, json } from "./support";

const KEY: ApiKey = {
  id: "k1",
  label: "web-01",
  key_hint: "cw_k1…abcd",
  allowed_domains: null,
  status: "active",
  created_at: "2026-09-01T00:00:00.000Z",
  last_used_at: null,
  revoked_at: null,
};

const SCOPED_KEY: ApiKey = {
  ...KEY,
  id: "k2",
  label: "web-02",
  allowed_domains: ["example.com"],
};

const CREATED: CreatedApiKey = { key: KEY, token: "cw_k1.very-secret" };

const DOMAINS: Domain[] = [
  {
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
  },
  {
    id: "d2",
    name: "other.example.net",
    zone_id: "z2",
    include_wildcard: false,
    key_type: "ecdsa_p256",
    renew_before_days: 30,
    preferred_chain: null,
    status: "active",
    last_error: null,
    created_at: "2026-09-01T00:00:00.000Z",
    updated_at: "2026-09-01T00:00:00.000Z",
    current_certificate: null,
  },
];

/** happy-dom implements no window.confirm; install a controllable one. */
function stubConfirm(result: boolean): ReturnType<typeof vi.fn> {
  const mock = vi.fn(() => result);
  Object.defineProperty(window, "confirm", { value: mock, writable: true, configurable: true });
  return mock;
}

function baseStubs() {
  return {
    "GET /api/domains": () => json(DOMAINS),
    "GET /api/keys": () => json([KEY, SCOPED_KEY]),
  };
}

afterEach(() => {
  Reflect.deleteProperty(window, "confirm");
});

describe("api keys view", () => {
  it("shows a new key's token exactly once and drops it when the dialog closes", async () => {
    const stub = installFetchStub({
      ...baseStubs(),
      "POST /api/keys": () => json(CREATED, 201),
    });
    render(<KeysView />);

    fireEvent.change(await screen.findByLabelText("Label (node name)"), { target: { value: "web-01" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    const token = (await screen.findByLabelText("Token for web-01")) as HTMLInputElement;
    expect(token.value).toBe("cw_k1.very-secret");
    expect(screen.getByText("only once")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Close — I stored the token" }));
    expect(screen.queryByLabelText("Token for web-01")).toBeNull();
    expect(document.body.textContent).not.toContain("very-secret");

    const create = stub.requests.find((request) => request.method === "POST" && request.path === "/api/keys");
    expect(create?.body).toEqual({ label: "web-01", allowed_domains: null });
  });

  it("posts an explicit scope when 'All domains' is unchecked", async () => {
    const stub = installFetchStub({
      ...baseStubs(),
      "POST /api/keys": () => json(CREATED, 201),
    });
    render(<KeysView />);

    fireEvent.change(await screen.findByLabelText("Label (node name)"), { target: { value: "web-01" } });
    fireEvent.click(screen.getByLabelText("All domains"));
    fireEvent.click(screen.getByLabelText("example.com"));
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    await screen.findByLabelText("Token for web-01");
    const create = stub.requests.find((request) => request.method === "POST" && request.path === "/api/keys");
    expect(create?.body).toEqual({ label: "web-01", allowed_domains: ["example.com"] });
  });

  it("renders the scope column", async () => {
    installFetchStub(baseStubs());
    render(<KeysView />);

    expect(await screen.findByText("web-01")).toBeTruthy();
    // "All domains" matches the editor checkbox label and the unrestricted row's cell.
    expect(screen.getAllByText("All domains").length).toBeGreaterThan(0);
    // The scoped row renders the allowlist; the editor also lists domain names.
    expect(screen.getAllByText("example.com").length).toBeGreaterThan(0);
  });

  it("edits a key's scope and reloads the list", async () => {
    const stub = installFetchStub({
      "GET /api/domains": () => json(DOMAINS),
      "GET /api/keys": () => json([KEY]),
      "PATCH /api/keys/k1": () => json({ key: { ...KEY, allowed_domains: ["example.com", "other.example.net"] } }),
    });
    render(<KeysView />);

    fireEvent.click(await screen.findByRole("button", { name: "Edit scope" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog.textContent).toContain("web-01");

    // The create form has a same-named checkbox; query within the dialog.
    fireEvent.click(within(dialog).getByLabelText("All domains"));
    fireEvent.click(within(dialog).getByLabelText("example.com"));
    fireEvent.click(within(dialog).getByLabelText("other.example.net"));
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => {
      expect(stub.requests.some((request) => request.method === "PATCH" && request.path === "/api/keys/k1")).toBe(true);
    });
    const patch = stub.requests.find((request) => request.method === "PATCH");
    expect(patch?.body).toEqual({ allowed_domains: ["example.com", "other.example.net"] });
    await waitFor(() => {
      expect(stub.requests.filter((request) => request.method === "GET" && request.path.startsWith("/api/keys")).length)
        .toBeGreaterThan(1);
    });
  });

  it("shows the replacement token after rotate and revokes only on confirm", async () => {
    const confirmMock = stubConfirm(true);
    const stub = installFetchStub({
      "GET /api/domains": () => json(DOMAINS),
      "GET /api/keys": () => json([KEY]),
      "POST /api/keys/k1/rotate": () => json({ key: { ...KEY, id: "k9" }, token: "cw_k9.fresh" }, 201),
      "POST /api/keys/k1/revoke": () => json({ key: { ...KEY, status: "revoked" } }),
    });
    render(<KeysView />);

    expect(await screen.findByText("web-01")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    const token = (await screen.findByLabelText("Token for web-01")) as HTMLInputElement;
    expect(token.value).toBe("cw_k9.fresh");

    fireEvent.click(screen.getByRole("button", { name: "Close — I stored the token" }));
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    await waitFor(() => {
      expect(stub.requests.map((request) => `${request.method} ${request.path}`)).toContain("POST /api/keys/k1/revoke");
    });
    // Once for rotate, once for revoke.
    expect(confirmMock).toHaveBeenCalledTimes(2);
  });

  it("does not revoke when the confirmation is cancelled", async () => {
    stubConfirm(false);
    const stub = installFetchStub({
      "GET /api/domains": () => json(DOMAINS),
      "GET /api/keys": () => json([KEY]),
    });
    render(<KeysView />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    expect(stub.requests.every((request) => request.method === "GET")).toBe(true);
  });
});
