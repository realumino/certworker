import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ApiKey, CreatedApiKey } from "../api/types";
import { KeysView } from "../views/Keys";
import { installFetchStub, json } from "./support";const KEY: ApiKey = {
  id: "k1",
  label: "web-01",
  key_hint: "scw_k1…abcd",
  status: "active",
  created_at: "2026-09-01T00:00:00.000Z",
  last_used_at: null,
  revoked_at: null,
};

const CREATED: CreatedApiKey = { key: KEY, token: "scw_k1.very-secret" };

/** happy-dom implements no window.confirm; install a controllable one. */
function stubConfirm(result: boolean): ReturnType<typeof vi.fn> {
  const mock = vi.fn(() => result);
  Object.defineProperty(window, "confirm", { value: mock, writable: true, configurable: true });
  return mock;
}

afterEach(() => {
  Reflect.deleteProperty(window, "confirm");
});

describe("api keys view", () => {
  it("shows a new key's token exactly once and drops it when the dialog closes", async () => {
    installFetchStub({
      "GET /api/keys": () => json([]),
      "POST /api/keys": () => json(CREATED, 201),
    });
    render(<KeysView />);

    fireEvent.change(await screen.findByLabelText("Label (node name)"), { target: { value: "web-01" } });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    const token = (await screen.findByLabelText("Token for web-01")) as HTMLInputElement;
    expect(token.value).toBe("scw_k1.very-secret");
    expect(screen.getByText("only once")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Close — I stored the token" }));
    expect(screen.queryByLabelText("Token for web-01")).toBeNull();
    expect(document.body.textContent).not.toContain("very-secret");
  });

  it("shows the replacement token after rotate and revokes only on confirm", async () => {
    const confirmMock = stubConfirm(true);
    const stub = installFetchStub({
      "GET /api/keys": () => json([KEY]),
      "POST /api/keys/k1/rotate": () => json({ key: { ...KEY, id: "k2" }, token: "scw_k2.fresh" }, 201),
      "POST /api/keys/k1/revoke": () => json({ key: { ...KEY, status: "revoked" } }),
    });
    render(<KeysView />);

    expect(await screen.findByText("web-01")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    const token = (await screen.findByLabelText("Token for web-01")) as HTMLInputElement;
    expect(token.value).toBe("scw_k2.fresh");

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
      "GET /api/keys": () => json([KEY]),
    });
    render(<KeysView />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    expect(stub.requests.every((request) => request.method === "GET")).toBe(true);
  });
});
