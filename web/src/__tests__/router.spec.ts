import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { matchPath, navigate, useRoute, useSearch } from "../router";

const PATTERNS = ["/", "/runs", "/runs/:id", "/certificates"] as const;

describe("router", () => {
  beforeEach(() => {
    window.history.replaceState(null, "", "/");
  });

  it("matches static and parameterized patterns", () => {
    expect(matchPath(PATTERNS, "/")).toEqual({ pattern: "/", params: {} });
    expect(matchPath(PATTERNS, "/runs")).toEqual({ pattern: "/runs", params: {} });
    expect(matchPath(PATTERNS, "/runs/abc-123")).toEqual({ pattern: "/runs/:id", params: { id: "abc-123" } });
    expect(matchPath(PATTERNS, "/unknown")).toBeNull();
    expect(matchPath(PATTERNS, "/runs/")).toBeNull();
    expect(matchPath(PATTERNS, "/runs/a/b")).toBeNull();
  });

  it("re-renders on navigate() and popstate", () => {
    const { result } = renderHook(() => useRoute(PATTERNS));
    expect(result.current.pattern).toBe("/");

    act(() => navigate("/runs/abc"));
    expect(result.current).toEqual({ pattern: "/runs/:id", params: { id: "abc" } });
    expect(window.location.pathname).toBe("/runs/abc");

    act(() => {
      window.history.back();
      window.dispatchEvent(new PopStateEvent("popstate"));
    });
    expect(result.current.pattern).toBe("/");
  });

  it("exposes the query string to views", () => {
    const { result } = renderHook(() => useSearch());
    act(() => navigate("/certificates?domain_id=d1"));
    expect(result.current).toBe("?domain_id=d1");
  });
});
