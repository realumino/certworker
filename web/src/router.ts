/**
 * Minimal history-API router: `navigate()` + a `useRoute()` matcher over the
 * path patterns the SPA serves. Deep links work because the asset router falls
 * back to index.html for unknown paths (`not_found_handling` in wrangler.jsonc).
 * The tracked location includes the query string so that filter links like
 * `/certificates?domain_id=…` re-render views on navigation.
 */
import { useEffect, useState } from "react";

export interface RouteMatch {
  /** Pattern that matched, e.g. `/runs/:id`. */
  pattern: string;
  params: Record<string, string>;
}

const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

export function navigate(path: string, options: { replace?: boolean } = {}): void {
  if (options.replace) window.history.replaceState(null, "", path);
  else window.history.pushState(null, "", path);
  emit();
}

function useLocation(): { pathname: string; search: string } {
  const [location, setLocation] = useState(() => ({
    pathname: window.location.pathname,
    search: window.location.search,
  }));
  useEffect(() => {
    const update = () => setLocation({ pathname: window.location.pathname, search: window.location.search });
    listeners.add(update);
    window.addEventListener("popstate", update);
    return () => {
      listeners.delete(update);
      window.removeEventListener("popstate", update);
    };
  }, []);
  return location;
}

/** Current query string (`?…` or empty); re-renders on navigation. */
export function useSearch(): string {
  return useLocation().search;
}

/** Match `pathname` against patterns with `:name` segments; first match wins. */
export function matchPath(patterns: readonly string[], pathname: string): RouteMatch | null {
  for (const pattern of patterns) {
    const params = matchSegments(pattern, pathname);
    if (params !== null) return { pattern, params };
  }
  return null;
}

function matchSegments(pattern: string, pathname: string): Record<string, string> | null {
  const patternParts = pattern.split("/");
  const pathParts = pathname.split("/");
  if (patternParts.length !== pathParts.length) return null;

  const params: Record<string, string> = {};
  for (let index = 0; index < patternParts.length; index += 1) {
    const expected = patternParts[index];
    const actual = pathParts[index];
    if (expected.startsWith(":")) {
      if (actual.length === 0) return null;
      params[expected.slice(1)] = decodeURIComponent(actual);
    } else if (expected !== actual) {
      return null;
    }
  }
  return params;
}

export function useRoute(patterns: readonly string[]): RouteMatch {
  const { pathname } = useLocation();
  return matchPath(patterns, pathname) ?? { pattern: "", params: {} };
}
