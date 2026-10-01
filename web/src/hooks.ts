/** Data-fetching hooks: one-shot loads, paged lists, and visibility-aware polling. */
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, apiFetch, asApiError } from "./api/client";

export interface AsyncState<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
  reload: () => void;
}

/** Load `load` on mount and whenever `deps` change; `reload` refetches on demand. */
export function useAsync<T>(load: (signal: AbortSignal) => Promise<T>, deps: readonly unknown[]): AsyncState<T> {
  const [state, setState] = useState<{ data: T | null; error: ApiError | null; loading: boolean }>({
    data: null,
    error: null,
    loading: true,
  });
  const [generation, setGeneration] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;

  useEffect(() => {
    const controller = new AbortController();
    setState((previous) => ({ ...previous, loading: true }));
    loadRef
      .current(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setState({ data, error: null, loading: false });
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setState({ data: null, error: asApiError(cause), loading: false });
      });
    return () => controller.abort();
  }, [...deps, generation]);

  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  return { ...state, reload };
}

const PAGE_SIZE = 50;

export interface PagedState<T> {
  rows: T[];
  error: ApiError | null;
  loading: boolean;
  hasMore: boolean;
  loadMore: () => void;
  reload: () => void;
}

/**
 * Paged list fetch. `buildPath` receives the offset/limit pair of each request;
 * changing `deps` (filters) resets to the first page. `reload` refetches from
 * offset 0 and keeps the number of rows already on screen. The loaded row count
 * lives in a ref so that `loadMore` never re-triggers the effect.
 */
export function usePaged<T>(
  buildPath: (offset: number, limit: number) => string,
  deps: readonly unknown[],
): PagedState<T> {
  const [rows, setRows] = useState<T[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(false);
  const [generation, setGeneration] = useState(0);
  const loadedRef = useRef(0);
  const buildPathRef = useRef(buildPath);
  buildPathRef.current = buildPath;

  useEffect(() => {
    const controller = new AbortController();
    const limit = Math.max(PAGE_SIZE, loadedRef.current);
    setLoading(true);
    apiFetch<T[]>(buildPathRef.current(0, limit), { signal: controller.signal })
      .then((fetched) => {
        if (controller.signal.aborted) return;
        loadedRef.current = fetched.length;
        setRows(fetched);
        setHasMore(fetched.length === limit);
        setError(null);
        setLoading(false);
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setError(asApiError(cause));
        setLoading(false);
      });
    return () => controller.abort();
  }, [...deps, generation]);

  const loadMore = useCallback(() => {
    const controller = new AbortController();
    setLoading(true);
    apiFetch<T[]>(buildPathRef.current(loadedRef.current, PAGE_SIZE), { signal: controller.signal })
      .then((fetched) => {
        if (controller.signal.aborted) return;
        loadedRef.current += fetched.length;
        setRows((previous) => [...previous, ...fetched]);
        setHasMore(fetched.length === PAGE_SIZE);
        setLoading(false);
      })
      .catch((cause: unknown) => {
        if (controller.signal.aborted) return;
        setError(asApiError(cause));
        setLoading(false);
      });
  }, []);

  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  return { rows, error, loading, hasMore, loadMore, reload };
}

/** `reload` on an interval while the tab is visible; `null` disables polling. */
export function usePolling(reload: () => void, ms: number | null): void {
  const reloadRef = useRef(reload);
  reloadRef.current = reload;

  useEffect(() => {
    if (ms === null) return;
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") reloadRef.current();
    }, ms);
    return () => window.clearInterval(id);
  }, [ms]);
}
