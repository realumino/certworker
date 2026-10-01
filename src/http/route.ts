/** Match an exact-segment pattern like `/api/domains/:id/issue` against a pathname. */
export function matchRoute(pattern: string, pathname: string): Record<string, string> | null {
  const patternSegments = pattern.split("/");
  const pathSegments = pathname.split("/");
  if (patternSegments.length !== pathSegments.length) return null;

  const params: Record<string, string> = {};
  for (let index = 0; index < patternSegments.length; index += 1) {
    const expected = patternSegments[index];
    const actual = pathSegments[index];
    if (expected.startsWith(":")) {
      try {
        params[expected.slice(1)] = decodeURIComponent(actual);
      } catch {
        return null;
      }
    } else if (expected !== actual) {
      return null;
    }
  }
  return params;
}
