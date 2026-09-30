/** Node pull API — Access app B (bypass). Bearer key auth and ETags land in M6. */
export async function handlePullApi(_request: Request, _env: Env): Promise<Response> {
  return Response.json(
    { error: "not_implemented", milestone: "M6" },
    { status: 501, headers: { "Cache-Control": "no-store" } },
  );
}
