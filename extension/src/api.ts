/**
 * Minimal andvari API client for the extension. Same wire as web/src/api/client.ts (Bearer auth,
 * JSON). Cross-origin fetch to the tailnet server works WITHOUT CORS because the manifest grants
 * host_permissions for that origin (spike doc Unknown 2). Only the fill/save surface is here; the
 * full account/lifecycle surface is not needed for autofill.
 */
export class AndvariApi {
  constructor(
    private baseUrl: string,
    private accessToken: string | null = null,
  ) {}

  setToken(token: string | null): void {
    this.accessToken = token;
  }

  private async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.accessToken) headers["authorization"] = `Bearer ${this.accessToken}`;
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) throw new ApiError(resp.status, await resp.text().catch(() => ""));
    return (await resp.json()) as T;
  }

  /** Unauthenticated liveness/CSP/host_permissions smoke check (spike verification step 3). */
  clientPolicy(): Promise<{ serverTime: number }> {
    return this.json("GET", "/api/v1/client-policy");
  }

  // TODO(extension): port the fill/save surface from web/src/api/client.ts as the SW grows —
  // prelogin, login (→ tokens), accountKeys (→ wrapped keys), sync (→ ciphertext items),
  // sync/push (save). All already exist server-side; this is a client-only port.
}

export class ApiError extends Error {
  constructor(
    public status: number,
    body: string,
  ) {
    super(`andvari api ${status}: ${body.slice(0, 200)}`);
  }
}
