export type ApiErrorBody = { error?: { message?: string }; detail?: string; message?: string };

export class ApiError extends Error {
  constructor(public readonly status: number, message: string, public readonly payload?: unknown) {
    super(message);
    this.name = 'ApiError';
  }
}

export type Page<T> = { items: T[]; total: number; limit: number; offset: number };
const API_ROOT = import.meta.env.VITE_API_ROOT ?? '/api/v1';
let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

function csrfValue(): string {
  return document.cookie.split('; ').find((item) => item.startsWith('sam_csrf='))?.split('=').slice(1).join('=') ?? '';
}

async function renewAccess(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = fetch(`${API_ROOT}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': decodeURIComponent(csrfValue()) },
    })
      .then(async (response) => {
        if (!response.ok) return false;
        const result = (await response.json()) as { access_token: string };
        accessToken = result.access_token;
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

async function send<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  const response = await fetch(`${API_ROOT}${path}`, { ...init, headers, credentials: 'include' });
  if (response.status === 401 && retry && !path.startsWith('/auth/')) {
    if (await renewAccess()) return send<T>(path, init, false);
    accessToken = null;
  }
  const payload = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const body = payload as ApiErrorBody | undefined;
    throw new ApiError(response.status, body?.error?.message ?? body?.detail ?? body?.message ?? `Request failed (${response.status})`, payload);
  }
  return payload as T;
}

export const api = {
  get: <T>(path: string) => send<T>(path),
  post: <T>(path: string, body?: unknown, headers?: Record<string, string>) => send<T>(path, {
    method: 'POST',
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { 'Idempotency-Key': crypto.randomUUID(), ...headers },
  }),
  patch: <T>(path: string, body: unknown) => send<T>(path, {
    method: 'PATCH',
    body: JSON.stringify(body),
    headers: { 'Idempotency-Key': crypto.randomUUID() },
  }),
  delete: <T>(path: string) => send<T>(path, { method: 'DELETE' }),
  upload: <T>(path: string, body: FormData) => send<T>(path, {
    method: 'POST',
    body,
    headers: { 'Idempotency-Key': crypto.randomUUID() },
  }),
  async download(path: string, fallbackName: string) {
    let response = await fetch(`${API_ROOT}${path}`, { credentials: 'include', headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {} });
    if (response.status === 401 && await renewAccess()) response = await fetch(`${API_ROOT}${path}`, { credentials: 'include', headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {} });
    if (!response.ok) {
      const payload = await response.json().catch(() => undefined) as ApiErrorBody | undefined;
      throw new ApiError(response.status, payload?.error?.message ?? payload?.detail ?? `Download failed (${response.status})`, payload);
    }
    const disposition = response.headers.get('Content-Disposition') ?? '';
    const filename = disposition.match(/filename="?([^";]+)"?/)?.[1] ?? fallbackName;
    const blobUrl = URL.createObjectURL(await response.blob());
    const anchor = document.createElement('a');
    anchor.href = blobUrl; anchor.download = filename; anchor.click(); URL.revokeObjectURL(blobUrl);
  },
  async login(email: string, password: string) {
    const result = await send<{ access_token: string; user: User }>('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }, false);
    setAccessToken(result.access_token);
    return result.user;
  },
  async currentUser() {
    if (!(await renewAccess())) return null;
    return api.get<User>('/auth/me');
  },
  async logout() {
    try {
      // Refresh first so an expired access token cannot leave a live refresh cookie behind.
      const hadAccessToken = accessToken !== null;
      const refreshed = await renewAccess();
      if (refreshed || hadAccessToken) await send('/auth/logout', { method: 'POST' }, false);
    } finally {
      setAccessToken(null);
    }
  },
};

export type User = { id: number; email: string; role: string };
export type Asset = {
  id: string;
  name: string;
  kind: 'Website' | 'Server';
  classification: string;
  owner: string;
  environment: string;
  criticality: string;
  compliance: number | null;
  status: string;
  waf?: string | null;
  open_findings?: number;
  findings?: Array<Record<string, unknown>>;
};
export type Finding = { id: string; asset_id: string; title: string; cve?: string | null; severity: string; state: string; due_at?: string | null; asset_name?: string };
