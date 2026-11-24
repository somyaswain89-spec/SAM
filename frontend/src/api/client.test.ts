import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, setAccessToken } from './client';

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
});

describe('API client', () => {
  it('sends same-origin credentials and the in-memory access token', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ items: [] }),
    });
    vi.stubGlobal('fetch', fetchMock);
    setAccessToken('short-lived-access-token');

    await expect(api.get('/assets')).resolves.toEqual({ items: [] });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.credentials).toBe('include');
    expect(new Headers(options.headers).get('Authorization')).toBe('Bearer short-lived-access-token');
  });

  it('returns the server error contract rather than treating a failed request as success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: { code: 'forbidden', message: 'Insufficient role' } }),
    }));

    await expect(api.get('/audit')).rejects.toMatchObject({
      status: 403,
      message: 'Insufficient role',
    });
  });

  it('attaches a stable idempotency key to each mutation request', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ id: 'asset-1' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await api.post('/assets', { id: 'asset-1' });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(options.headers).get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('attaches an idempotency key to file uploads', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 202,
      json: async () => ({ job: { id: 'import-1' } }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await api.upload('/imports/assets', new FormData());

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(options.headers).get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('attaches an idempotency key to patch requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'finding-1', state: 'In Progress' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await api.patch('/findings/finding-1/state', { state: 'In Progress' });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new Headers(options.headers).get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it('reuses the patch idempotency key after refreshing an expired access token', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ access_token: 'renewed' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ id: 'finding-1' }) });
    vi.stubGlobal('fetch', fetchMock);
    setAccessToken('expired');

    await api.patch('/findings/finding-1/state', { state: 'Resolved' });

    const firstHeaders = new Headers((fetchMock.mock.calls[0]?.[1] as RequestInit).headers);
    const retryHeaders = new Headers((fetchMock.mock.calls[2]?.[1] as RequestInit).headers);
    expect(firstHeaders.get('Idempotency-Key')).toBe(retryHeaders.get('Idempotency-Key'));
  });

  it('rotates the refresh cookie before logout so an expired access session is revoked', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ access_token: 'rotated-access-token' }),
      })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ status: 'signed_out' }) });
    vi.stubGlobal('fetch', fetchMock);
    setAccessToken('expired-access-token');

    await expect(api.logout()).resolves.toBeUndefined();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/auth/refresh');
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/v1/auth/logout');
    const [, logoutOptions] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(new Headers(logoutOptions.headers).get('Authorization')).toBe('Bearer rotated-access-token');
  });
});
