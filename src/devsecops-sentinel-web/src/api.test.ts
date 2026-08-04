import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * The deployed client and API are separate origins, and nothing rewrites
 * between them - Static Web Apps cannot proxy to an external backend on the
 * Free tier. So VITE_API_BASE_URL is what joins the two halves, and a
 * regression here is invisible until a deployment 404s every call.
 *
 * The module reads the variable once at load, so each case resets the module
 * registry and re-imports rather than stubbing after the fact.
 */
async function loadApi(baseUrl?: string) {
  vi.resetModules();
  if (baseUrl === undefined) {
    vi.stubEnv('VITE_API_BASE_URL', '');
  } else {
    vi.stubEnv('VITE_API_BASE_URL', baseUrl);
  }
  return import('./api');
}

function captureFetch() {
  const calls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return Response.json({});
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe('API origin', () => {
  it('leaves paths relative when no origin is configured', async () => {
    const calls = captureFetch();
    const api = await loadApi();

    await api.getScenarios();

    expect(calls).toEqual(['/api/scenarios']);
  });

  it('prefixes the configured origin when one is baked in', async () => {
    const calls = captureFetch();
    const api = await loadApi('https://app-sentinel.azurewebsites.net');

    await api.getScenarios();

    expect(calls).toEqual(['https://app-sentinel.azurewebsites.net/api/scenarios']);
  });

  it('does not produce a double slash when the origin has a trailing one', async () => {
    // A base URL copied from a browser address bar usually carries one.
    const calls = captureFetch();
    const api = await loadApi('https://app-sentinel.azurewebsites.net/');

    await api.getScenarios();

    expect(calls).toEqual(['https://app-sentinel.azurewebsites.net/api/scenarios']);
  });

  it('applies the origin to the unauthenticated security probe too', async () => {
    // getSecurityStatus deliberately bypasses apiFetch so it sends no key.
    // That made it the one call that could keep a relative path unnoticed.
    const calls = captureFetch();
    const api = await loadApi('https://app-sentinel.azurewebsites.net');

    await api.getSecurityStatus();

    expect(calls).toEqual(['https://app-sentinel.azurewebsites.net/api/security/status']);
  });
});
