import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { downloadRemediationExport } from './api';

/**
 * The two flows the other suites leave untouched: buying live access with the
 * key, and taking a remediation out of the app as a file. The unlock flow is
 * security-relevant — a wrong key must not be stored as though it worked,
 * which is a regression this app has actually had.
 */
const scenario = { id: 'sample', name: 'Sample', description: 'Sample', fileName: 'sample.yml' };

const publicMode = {
  required: false,
  headerName: 'X-API-Key',
  sessionOnlyBrowserKey: true,
  mode: 'Public',
  keyUnlocksGitHub: true,
  keyUnlocksLiveAi: true,
};

function respond(overrides: Record<string, (init?: RequestInit) => Response> = {}) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    for (const [prefix, handler] of Object.entries(overrides)) {
      if (url.includes(prefix)) return handler(init);
    }
    if (url === '/api/security/status') return Response.json(publicMode);
    if (url === '/api/scenarios') return Response.json([scenario]);
    if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
    if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
    if (url === '/api/github/status') return Response.json({ enabled: false, configured: false, connected: false, mode: 'ReadOnly', allowedRepositoryCount: 0, message: 'Not configured.' });
    return new Response('{}', { status: 404 });
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe('Unlocking live access', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(respond()));
  });

  it('accepts a key the API verifies and switches the header to locked mode', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock live AI and GitHub' })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Unlock live AI and GitHub' }));
    fireEvent.change(screen.getByLabelText('X-API-Key'), { target: { value: 'the-key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Lock API' })).toBeInTheDocument());
    expect(sessionStorage.getItem('devsecops-sentinel-api-key')).toBe('the-key');
  });

  it('rejects a key the API refuses and does not keep it', async () => {
    // The regression this pins: an unverified key was stored, the header said
    // "Lock API" as though it had worked, and the only symptom was GitHub
    // quietly staying unavailable.
    // The app verifies a candidate key by probing /api/github/status with it.
    vi.stubGlobal('fetch', vi.fn(respond({
      '/api/github/status': (init) => {
        const headers = new Headers(init?.headers);
        return headers.get('X-API-Key')
          ? new Response('{"title":"Invalid key"}', { status: 401 })
          : Response.json({ enabled: false, configured: false, connected: false, mode: 'ReadOnly', allowedRepositoryCount: 0, message: 'Not configured.' });
      },
    })));

    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock live AI and GitHub' })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Unlock live AI and GitHub' }));
    fireEvent.change(screen.getByLabelText('X-API-Key'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));

    await waitFor(() => expect(screen.getAllByText('That key was not accepted. Check it and try again.').length).toBeGreaterThan(0));
    expect(sessionStorage.getItem('devsecops-sentinel-api-key')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Lock API' })).not.toBeInTheDocument();
  });

  it('locking again clears the stored key', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock live AI and GitHub' })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Unlock live AI and GitHub' }));
    fireEvent.change(screen.getByLabelText('X-API-Key'), { target: { value: 'the-key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Unlock' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Lock API' })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Lock API' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Unlock live AI and GitHub' })).toBeInTheDocument());
    expect(sessionStorage.getItem('devsecops-sentinel-api-key')).toBeNull();
  });
});

describe('Remediation export', () => {
  it('downloads the export under the server-supplied file name', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/api/workflows/remediation/export/markdown')) {
        return new Response(new Blob(['# report']), {
          status: 200,
          headers: { 'content-disposition': 'attachment; filename="sample-remediation.md"' },
        });
      }
      return new Response('{}', { status: 404 });
    }));
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn(() => 'blob:url'),
      revokeObjectURL: vi.fn(),
    });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    await downloadRemediationExport('sample.yml', 'name: x', 'markdown');

    expect(click).toHaveBeenCalledTimes(1);
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:url');
  });

  it('a failed export throws with the status instead of downloading', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 500 })));
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

    await expect(downloadRemediationExport('sample.yml', 'name: x', 'sarif'))
      .rejects.toThrow('Export failed (500)');
    expect(click).not.toHaveBeenCalled();
  });
});
