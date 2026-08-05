import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

/**
 * Public mode: the scanner is open and the key is an upgrade.
 *
 * The regression worth guarding is a full-page gate reappearing in front of
 * analysis that needs no key — a public demonstration nobody can run
 * demonstrates nothing.
 */
const scenario = { id: 'sample', name: 'Sample', description: 'Sample', fileName: 'sample.yml' };

function respondWith(security: Record<string, unknown>) {
  return async function respond(input: RequestInfo | URL): Promise<Response> {
    const url = String(input);
    if (url === '/api/security/status') return Response.json(security);
    if (url === '/api/scenarios') return Response.json([scenario]);
    if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
    if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
    if (url === '/api/github/status') return Response.json({ enabled: false, configured: false, connected: false, mode: 'ReadOnly', allowedRepositoryCount: 0, message: 'Not configured.' });
    return new Response('{}', { status: 404 });
  };
}

const publicMode = {
  required: false,
  headerName: 'X-API-Key',
  sessionOnlyBrowserKey: true,
  mode: 'Public',
  keyUnlocksGitHub: true,
  keyUnlocksLiveAi: true,
};

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('Public mode', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(respondWith(publicMode)));
  });

  it('does not put a key gate in front of the workspace', async () => {
    render(<App />);

    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    expect(screen.queryByText('Access key required')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Analyze workflow' })).toBeInTheDocument();
  });

  it('still loads scenarios when the privileged GitHub call is refused', async () => {
    // The regression this guards: the three start-up calls were batched with
    // Promise.all, so a 401 from /api/github/status - the designed answer for
    // an anonymous caller - rejected the batch and discarded the scenarios that
    // had already arrived. The dropdown rendered empty on a working API.
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = String(input);
      if (url === '/api/security/status') return Response.json(publicMode);
      if (url === '/api/scenarios') return Response.json([scenario]);
      if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
      if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
      if (url === '/api/github/status') return new Response('{"title":"Authentication required"}', { status: 401 });
      return new Response('{}', { status: 404 });
    }));

    render(<App />);

    expect(await screen.findByDisplayValue('sample.yml')).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Sample' })).toBeInTheDocument();
    expect(screen.getByText(/GitHub: Unavailable/)).toBeInTheDocument();
  });

  it('offers the key as an upgrade rather than demanding it', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    const unlock = screen.getByRole('button', { name: 'Unlock live AI and GitHub' });

    // Hidden until asked for, so it cannot be mistaken for a gate.
    expect(screen.queryByLabelText('X-API-Key')).not.toBeInTheDocument();

    fireEvent.click(unlock);

    expect(screen.getByLabelText('X-API-Key')).toBeInTheDocument();
    expect(screen.getByText(/scanner works without a key/i)).toBeInTheDocument();
  });
});

describe('Required mode', () => {
  it('still gates the whole workspace', async () => {
    // The stricter mode has to keep working; Public is an addition, not a
    // replacement.
    vi.stubGlobal('fetch', vi.fn(respondWith({
      required: true,
      headerName: 'X-API-Key',
      sessionOnlyBrowserKey: true,
      mode: 'Required',
    })));

    render(<App />);

    expect(await screen.findByText('Access key required')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Analyze workflow' })).not.toBeInTheDocument();
  });
});
