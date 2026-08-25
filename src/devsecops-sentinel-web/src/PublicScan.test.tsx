import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

/**
 * Public repository scanning: type owner/repository, get per-file findings,
 * no key involved.
 *
 * The regression worth guarding is the feature quietly requiring something —
 * a key, a paste, a second step. Its entire value is that it asks for a name
 * and nothing else.
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

const scanResult = {
  owner: 'octo',
  repository: 'app',
  status: 'Completed',
  detail: null,
  files: [
    {
      fileName: 'ci.yml',
      htmlUrl: 'https://github.com/octo/app/blob/main/.github/workflows/ci.yml',
      analysis: {
        fileName: 'ci.yml',
        isValid: true,
        validationErrors: [],
        findings: [
          {
            ruleId: 'GHA001',
            severity: 'High',
            title: 'Action reference is not pinned to a commit SHA',
            description: 'A movable tag can resolve to different code.',
            lineNumber: 8,
            recommendation: 'Pin the action to a full commit SHA.',
            isAutomaticallyFixable: true,
          },
        ],
        patch: null,
        findingCount: 1,
      },
    },
    {
      fileName: 'release.yml',
      htmlUrl: 'https://github.com/octo/app/blob/main/.github/workflows/release.yml',
      analysis: {
        fileName: 'release.yml',
        isValid: true,
        validationErrors: [],
        findings: [],
        patch: null,
        findingCount: 0,
        acknowledgements: [
          {
            ruleId: 'GHA002',
            title: 'security-events: write is required, not excessive',
            detail: "'github/codeql-action/analyze' in job 'analyze' cannot work without it.",
            lineNumber: 8,
            acceptedBy: 'Rule',
          },
          {
            ruleId: 'GHA002',
            title: 'Workflow grants excessive token permissions - accepted',
            detail: 'deleting a workflow run has no narrower grant (accepted in the workflow, line 12; severity was High)',
            lineNumber: 13,
            acceptedBy: 'Author',
          },
        ],
      },
    },
  ],
  skippedFiles: 0,
  fetchedAtUtc: '2026-08-24T00:00:00Z',
  fromCache: false,
};

function respond(handlers: Record<string, () => Response>) {
  return async (input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    if (url === '/api/security/status') return Response.json(publicMode);
    if (url === '/api/scenarios') return Response.json([scenario]);
    if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
    if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
    if (url === '/api/github/status') return Response.json({ enabled: false, configured: false, connected: false, mode: 'ReadOnly', allowedRepositoryCount: 0, message: 'Not configured.' });
    for (const [prefix, handler] of Object.entries(handlers)) {
      if (url.includes(prefix)) return handler();
    }
    return new Response('{}', { status: 404 });
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe('Public repository scan', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(respond({
      '/api/public-scan/octo/app': () => Response.json(scanResult),
    })));
  });

  it('scans by name and shows per-file findings without any key', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByRole('tab', { name: /Public repo/ })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('tab', { name: /Public repo/ }));
    fireEvent.change(screen.getByLabelText('Public repository'), { target: { value: 'octo/app' } });
    fireEvent.click(screen.getByRole('button', { name: 'Scan public repository' }));

    await waitFor(() => expect(screen.getByText('ci.yml')).toBeInTheDocument());

    // The vulnerable file shows its finding; the clean file says so.
    expect(screen.getByText('Action reference is not pinned to a commit SHA')).toBeInTheDocument();
    expect(screen.getByText('release.yml')).toBeInTheDocument();
    expect(screen.getByText('No configured rule violations were detected.')).toBeInTheDocument();

    // And the whole path involved no key gate.
    expect(screen.queryByText('Access key required')).not.toBeInTheDocument();
  });

  it('accepts a pasted github.com URL, not only owner/name', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByRole('tab', { name: /Public repo/ })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('tab', { name: /Public repo/ }));
    fireEvent.change(screen.getByLabelText('Public repository'), {
      target: { value: 'https://github.com/octo/app' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Scan public repository' }));

    await waitFor(() => expect(screen.getByText('ci.yml')).toBeInTheDocument());
  });

  it('surfaces the problem detail when the repository is not found', async () => {
    vi.stubGlobal('fetch', vi.fn(respond({
      '/api/public-scan/octo/gone': () =>
        Response.json(
          { title: 'Repository not found', detail: 'No public repository with workflows was found under that name.', status: 404 },
          { status: 404 }),
    })));

    render(<App />);
    await waitFor(() => expect(screen.getByRole('tab', { name: /Public repo/ })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('tab', { name: /Public repo/ }));
    fireEvent.change(screen.getByLabelText('Public repository'), { target: { value: 'octo/gone' } });
    fireEvent.click(screen.getByRole('button', { name: 'Scan public repository' }));

    await waitFor(() => expect(
      screen.getByText('No public repository with workflows was found under that name.')).toBeInTheDocument());
  });

  it('shows what a rule accepted without making the file look non-compliant', async () => {
    // The reason a finding disappeared has to be visible, or "clean" cannot be
    // told from "never checked". It must not count as a finding while doing it.
    render(<App />);
    await waitFor(() => expect(screen.getByRole('tab', { name: /Public repo/ })).toBeInTheDocument());

    fireEvent.click(screen.getByRole('tab', { name: /Public repo/ }));
    fireEvent.change(screen.getByLabelText('Public repository'), { target: { value: 'octo/app' } });
    fireEvent.click(screen.getByRole('button', { name: 'Scan public repository' }));

    await waitFor(() => expect(screen.getByText('Reviewed and accepted')).toBeInTheDocument());
    expect(screen.getByText(/security-events: write is required/)).toBeInTheDocument();

    // A documented requirement and a person's judgement are different claims,
    // and only the second can be wrong about the risk.
    expect(screen.getByText('required by an action')).toBeInTheDocument();
    expect(screen.getByText('accepted by author')).toBeInTheDocument();

    // release.yml still reads as clean: the note is not a finding.
    expect(screen.getByText(/Clean · 0 findings/)).toBeInTheDocument();
  });
});
