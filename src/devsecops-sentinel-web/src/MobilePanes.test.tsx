import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

/**
 * On a phone the workspace shows one pane at a time.
 *
 * The behaviour worth protecting is not the switcher itself but what happens
 * after an analysis: the panes are exclusive, so finishing has to move you to
 * the answer. Leaving the input selected with a result rendered in a hidden
 * pane would be worse than the stacking it replaced — the findings would be
 * not merely far away but invisible.
 *
 * The switcher renders at every width; CSS hides it once both panes fit side by
 * side, which jsdom does not evaluate. So these assert the state machine, and
 * the media query is verified in the browser.
 */
const scenario = { id: 'sample', name: 'Sample', description: 'Sample', fileName: 'sample.yml' };
const analysis = {
  fileName: 'sample.yml', isValid: true, validationErrors: [],
  findings: [{ ruleId: 'GHA001', severity: 'High', title: 'Action not pinned', description: 'd', lineNumber: 7, recommendation: 'r', autoFixable: true }],
  findingCount: 1,
  patch: { originalContent: 'x', proposedContent: 'x', appliedRuleIds: [], proposedContentIsValid: true, referenceResolutionWarnings: [] },
};
const remediation = {
  fileName: 'sample.yml', originalAnalysis: analysis, proposedAnalysis: analysis, changes: [],
  unifiedDiff: ['--- original'], originalRiskScore: 7, proposedRiskScore: 0,
  riskReductionPercent: 100, patchValid: true, resolvedFindingCount: 1, remainingFindingCount: 0,
};

async function respond(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = String(input);
  if (url === '/api/security/status') return Response.json({ required: false, headerName: 'X-API-Key', sessionOnlyBrowserKey: true, mode: 'Public' });
  if (url === '/api/scenarios') return Response.json([scenario]);
  if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
  if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
  if (url === '/api/github/status') return new Response('{}', { status: 401 });
  if (url === '/api/workflows/analyze' && init?.method === 'POST') return Response.json(analysis);
  if (url === '/api/workflows/remediation' && init?.method === 'POST') return Response.json(remediation);
  return new Response('{}', { status: 404 });
}

beforeEach(() => vi.stubGlobal('fetch', vi.fn(respond)));
afterEach(() => { vi.unstubAllGlobals(); sessionStorage.clear(); });

describe('Workspace panes', () => {
  it('starts on the input pane', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    expect(screen.getByRole('tab', { name: /^Input$/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /^Results/ })).toHaveAttribute('aria-selected', 'false');
  });

  it('moves to the results pane once an analysis finishes', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));

    await waitFor(() =>
      expect(screen.getByRole('tab', { name: /^Results/ })).toHaveAttribute('aria-selected', 'true'));
    expect(screen.getByRole('tab', { name: /^Input$/ })).toHaveAttribute('aria-selected', 'false');
  });

  it('shows the finding count on the results tab', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));

    // So the tab says whether it is worth switching to before you switch.
    expect(await screen.findByRole('tab', { name: /Results\s*1/ })).toBeInTheDocument();
  });

  it('lets you go back to the input after analysing', async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());

    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));
    await waitFor(() => expect(screen.getByRole('tab', { name: /^Results/ })).toHaveAttribute('aria-selected', 'true'));

    fireEvent.click(screen.getByRole('tab', { name: /^Input$/ }));

    expect(screen.getByRole('tab', { name: /^Input$/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument();
  });
});
