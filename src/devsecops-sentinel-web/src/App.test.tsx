import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

const scenario = { id: 'sample', name: 'Sample', description: 'Sample', fileName: 'sample.yml' };
const analysis = { fileName: 'sample.yml', isValid: true, validationErrors: [], findings: [], findingCount: 0, patch: { originalContent: 'x', proposedContent: 'x', appliedRuleIds: [], proposedContentIsValid: true, referenceResolutionWarnings: [] } };
const repo = { owner: 'bgard68', name: 'DevSecOpsSentinel-Sandbox', fullName: 'bgard68/DevSecOpsSentinel-Sandbox', defaultBranch: 'main', isPrivate: true, htmlUrl: 'https://github.test/repo' };
const workflow = { name: 'safe.yml', path: '.github/workflows/safe.yml', sha: '1234567890abcdef', htmlUrl: 'https://github.test/workflow' };
const remediation = { fileName: 'sample.yml', originalAnalysis: analysis, proposedAnalysis: analysis, changes: [], unifiedDiff: ['--- original', '+++ proposed'], originalRiskScore: 0, proposedRiskScore: 0, riskReductionPercent: 0, patchValid: true, resolvedFindingCount: 0, remainingFindingCount: 0 };
const source = { owner: repo.owner, repository: repo.name, defaultBranch: 'main', path: workflow.path, sha: workflow.sha, content: 'name: Safe\non:\n  push:\n', htmlUrl: workflow.htmlUrl, retrievedAtUtc: '2026-08-03T00:00:00Z' };

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/api/security/status') return Response.json({ required: false, headerName: 'X-API-Key', sessionOnlyBrowserKey: true });
    if (url === '/api/scenarios') return Response.json([scenario]);
    if (url === '/api/ai/status') return Response.json({ enabled: true, configured: false, provider: 'OpenAI', mode: 'Mock', model: 'gpt-5-mini', costProtection: { explicitRequestOnly: true, mockModeConsumesCredits: false } });
    if (url === '/api/github/status') return Response.json({ enabled: true, configured: true, connected: true, mode: 'ReadOnly', allowedRepositoryCount: 1, message: 'Connected.' });
    if (url === '/api/scenarios/sample') return Response.json({ ...scenario, content: 'name: Sample\non:\n  push:\n' });
    if (url === '/api/github/repositories') return Response.json([repo]);
    if (url.endsWith('/workflows')) return Response.json([workflow]);
    if (url.includes('/workflows/content?')) return Response.json(source);
    if (url === '/api/workflows/remediation' && init?.method === 'POST') return Response.json(remediation);
    if (url === '/api/workflows/analyze' && init?.method === 'POST') return Response.json(analysis);
    if (url.endsWith('/analyze') && init?.method === 'POST') return Response.json({ source, result: analysis });
    if (url === '/api/workflows/explain' && init?.method === 'POST') return Response.json({ analysis, sensitiveContentRedacted: false, explanation: { summary: 'Mock explanation', findings: [], recommendedNextStep: 'Review.', limitations: [], generatedByAi: true, mode: 'Mock', fallbackReason: null } });
    return new Response('{}', { status: 404 });
  }));
});

describe('App', () => {
  it('runs deterministic simulation analysis without AI by default', async () => {
    render(<App />); await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));
    expect(await screen.findByText('No configured rule violations were detected.')).toBeInTheDocument();
  });

  it('renders the remediation plan and export actions', async () => {
    render(<App />); await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Remediation plan' }));
    expect(screen.getByText('Risk reduction plan')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Export SARIF' })).toBeInTheDocument();
  });

  it('renders the AI advisor when explicitly selected', async () => {
    render(<App />); await waitFor(() => expect(screen.getByDisplayValue('sample.yml')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('checkbox', { name: /include ai explanation/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Analyze workflow' }));
    expect(await screen.findByText('Mock explanation')).toBeInTheDocument();
  });

  it('loads and analyzes an allowlisted GitHub workflow in read-only mode', async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole('tab', { name: /GitHub Sandbox/i }));
    expect(await screen.findByText('GitHub App connected')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Allowed repository')).toHaveValue(repo.fullName));
    await waitFor(() => expect(screen.getByLabelText('Workflow file')).toHaveValue(workflow.path));
    expect(screen.getByLabelText('Workflow YAML')).toHaveAttribute('readonly');
    fireEvent.click(screen.getByRole('button', { name: 'Analyze GitHub workflow' }));
    expect(await screen.findByText('No configured rule violations were detected.')).toBeInTheDocument();
  });
});
