import type {
  AiStatus,
  ApiSecurityStatus,
  ScenarioDetail,
  ScenarioSummary,
  WorkflowAnalysisResult,
  WorkflowExplanationResult,
  GitHubAnalysisResponse,
  GitHubConnectionStatus,
  GitHubRepositorySummary,
  GitHubWorkflowFile,
  GitHubWorkflowSummary,
} from './models';

const apiKeyStorageKey = 'devsecops-sentinel-api-key';

export function getStoredApiKey(): string {
  return sessionStorage.getItem(apiKeyStorageKey) ?? '';
}

export function setStoredApiKey(value: string): void {
  const normalized = value.trim();
  if (normalized) {
    sessionStorage.setItem(apiKeyStorageKey, normalized);
  } else {
    sessionStorage.removeItem(apiKeyStorageKey);
  }
}

async function apiFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  const apiKey = getStoredApiKey();

  if (apiKey) {
    headers.set('X-API-Key', apiKey);
  }

  return fetch(input, {
    ...init,
    headers,
  });
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const problem = await response.json().catch(() => ({ title: 'Request failed' }));
    throw new Error(problem.detail ?? problem.title ?? `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export async function getSecurityStatus(): Promise<ApiSecurityStatus> {
  return readJson(await fetch('/api/security/status'));
}

export async function getScenarios(): Promise<ScenarioSummary[]> {
  return readJson(await apiFetch('/api/scenarios'));
}

export async function getScenario(id: string): Promise<ScenarioDetail> {
  return readJson(await apiFetch(`/api/scenarios/${encodeURIComponent(id)}`));
}

export async function getAiStatus(): Promise<AiStatus> {
  return readJson(await apiFetch('/api/ai/status'));
}

export async function analyzeWorkflow(fileName: string, content: string): Promise<WorkflowAnalysisResult> {
  return readJson(await apiFetch('/api/workflows/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, content }),
  }));
}

export async function explainWorkflow(
  fileName: string,
  content: string,
  useAi: boolean,
): Promise<WorkflowExplanationResult> {
  return readJson(await apiFetch('/api/workflows/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, content, useAi }),
  }));
}

export async function getGitHubStatus(): Promise<GitHubConnectionStatus> {
  return readJson(await apiFetch('/api/github/status'));
}

export async function getGitHubRepositories(): Promise<GitHubRepositorySummary[]> {
  return readJson(await apiFetch('/api/github/repositories'));
}

export async function getGitHubWorkflows(owner: string, repository: string): Promise<GitHubWorkflowSummary[]> {
  return readJson(await apiFetch(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/workflows`));
}

export async function getGitHubWorkflowContent(
  owner: string,
  repository: string,
  path: string,
  reference?: string,
): Promise<GitHubWorkflowFile> {
  const query = new URLSearchParams({ path });
  if (reference) query.set('reference', reference);
  return readJson(await apiFetch(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/workflows/content?${query}`));
}

export async function analyzeGitHubWorkflow(
  owner: string,
  repository: string,
  path: string,
  reference: string | undefined,
  useAi: boolean,
): Promise<GitHubAnalysisResponse> {
  return readJson(await apiFetch(`/api/github/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, reference, useAi }),
  }));
}

export async function getRemediationReport(fileName: string, content: string): Promise<import('./models').RemediationReport> {
  return readJson(await apiFetch('/api/workflows/remediation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, content }),
  }));
}

export async function downloadRemediationExport(fileName: string, content: string, format: string): Promise<void> {
  const response = await apiFetch(`/api/workflows/remediation/export/${encodeURIComponent(format)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, content }),
  });
  if (!response.ok) throw new Error(`Export failed (${response.status})`);
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') ?? '';
  const match = /filename\*?=(?:UTF-8''|\")?([^\";]+)/i.exec(disposition);
  const extension = format === 'markdown' ? 'md' : format === 'diff' ? 'patch' : format;
  const downloadName = match ? decodeURIComponent(match[1].replace(/\"/g, '')) : `${fileName}-remediation.${extension}`;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = downloadName;
  anchor.click();
  URL.revokeObjectURL(url);
}
