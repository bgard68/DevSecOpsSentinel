import { useEffect, useMemo, useState } from 'react';
import {
  analyzeGitHubWorkflow,
  analyzeWorkflow,
  getSecurityStatus,
  getStoredApiKey,
  setStoredApiKey,
  explainWorkflow,
  getAiStatus,
  getGitHubRepositories,
  getGitHubStatus,
  getGitHubWorkflowContent,
  getGitHubWorkflows,
  getScenario,
  getScenarios,
  getRemediationReport,
  downloadRemediationExport,
} from './api';
import type {
  AiStatus,
  ApiSecurityStatus,
  GitHubConnectionStatus,
  GitHubRepositorySummary,
  GitHubWorkflowFile,
  GitHubWorkflowSummary,
  ScenarioSummary,
  WorkflowAnalysisResult,
  WorkflowExplanationResult,
  WorkflowFinding,
  RemediationReport,
} from './models';

const severityOrder = ['Critical', 'High', 'Medium', 'Low'];
type SourceMode = 'simulation' | 'github';
type ResultTab = 'findings' | 'remediation' | 'comparison' | 'advisor';

function getRiskLabel(findings: WorkflowFinding[]) {
  if (findings.some((finding) => finding.severity === 'Critical')) return 'Critical';
  if (findings.some((finding) => finding.severity === 'High')) return 'High';
  if (findings.some((finding) => finding.severity === 'Medium')) return 'Moderate';
  if (findings.length > 0) return 'Low';
  return 'Clear';
}

function countBySeverity(findings: WorkflowFinding[], severity: string) {
  return findings.filter((finding) => finding.severity === severity).length;
}

function CodePanel({ title, subtitle, content, tone }: { title: string; subtitle: string; content: string; tone: 'original' | 'proposed' }) {
  return <section className={`code-panel code-panel-${tone}`}>
    <header className="code-panel-header"><div><span className="panel-kicker">{subtitle}</span><h3>{title}</h3></div><span className="code-language">YAML</span></header>
    <pre tabIndex={0} aria-label={`${title} YAML`}><code>{content}</code></pre>
  </section>;
}

function App() {
  const [securityStatus, setSecurityStatus] = useState<ApiSecurityStatus | null>(null);
  const [apiKeyDraft, setApiKeyDraft] = useState('');
  const [apiKeyConfigured, setApiKeyConfigured] = useState(() => Boolean(getStoredApiKey()));
  const [sourceMode, setSourceMode] = useState<SourceMode>('simulation');
  const [scenarios, setScenarios] = useState<ScenarioSummary[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [fileName, setFileName] = useState('workflow.yml');
  const [content, setContent] = useState('');
  const [result, setResult] = useState<WorkflowAnalysisResult | null>(null);
  const [explanation, setExplanation] = useState<WorkflowExplanationResult | null>(null);
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [includeAi, setIncludeAi] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeResultTab, setActiveResultTab] = useState<ResultTab>('findings');
  const [gitHubStatus, setGitHubStatus] = useState<GitHubConnectionStatus | null>(null);
  const [repositories, setRepositories] = useState<GitHubRepositorySummary[]>([]);
  const [selectedRepository, setSelectedRepository] = useState('');
  const [workflows, setWorkflows] = useState<GitHubWorkflowSummary[]>([]);
  const [selectedWorkflowPath, setSelectedWorkflowPath] = useState('');
  const [gitHubSource, setGitHubSource] = useState<GitHubWorkflowFile | null>(null);
  const [remediation, setRemediation] = useState<RemediationReport | null>(null);

  useEffect(() => {
    getSecurityStatus()
      .then((status) => {
        setSecurityStatus(status);

        if (status.required && !apiKeyConfigured) {
          return;
        }

        return Promise.all([getScenarios(), getAiStatus(), getGitHubStatus()])
          .then(([items, ai, github]) => {
            setScenarios(items);
            setAiStatus(ai);
            setGitHubStatus(github);
            if (items.length > 0) setSelectedId(items[0].id);
          });
      })
      .catch((reason: unknown) =>
        setError(reason instanceof Error
          ? reason.message
          : 'Application data could not be loaded.'));
  }, [apiKeyConfigured]);

  useEffect(() => {
    if (sourceMode !== 'simulation' || !selectedId) return;
    getScenario(selectedId).then((scenario) => {
      setFileName(scenario.fileName); setContent(scenario.content); resetResults();
    }).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'Scenario could not be loaded.'));
  }, [selectedId, sourceMode]);

  useEffect(() => {
    if (sourceMode !== 'github' || !gitHubStatus?.connected || repositories.length > 0) return;
    setIsLoading(true);
    getGitHubRepositories().then((items) => {
      setRepositories(items);
      if (items.length > 0) setSelectedRepository(items[0].fullName);
    }).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'GitHub repositories could not be loaded.'))
      .finally(() => setIsLoading(false));
  }, [sourceMode, gitHubStatus, repositories.length]);

  useEffect(() => {
    if (sourceMode !== 'github' || !selectedRepository) return;
    const [owner, repository] = selectedRepository.split('/');
    setIsLoading(true); setWorkflows([]); setSelectedWorkflowPath(''); resetResults();
    getGitHubWorkflows(owner, repository).then((items) => {
      setWorkflows(items);
      if (items.length > 0) setSelectedWorkflowPath(items[0].path);
    }).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'GitHub workflows could not be loaded.'))
      .finally(() => setIsLoading(false));
  }, [selectedRepository, sourceMode]);

  useEffect(() => {
    if (sourceMode !== 'github' || !selectedRepository || !selectedWorkflowPath) return;
    const [owner, repository] = selectedRepository.split('/');
    const branch = repositories.find((item) => item.fullName === selectedRepository)?.defaultBranch;
    setIsLoading(true);
    getGitHubWorkflowContent(owner, repository, selectedWorkflowPath, branch).then((workflow) => {
      setGitHubSource(workflow); setFileName(workflow.path.split('/').pop() ?? workflow.path); setContent(workflow.content); resetResults();
    }).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : 'GitHub workflow content could not be loaded.'))
      .finally(() => setIsLoading(false));
  }, [selectedWorkflowPath, selectedRepository, sourceMode, repositories]);

  function unlockApi(event: React.FormEvent) {
    event.preventDefault();
    if (!apiKeyDraft.trim()) {
      setError('Enter the API access key.');
      return;
    }

    setStoredApiKey(apiKeyDraft);
    setApiKeyConfigured(true);
    setApiKeyDraft('');
    setError('');
  }

  function clearApiKey() {
    setStoredApiKey('');
    setApiKeyConfigured(false);
    setScenarios([]);
    setAiStatus(null);
    setGitHubStatus(null);
    resetResults();
  }

  function resetResults() { setResult(null); setExplanation(null); setRemediation(null); setActiveResultTab('findings'); setError(''); }

  async function submit(event: React.FormEvent) {
    event.preventDefault(); setIsLoading(true); setError(''); setResult(null); setExplanation(null); setRemediation(null); setActiveResultTab(includeAi ? 'advisor' : 'findings');
    try {
      if (sourceMode === 'github') {
        if (!selectedRepository || !selectedWorkflowPath) throw new Error('Select a GitHub workflow first.');
        const [owner, repository] = selectedRepository.split('/');
        const branch = repositories.find((item) => item.fullName === selectedRepository)?.defaultBranch;
        const response = await analyzeGitHubWorkflow(owner, repository, selectedWorkflowPath, branch, includeAi);
        setGitHubSource(response.source);
        if (includeAi) {
          const explained = response.result as WorkflowExplanationResult;
          setResult(explained.analysis); setExplanation(explained);
        } else setResult(response.result as WorkflowAnalysisResult);
        setRemediation(await getRemediationReport(fileName, content));
      } else if (includeAi) {
        const response = await explainWorkflow(fileName, content, true); setResult(response.analysis); setExplanation(response); setRemediation(await getRemediationReport(fileName, content));
      } else { setResult(await analyzeWorkflow(fileName, content)); setRemediation(await getRemediationReport(fileName, content)); }
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Analysis failed.'); }
    finally { setIsLoading(false); }
  }

  const findings = result?.findings ?? [];
  const sortedFindings = useMemo(() => severityOrder.flatMap((severity) => findings.filter((finding) => finding.severity === severity)), [findings]);
  const riskLabel = result ? getRiskLabel(findings) : 'Not scanned';
  const aiModeLabel = aiStatus ? `${aiStatus.mode}${aiStatus.configured ? ' · configured' : ''}` : 'Loading';
  const selectedScenario = scenarios.find((scenario) => scenario.id === selectedId);
  const githubReady = Boolean(gitHubStatus?.connected);
  const referenceResolutionWarnings =
    result?.patch?.referenceResolutionWarnings ?? [];

  if (securityStatus?.required && !apiKeyConfigured) {
    return <main className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">DS</div>
          <div>
            <span className="eyebrow">Protected portfolio deployment</span>
            <h1>DevSecOps Sentinel</h1>
            <p>Enter the deployment API key to open the analysis workspace.</p>
          </div>
        </div>
      </header>
      <section className="access-gate" aria-labelledby="access-gate-title">
        <span className="panel-kicker">API authentication</span>
        <h2 id="access-gate-title">Access key required</h2>
        <p>The key is stored only in this browser tab. It is not embedded in the React bundle or written to local storage.</p>
        <form onSubmit={unlockApi}>
          <label htmlFor="api-access-key">{securityStatus.headerName}</label>
          <input
            id="api-access-key"
            type="password"
            autoComplete="off"
            value={apiKeyDraft}
            onChange={(event) => setApiKeyDraft(event.target.value)}
          />
          <button className="primary-action" type="submit">Open workspace</button>
        </form>
        {error && <p className="error">{error}</p>}
      </section>
    </main>;
  }

  return <main className="app-shell">
    <header className="topbar"><div className="brand-lockup"><div className="brand-mark" aria-hidden="true">DS</div><div><span className="eyebrow">v{__APP_VERSION__} · GitHub Actions supply-chain analysis</span><h1>DevSecOps Sentinel</h1><p>Detect, explain, preview, validate, and export secure GitHub Actions remediations without modifying repositories.</p></div></div>
      <div className="status-cluster" aria-label="Application status"><div className="status-item"><span className="status-dot status-dot-online" />API connected</div><div className="status-item"><span className="status-dot status-dot-ai" />AI: {aiModeLabel}</div><div className={`status-item ${githubReady ? 'status-item-safe' : ''}`}>GitHub: {githubReady ? 'Read-only connected' : 'Unavailable'}</div>{securityStatus?.required && <button type="button" className="status-item status-action" onClick={clearApiKey}>Lock API</button>}</div></header>

    <section className="hero-strip" aria-label="Security boundaries"><div><strong>Read-only GitHub App</strong><span>No branches, commits, or pull requests.</span></div><div><strong>Repository allowlist</strong><span>Only explicitly permitted repositories appear.</span></div><div><strong>Deterministic first</strong><span>AI remains optional and advisory.</span></div></section>

    <div className="source-switcher" role="tablist" aria-label="Workflow source">
      <button type="button" role="tab" aria-selected={sourceMode === 'simulation'} className={sourceMode === 'simulation' ? 'active' : ''} onClick={() => { setSourceMode('simulation'); resetResults(); }}>Simulation</button>
      <button type="button" role="tab" aria-selected={sourceMode === 'github'} className={sourceMode === 'github' ? 'active' : ''} onClick={() => { setSourceMode('github'); resetResults(); }}>GitHub Sandbox <span className="read-only-tag">READ ONLY</span></button>
    </div>

    <section className="workspace"><form className="control-panel" onSubmit={submit}>
      <div className="panel-heading"><div><span className="panel-kicker">Analysis workspace</span><h2>{sourceMode === 'github' ? 'GitHub workflow' : 'Workflow input'}</h2></div><span className={`mode-pill ${sourceMode === 'github' ? 'mode-pill-readonly' : 'mode-pill-safe'}`}>{sourceMode === 'github' ? 'Read only' : 'Simulation'}</span></div>

      {sourceMode === 'simulation' ? <>
        <label htmlFor="scenario">Sample scenario</label><select id="scenario" value={selectedId} onChange={(event) => setSelectedId(event.target.value)}>{scenarios.map((scenario) => <option key={scenario.id} value={scenario.id}>{scenario.name}</option>)}</select>
        {selectedScenario && <p className="scenario-description">{selectedScenario.description}</p>}
        <label htmlFor="file-name">Workflow file</label><input id="file-name" value={fileName} onChange={(event) => setFileName(event.target.value)} />
      </> : <>
        <div className={`github-connection-card ${githubReady ? 'connected' : 'disconnected'}`}><strong>{githubReady ? 'GitHub App connected' : 'GitHub App unavailable'}</strong><span>{gitHubStatus?.message ?? 'Checking connection…'}</span></div>
        <label htmlFor="github-repository">Allowed repository</label><select id="github-repository" value={selectedRepository} onChange={(event) => setSelectedRepository(event.target.value)} disabled={!githubReady || repositories.length === 0}><option value="">Select repository</option>{repositories.map((repo) => <option key={repo.fullName} value={repo.fullName}>{repo.fullName}</option>)}</select>
        <label htmlFor="github-workflow">Workflow file</label><select id="github-workflow" value={selectedWorkflowPath} onChange={(event) => setSelectedWorkflowPath(event.target.value)} disabled={!selectedRepository || workflows.length === 0}><option value="">Select workflow</option>{workflows.map((workflow) => <option key={workflow.sha} value={workflow.path}>{workflow.path}</option>)}</select>
        {gitHubSource && <div className="source-metadata"><span>Branch <strong>{gitHubSource.defaultBranch}</strong></span><span>SHA <code>{gitHubSource.sha.slice(0, 10)}</code></span><a href={gitHubSource.htmlUrl} target="_blank" rel="noreferrer">View on GitHub</a></div>}
      </>}

      <div className="editor-label-row"><label htmlFor="workflow">Workflow YAML</label><span>{content.length.toLocaleString()} characters</span></div>
      <div className="editor-shell"><div className="editor-toolbar"><span className="editor-dot" /><span className="editor-dot" /><span className="editor-dot" /><strong>{fileName}</strong>{sourceMode === 'github' && <span className="editor-readonly">READ ONLY</span>}</div><textarea id="workflow" value={content} onChange={(event) => setContent(event.target.value)} spellCheck={false} readOnly={sourceMode === 'github'} aria-describedby="workflow-help" /></div>

      <div className="ai-control-card"><label className="ai-toggle" htmlFor="include-ai"><input id="include-ai" type="checkbox" aria-label="Include AI explanation" checked={includeAi} onChange={(event) => setIncludeAi(event.target.checked)} disabled={aiStatus?.enabled === false} /><span><strong>Include AI explanation</strong><small>Explain confirmed findings and remediation steps.</small></span></label><span className="mode-pill">{aiModeLabel}</span></div>
      <p id="workflow-help" className="helper-text">{sourceMode === 'github' ? 'The selected GitHub workflow is retrieved and analyzed without modifying the repository.' : 'Live AI mode sends sanitized context; Mock mode uses no credits.'}</p>
      <button className="primary-action" type="submit" disabled={isLoading || content.trim().length === 0 || (sourceMode === 'github' && !selectedWorkflowPath)}>{isLoading ? <><span className="spinner" aria-hidden="true" />Loading…</> : sourceMode === 'github' ? 'Analyze GitHub workflow' : 'Analyze workflow'}</button>
      {error && <p className="error" role="alert">{error}</p>}
    </form>

    <section className="results" aria-live="polite">{!result && !error && <div className="empty-state"><div className="empty-icon" aria-hidden="true">✓</div><h2>{sourceMode === 'github' ? 'Select a GitHub workflow' : 'Ready to analyze'}</h2><p>{sourceMode === 'github' ? 'Choose an allowlisted repository and workflow. DevSecOps Sentinel will read and analyze it without making repository changes.' : 'Select a scenario or edit the YAML, then run the scanner.'}</p></div>}
      {result && <><div className="summary-grid"><article className="metric-card"><span>Risk level</span><strong className={`risk-${riskLabel.toLowerCase().replace(' ', '-')}`}>{riskLabel}</strong><small>Deterministic findings</small></article><article className="metric-card"><span>Total findings</span><strong>{result.findingCount ?? findings.length}</strong><small>{countBySeverity(findings, 'Critical')} critical · {countBySeverity(findings, 'High')} high</small></article><article className="metric-card"><span>Auto-fixes</span><strong>{result.patch?.appliedRuleIds.length ?? 0}</strong><small>Proposed only</small></article><article className="metric-card"><span>Source</span><strong>{sourceMode === 'github' ? 'GitHub' : 'Local'}</strong><small>{sourceMode === 'github' ? 'Read-only retrieval' : 'Simulation scenario'}</small></article></div>
        <nav className="result-tabs" aria-label="Analysis result sections"><button type="button" className={activeResultTab === 'findings' ? 'active' : ''} onClick={() => setActiveResultTab('findings')}>Findings <span>{result.findingCount}</span></button><button type="button" disabled={!remediation} className={activeResultTab === 'remediation' ? 'active' : ''} onClick={() => setActiveResultTab('remediation')}>Remediation plan</button><button type="button" className={activeResultTab === 'comparison' ? 'active' : ''} onClick={() => setActiveResultTab('comparison')}>Workflow comparison</button><button type="button" disabled={!explanation} className={activeResultTab === 'advisor' ? 'active' : ''} onClick={() => setActiveResultTab('advisor')}>AI advisor</button></nav>
        {activeResultTab === 'findings' && <section className="findings-panel"><div className="section-heading"><div><span className="panel-kicker">Authoritative results</span><h2>Deterministic findings</h2></div><span className="result-badge">{result.findingCount === 0 ? 'Compliant' : 'Action required'}</span></div>{result.findings.length === 0 ? <div className="success-card"><strong>No configured rule violations were detected.</strong><span>The workflow passed all deterministic security checks.</span></div> : sortedFindings.map((finding) => <article className={`finding finding-${finding.severity.toLowerCase()}`} key={`${finding.ruleId}-${finding.lineNumber}`}><div className="finding-heading"><span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span><code>{finding.ruleId}</code>{finding.lineNumber && <span>Line {finding.lineNumber}</span>}{finding.isAutomaticallyFixable && <span className="auto-fix-label">Proposed fix available</span>}</div><h3>{finding.title}</h3><p>{finding.description}</p><div className="recommendation"><strong>Recommended remediation</strong><span>{finding.recommendation}</span></div></article>)}</section>}
        {activeResultTab === 'remediation' && remediation && <section className="remediation-panel"><div className="section-heading"><div><span className="panel-kicker">Validated remediation</span><h2>Risk reduction plan</h2></div><span className="result-badge">{remediation.riskReductionPercent}% reduction</span></div><div className="remediation-metrics"><article><span>Risk score</span><strong>{remediation.originalRiskScore} → {remediation.proposedRiskScore}</strong></article><article><span>Resolved</span><strong>{remediation.resolvedFindingCount}</strong></article><article><span>Remaining</span><strong>{remediation.remainingFindingCount}</strong></article><article><span>Patch</span><strong>{remediation.patchValid ? 'Valid' : 'Review'}</strong></article></div>{referenceResolutionWarnings.length > 0 && (
          <div className="warning">
            <strong>Action SHA resolution</strong>
            {referenceResolutionWarnings.map((warning) => (
              <div key={warning}>{warning}</div>
            ))}
          </div>
        )}<div className="export-actions"><button type="button" onClick={() => downloadRemediationExport(fileName, content, 'markdown')}>Export Markdown</button><button type="button" onClick={() => downloadRemediationExport(fileName, content, 'sarif')}>Export SARIF</button><button type="button" onClick={() => downloadRemediationExport(fileName, content, 'json')}>Export JSON</button><button type="button" onClick={() => downloadRemediationExport(fileName, content, 'diff')}>Download patch</button><button type="button" onClick={() => downloadRemediationExport(fileName, content, 'html')}>Printable HTML/PDF</button></div>{remediation.changes.map((change) => <article className={`remediation-change ${change.resolved ? 'resolved' : 'remaining'}`} key={change.ruleId}><header><code>{change.ruleId}</code><span>{change.resolved ? 'Resolved by preview' : 'Still requires review'}</span></header><h3>{change.title}</h3><p>{change.recommendation}</p></article>)}<pre className="diff-view" tabIndex={0}><code>{remediation.unifiedDiff.join('\n')}</code></pre></section>}
        {activeResultTab === 'advisor' && explanation && <section className="ai-panel"><div className="ai-panel-heading"><div><span className="eyebrow">AI Security Advisor</span><h2>{explanation.explanation.generatedByAi ? 'OpenAI explanation' : 'Deterministic fallback'}</h2></div><span className="mode-pill">{explanation.explanation.mode}</span></div><div className="advisor-notice"><strong>Advisory only</strong><span>AI cannot create findings, change severity, or apply patches.</span></div>{explanation.sensitiveContentRedacted && <p className="warning">Potentially sensitive values were redacted.</p>}<div className="advisor-summary"><span className="panel-kicker">Executive summary</span><p>{explanation.explanation.summary}</p></div>{explanation.explanation.findings.map((item) => <article className="ai-finding" key={item.ruleId}><header><code>{item.ruleId}</code><span>{item.confidence} confidence</span></header><p><strong>Why it matters</strong>{item.whyItMatters}</p><p><strong>Recommended action</strong>{item.recommendedAction}</p></article>)}</section>}
        {activeResultTab === 'comparison' && result.patch && <><div className="readonly-banner"><strong>Preview only</strong><span>Phase D does not write this patch back to GitHub.</span></div><div className="comparison"><CodePanel title="Original workflow" subtitle="Repository content" content={result.patch.originalContent} tone="original" /><CodePanel title="Proposed workflow" subtitle="Validated remediation preview" content={result.patch.proposedContent} tone="proposed" /></div></>}
      </>}
    </section></section>
  </main>;
}
export default App;
