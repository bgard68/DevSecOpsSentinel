export interface ApiSecurityStatus {
  required: boolean;
  headerName: string;
  sessionOnlyBrowserKey: boolean;
}

export interface ScenarioSummary {
  id: string;
  name: string;
  description: string;
  fileName: string;
}

export interface ScenarioDetail extends ScenarioSummary {
  content: string;
}

export interface WorkflowFinding {
  ruleId: string;
  severity: string;
  title: string;
  description: string;
  lineNumber: number | null;
  recommendation: string;
  isAutomaticallyFixable: boolean;
}

export interface WorkflowPatch {
  originalContent: string;
  proposedContent: string;
  appliedRuleIds: string[];
  proposedContentIsValid: boolean;
  referenceResolutionWarnings: string[];
}

export interface WorkflowAnalysisResult {
  fileName: string;
  isValid: boolean;
  validationErrors: string[];
  findings: WorkflowFinding[];
  patch: WorkflowPatch | null;
  findingCount: number;
}

export interface AiFindingExplanation {
  ruleId: string;
  whyItMatters: string;
  recommendedAction: string;
  confidence: string;
}

export interface WorkflowAiExplanation {
  summary: string;
  findings: AiFindingExplanation[];
  recommendedNextStep: string;
  limitations: string[];
  generatedByAi: boolean;
  mode: string;
  fallbackReason: string | null;
}

export interface WorkflowExplanationResult {
  analysis: WorkflowAnalysisResult;
  explanation: WorkflowAiExplanation;
  sensitiveContentRedacted: boolean;
}

export interface AiStatus {
  enabled: boolean;
  configured: boolean;
  provider: string;
  mode: string;
  model: string;
  costProtection: {
    explicitRequestOnly: boolean;
    mockModeConsumesCredits: boolean;
  };
}


export interface GitHubConnectionStatus {
  enabled: boolean;
  configured: boolean;
  connected: boolean;
  mode: string;
  allowedRepositoryCount: number;
  message: string | null;
}

export interface GitHubRepositorySummary {
  owner: string;
  name: string;
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean;
  htmlUrl: string;
}

export interface GitHubWorkflowSummary {
  name: string;
  path: string;
  sha: string;
  htmlUrl: string;
}

export interface GitHubWorkflowFile {
  owner: string;
  repository: string;
  defaultBranch: string;
  path: string;
  sha: string;
  content: string;
  htmlUrl: string;
  retrievedAtUtc: string;
}

export interface GitHubAnalysisResponse {
  source: GitHubWorkflowFile;
  result: WorkflowAnalysisResult | WorkflowExplanationResult;
}

export interface RemediationChange {
  ruleId: string;
  title: string;
  severity: string;
  resolved: boolean;
  recommendation: string;
}

export interface RemediationReport {
  fileName: string;
  originalAnalysis: WorkflowAnalysisResult;
  proposedAnalysis: WorkflowAnalysisResult;
  changes: RemediationChange[];
  unifiedDiff: string[];
  originalRiskScore: number;
  proposedRiskScore: number;
  riskReductionPercent: number;
  patchValid: boolean;
  resolvedFindingCount: number;
  remainingFindingCount: number;
}
