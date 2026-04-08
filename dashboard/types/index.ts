// ── Fathom Dashboard Types ────────────────────────────────────

export interface Expert {
  id: string;
  name: string;
  domain: string;
  description: string;
  icon: string;
  color: string;
  status: "trained" | "training" | "pending" | "failed";
  datasetRows: number;
  datasetFile: string;
  accuracy?: number;
  lossHistory?: number[];
  adapter?: string;
}

export interface Dataset {
  id: string;
  name: string;
  file: string;
  rows: number;
  size: string;
  location: "processed" | "experts";
  expertId?: string;
  status: "ready" | "downloading" | "pending" | "error";
  source: string;
  description: string;
}

export interface AnalysisResult {
  id: string;
  fileName: string;
  fileHash: string;
  timestamp: string;
  verdict: "malicious" | "suspicious" | "benign" | "unknown";
  confidence: number;
  expertResults: ExpertResult[];
  routerDecision: RouterDecision;
  ragContext: RAGContext[];
  graphNodes?: GraphNode[];
}

export interface ExpertResult {
  expertId: string;
  expertName: string;
  analysis: string;
  confidence: number;
  indicators: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
}

export interface RouterDecision {
  selectedExperts: string[];
  reasoning: string;
  domainScores: Record<string, number>;
}

export interface RAGContext {
  source: string;
  relevance: number;
  content: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "file" | "behavior" | "ioc" | "technique" | "actor" | "campaign";
  properties: Record<string, string>;
}

export interface GraphEdge {
  source: string;
  target: string;
  label: string;
  weight: number;
}

export interface TrainingRun {
  id: string;
  expertId: string;
  status: "queued" | "running" | "completed" | "failed";
  progress: number;
  currentStep: number;
  totalSteps: number;
  loss: number;
  learningRate: number;
  startedAt?: string;
  completedAt?: string;
  gpu: string;
  checkpoint?: string;
}

export interface SystemStats {
  totalAnalyses: number;
  totalExperts: number;
  trainedExperts: number;
  totalDatasetRows: number;
  avgConfidence: number;
  ragIndexSize: number;
  graphNodes: number;
}

export interface NavItem {
  label: string;
  href: string;
  icon: string;
  badge?: string;
}
