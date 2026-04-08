/**
 * fathom-api.ts — Typed API client for the Fathom backend.
 *
 * All pages import from here. sessionStorage is used to pass analysis
 * results between pages without redundant API calls.
 */

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://134.199.201.243:7860";

// ── Storage keys ─────────────────────────────────────────────────────────────

const KEYS = {
  upload: "fathom_upload",
  analysis: "fathom_analysis",
  report: "fathom_report",
} as const;

// ── Types ─────────────────────────────────────────────────────────────────────

export interface UploadResult {
  brief_id: string;
  sha256: string;
  md5?: string;
  file_type: "cape_report" | "pe_binary";
  file_name: string;
  file_size: number;
  ioc_count: number;
  behavior_count: number;
}

export interface AnalysisResult {
  brief_id: string;
  file_name: string;
  file_size: string;
  file_type: string;
  sha256: string;
  md5: string;
  verdict: "malicious" | "suspicious" | "benign";
  confidence: number;
  report: string;           // full markdown report text
  routing: {
    domain_id: string;
    domain_name: string;
    confidence: number;
    scores: Record<string, number>;
    adapter: string;
  };
  warnings: string[];
  graph_id: string | null;
  kimi_enrichment_used: boolean;
  enrichment_gaps_filled: string[];
  synthesis_model: string;
  analyzed_at: string;
}

export interface ReportSection {
  id: string;
  title: string;
  icon: string;
  content?: string;
  iocTable?: boolean;
  mitreTable?: boolean;
}

export interface IOC {
  type: string;
  value: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface StructuredReport {
  verdict: "malicious" | "suspicious" | "benign";
  confidence: number;
  riskScore: number;
  malwareFamily: string;
  sections: ReportSection[];
  iocs: IOC[];
  techniques: Technique[];
  report_text: string;
  kimi_enrichment_used: boolean;
  generated_at: string;
}

// ── sessionStorage helpers ────────────────────────────────────────────────────

export function saveUpload(data: UploadResult) {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(KEYS.upload, JSON.stringify(data));
}

export function loadUpload(): UploadResult | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(KEYS.upload);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export function saveAnalysis(data: AnalysisResult) {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(KEYS.analysis, JSON.stringify(data));
}

export function loadAnalysis(): AnalysisResult | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(KEYS.analysis);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export function saveReport(data: StructuredReport) {
  if (typeof window === "undefined") return;
  sessionStorage.setItem(KEYS.report, JSON.stringify(data));
}

export function loadReport(): StructuredReport | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = sessionStorage.getItem(KEYS.report);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

export function clearSession() {
  if (typeof window === "undefined") return;
  Object.values(KEYS).forEach((k) => sessionStorage.removeItem(k));
}

// ── API calls ─────────────────────────────────────────────────────────────────

/** Upload a CAPE JSON or PE binary. Returns UploadResult. */
export async function uploadFile(file: File): Promise<UploadResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_URL}/api/upload`, { method: "POST", body: form });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(`Upload failed (${res.status}): ${msg}`);
  }
  const data = await res.json();
  return {
    brief_id: data.brief_id,
    sha256: data.sha256 || "",
    md5: data.md5 || "",
    file_type: data.file_type,
    file_name: file.name,
    file_size: file.size,
    ioc_count: data.ioc_count,
    behavior_count: data.behavior_count,
  };
}

/**
 * Stream analysis from the backend.
 * Calls onChunk for each text chunk, onStatus for status updates.
 * Returns the full AnalysisResult when done.
 */
export async function streamAnalysis(
  briefId: string,
  enableEnrichment: boolean,
  onStatus: (s: string) => void,
  onChunk: (text: string) => void,
): Promise<Partial<AnalysisResult>> {
  const FULL_PROMPT =
    "Analyze this CAPE sandbox report. Provide executive summary, ATT&CK technique mappings, behavioral indicators, IOCs, and threat assessment.";

  const res = await fetch(`${API_URL}/api/analyze/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: FULL_PROMPT,
      enable_enrichment: enableEnrichment,
      cape_task_id: briefId,
    }),
  });

  if (!res.ok) throw new Error(`Analysis failed: ${res.status}`);
  if (!res.body) throw new Error("No response body");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let fullText = "";
  let graphId: string | null = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      try {
        const ev = JSON.parse(line.slice(6));
        if (ev.type === "status") onStatus(ev.text);
        else if (ev.type === "chunk") { fullText += ev.text; onChunk(ev.text); }
        else if (ev.type === "done") {
          if (ev.text?.graph_id) graphId = ev.text.graph_id;
        }
      } catch { /* ignore */ }
    }
  }

  return { report: fullText, graph_id: graphId };
}

/**
 * Generate a fully structured report from the analysis text.
 * Uses the backend report_generator which calls Kimi for each section.
 */
export async function generateStructuredReport(
  analysisText: string,
  sampleMeta: {
    sha256?: string; md5?: string; file_name?: string;
    family?: string; score?: number;
  },
  enableEnrichment: boolean,
): Promise<StructuredReport> {
  const res = await fetch(`${API_URL}/api/report/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: analysisText.slice(0, 500) || "Generate structured report",
      enable_enrichment: enableEnrichment,
      cape_task_id: "",
    }),
  });
  if (!res.ok) throw new Error(`Report generation failed: ${res.status}`);
  return res.json();
}

/** Fetch graph data for a sample hash. */
export async function fetchGraphData(sampleHash: string) {
  const res = await fetch(`${API_URL}/api/graph`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query_name: "sample_graph", sample_hash: sampleHash }),
  });
  if (!res.ok) return { nodes: [], edges: [] };
  return res.json();
}

/** Infer verdict + confidence from report text. */
export function inferVerdict(text: string): { verdict: AnalysisResult["verdict"]; confidence: number } {
  const t = text.toLowerCase();
  if (t.includes("malicious") || t.includes("malware") || t.includes("trojan") ||
      t.includes("ransomware") || t.includes("stealer") || t.includes("backdoor")) {
    const scoreMatch = text.match(/(?:risk score|score)[:\s]+(\d+(?:\.\d+)?)\s*\/\s*(?:10|100)/i);
    const raw = scoreMatch ? parseFloat(scoreMatch[1]) : 8.5;
    const score = raw > 10 ? raw : raw * 10;
    return { verdict: "malicious", confidence: Math.min(99, Math.round(score)) };
  }
  if (t.includes("suspicious") || t.includes("potentially")) {
    return { verdict: "suspicious", confidence: 65 };
  }
  return { verdict: "benign", confidence: 90 };
}

/** Extract family name from report text. */
export function extractFamily(text: string): string {
  const families = [
    "Emotet", "Cobalt Strike", "Vidar", "Amadey", "Formbook", "Redline",
    "AgentTesla", "Lokibot", "NjRAT", "AsyncRAT", "Remcos", "Raccoon",
    "DridexV4", "Dridex", "LockBit", "BlackCat", "Ryuk", "Conti",
    "IcedID", "QakBot", "BazarLoader", "TrickBot",
  ];
  for (const f of families) {
    if (text.toLowerCase().includes(f.toLowerCase())) return f;
  }
  return "Unknown";
}

/** Format file size bytes to human-readable string. */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// ── New feature helpers ───────────────────────────────────────────────────────

export interface SimilarSample {
  sha256: string;
  file_name: string;
  family: string;
  malscore: number;
  similarity: number;
  shared_techniques: string[];
  shared_iocs: string[];
}

/** Fetch cross-sample similarity results for a given SHA256. */
export async function fetchSimilarSamples(sha256: string): Promise<SimilarSample[]> {
  try {
    const res = await fetch(`${API_URL}/api/similar/${sha256}`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.similar || [];
  } catch {
    return [];
  }
}

/**
 * Parse "=== SIMILAR SAMPLES ===" and "=== RELATED SAMPLES ===" sections
 * injected by the backend into the report text.
 */
export function parseSimilarFromReport(reportText: string): string[] {
  const lines: string[] = [];
  let inSection = false;
  for (const line of reportText.split("\n")) {
    if (line.includes("SIMILAR SAMPLES") || line.includes("RELATED SAMPLES")) {
      inSection = true;
      continue;
    }
    if (inSection) {
      if (line.startsWith("===") || line.trim() === "") {
        if (line.startsWith("===")) inSection = false;
        continue;
      }
      if (line.startsWith("•")) lines.push(line.slice(1).trim());
    }
  }
  return lines;
}

/**
 * Parse "=== IOC REPUTATION ===" section from report text.
 */
export function parseIocReputationFromReport(reportText: string): string[] {
  const lines: string[] = [];
  let inSection = false;
  for (const line of reportText.split("\n")) {
    if (line.includes("IOC REPUTATION")) { inSection = true; continue; }
    if (inSection) {
      if (line.startsWith("===") || line.trim() === "") { if (line.startsWith("===")) inSection = false; continue; }
      if (line.startsWith("•")) lines.push(line.slice(1).trim());
    }
  }
  return lines;
}
