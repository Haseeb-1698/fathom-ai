"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import {
  ShieldAlert, ShieldCheck, Brain, Database, Network, Activity,
  AlertTriangle, CheckCircle2, Hash, FileText, ChevronRight,
  ExternalLink, Copy, Crosshair, Layers, Radar, Sparkles, Loader2,
  GitCompare, Shield,
} from "lucide-react";
import { cn, getSeverityColor, getVerdictColor } from "@/lib/utils";
import Link from "next/link";
import { ChatPanel } from "@/components/analysis/chat-panel";
import { saveAnalysis, loadUpload, inferVerdict, extractFamily, formatFileSize, API_URL, parseSimilarFromReport, parseIocReputationFromReport } from "@/lib/fathom-api";

const FULL_REPORT_PROMPT =
  "Analyze this CAPE sandbox report. Provide executive summary, ATT&CK technique mappings, behavioral indicators, IOCs, and threat assessment.";

interface AnalysisData {
  id: string;
  fileName: string;
  fileHash: string;
  fileSize: string;
  fileType: string;
  verdict: "malicious" | "suspicious" | "benign";
  confidence: number;
  timestamp: string;
  kimi_enrichment_used: boolean;
  enrichment_gaps_filled: string[];
  report: string;
  routing: { domain_id: string; domain_name: string; confidence: number; scores: Record<string, number>; adapter: string };
  warnings: string[];
  graph_id: string | null;
}

type Tab = "overview" | "report" | "evidence" | "rag";

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: "overview", label: "Overview", icon: Layers },
  { id: "report", label: "Analysis Report", icon: Brain },
  { id: "evidence", label: "Evidence", icon: Crosshair },
  { id: "rag", label: "RAG Context", icon: Database },
];

export default function AnalysisPage() {
  const params = useParams();
  const id = params?.id as string;
  const [activeTab, setActiveTab] = useState<Tab>("report");
  const [data, setData] = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [streamingReport, setStreamingReport] = useState("");
  const [streaming, setStreaming] = useState(false);

  useEffect(() => {
    if (!id || id === "new") { setLoading(false); return; }
    runAnalysis();
  }, [id]);

  async function runAnalysis() {
    setLoading(true);
    setError(null);

    const uploadMeta = loadUpload();
    if (!uploadMeta?.brief_id) {
      setError("No upload data found. Please upload a file first.");
      setLoading(false);
      return;
    }

    setStreaming(true);
    setStreamingReport("");

    try {
      const res = await fetch(`${API_URL}/api/analyze/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: FULL_REPORT_PROMPT,
          enable_enrichment: false,
          cape_task_id: uploadMeta.brief_id,
        }),
      });

      if (!res.ok) throw new Error(`Analysis failed: ${res.status}`);
      if (!res.body) throw new Error("No response body");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      let fullReport = "";
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
            if (ev.type === "chunk") { fullReport += ev.text; setStreamingReport(p => p + ev.text); }
            else if (ev.type === "done") { graphId = ev.text?.graph_id || null; }
          } catch { /* ignore */ }
        }
      }

      const { verdict, confidence } = inferVerdict(fullReport);
      const analysisData: AnalysisData = {
        id: uploadMeta.brief_id,
        fileName: uploadMeta.file_name || "unknown",
        fileHash: uploadMeta.sha256 || "",
        fileSize: formatFileSize(uploadMeta.file_size || 0),
        fileType: uploadMeta.file_type === "cape_report" ? "CAPE Report" : "PE Binary",
        verdict, confidence,
        timestamp: new Date().toISOString(),
        kimi_enrichment_used: false,
        enrichment_gaps_filled: [],
        report: fullReport,
        routing: { domain_id: "—", domain_name: "—", confidence: 0, scores: {}, adapter: "—" },
        warnings: [],
        graph_id: graphId,
      };

      setData(analysisData);

      // Save to sessionStorage for report page
      saveAnalysis({
        brief_id: uploadMeta.brief_id,
        file_name: uploadMeta.file_name || "unknown",
        file_size: formatFileSize(uploadMeta.file_size || 0),
        file_type: uploadMeta.file_type === "cape_report" ? "CAPE Report" : "PE Binary",
        sha256: uploadMeta.sha256 || "",
        md5: uploadMeta.md5 || "",
        verdict, confidence,
        report: fullReport,
        routing: { domain_id: "—", domain_name: "—", confidence: 0, scores: {}, adapter: "—" },
        warnings: [],
        graph_id: graphId,
        kimi_enrichment_used: false,
        enrichment_gaps_filled: [],
        synthesis_model: "",
        analyzed_at: new Date().toISOString(),
      });

      // Store graph_id for graph page
      if (graphId) {
        sessionStorage.setItem("fathom_last_analysis", JSON.stringify({ graph_id: graphId }));
      }

    } catch (e: any) {
      setError(e.message);
    } finally {
      setStreaming(false);
      setLoading(false);
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-[calc(100vh-48px)]">
      <div className="flex flex-col items-center gap-3">
        <Loader2 className="w-8 h-8 text-[var(--accent)] animate-spin" />
        <p className="text-sm text-[var(--text-muted)]">Running analysis pipeline...</p>
      </div>
    </div>
  );

  if (error) return (
    <div className="flex items-center justify-center h-[calc(100vh-48px)]">
      <div className="text-center space-y-3">
        <AlertTriangle className="w-8 h-8 text-[var(--danger)] mx-auto" />
        <p className="text-sm text-[var(--danger)]">{error}</p>
        <Link href="/app/upload" className="text-xs text-[var(--accent)] hover:underline">Upload a file</Link>
      </div>
    </div>
  );

  if (!data) return (
    <div className="flex items-center justify-center h-[calc(100vh-48px)]">
      <div className="text-center space-y-3">
        <p className="text-sm text-[var(--text-muted)]">No analysis data.</p>
        <Link href="/app/upload" className="text-xs text-[var(--accent)] hover:underline">Upload a file</Link>
      </div>
    </div>
  );

  return (
    <div className="flex flex-col h-[calc(100vh-48px)]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[var(--border)] bg-[var(--bg-surface)]">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold uppercase"
            style={{ backgroundColor: `${getVerdictColor(data.verdict)}15`, color: getVerdictColor(data.verdict), border: `1px solid ${getVerdictColor(data.verdict)}30` }}>
            {data.verdict === "malicious" ? <ShieldAlert className="w-3.5 h-3.5" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            {data.verdict}
            <span className="ml-1 opacity-70">{data.confidence}%</span>
          </div>
          {data.kimi_enrichment_used && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border border-blue-500/30 bg-blue-500/10 text-blue-400">
              <Sparkles className="w-3 h-3" /> Kimi Enriched
            </div>
          )}
          <div className="h-4 w-px bg-[var(--border)]" />
          <span className="text-sm font-mono text-[var(--text-primary)]">{data.fileName}</span>
          <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-muted)] font-mono">{data.fileType}</span>
        </div>
        <div className="flex items-center gap-2">
          {streaming && <Loader2 className="w-3.5 h-3.5 text-[var(--accent)] animate-spin" />}
          <Link href={`/app/report/${data.id}`} className="flex items-center gap-1 text-xs text-[var(--accent)] hover:text-[var(--accent-dim)] transition-colors">
            <FileText className="w-3 h-3" /> Full Report <ChevronRight className="w-3 h-3" />
          </Link>
          {data.graph_id && (
            <Link href="/app/graph" className="flex items-center gap-1 text-xs text-[var(--secondary)] hover:opacity-80 transition-colors">
              <Network className="w-3 h-3" /> Graph <ChevronRight className="w-3 h-3" />
            </Link>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center px-4 border-b border-[var(--border)] bg-[var(--bg-surface)]/50">
        {TABS.map((tab) => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)}
            className={cn("relative px-4 py-2.5 text-xs font-medium transition-colors cursor-pointer",
              activeTab === tab.id ? "text-[var(--accent)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]")}>
            <span className="flex items-center gap-1.5">
              <tab.icon className="w-3.5 h-3.5" />{tab.label}
            </span>
            {activeTab === tab.id && (
              <motion.div className="absolute bottom-0 left-0 right-0 h-[2px] bg-[var(--accent)]" layoutId="analysisTab" />
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === "overview" && <OverviewTab data={data} />}
        {activeTab === "report" && (
          <div className="max-w-4xl">
            <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-6">
              <div className="text-[var(--text-secondary)] text-sm leading-relaxed whitespace-pre-wrap font-mono">
                {streamingReport || data.report}
                {streaming && <span className="animate-pulse">▋</span>}
              </div>
            </div>
          </div>
        )}
        {activeTab === "evidence" && <EvidenceTab report={data.report} />}
        {activeTab === "rag" && (
          <p className="text-xs text-[var(--text-muted)] p-2">RAG context is embedded in the analysis report above.</p>
        )}
      </div>

      <ChatPanel capeContext={data.report} sessionId={data.id} sampleSha256={data.fileHash} />
    </div>
  );
}

function OverviewTab({ data }: { data: AnalysisData }) {
  const similarLines = parseSimilarFromReport(data.report);
  const iocRepLines = parseIocReputationFromReport(data.report);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2 space-y-4">
        {/* Domain Routing */}
        <Panel title="Domain Routing" icon={Activity}>
          {Object.keys(data.routing.scores).length > 0 ? (
            <div className="space-y-1.5">
              {Object.entries(data.routing.scores).sort(([, a], [, b]) => b - a).map(([domain, score]) => (
                <div key={domain} className="flex items-center gap-2">
                  <span className={cn("text-[10px] font-mono w-20 text-right",
                    domain === data.routing.domain_id ? "text-[var(--accent)] font-bold" : "text-[var(--text-muted)]")}>
                    {domain}
                  </span>
                  <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-elevated)] overflow-hidden">
                    <motion.div className="h-full rounded-full"
                      style={{ backgroundColor: domain === data.routing.domain_id ? "var(--accent)" : "var(--text-muted)", opacity: domain === data.routing.domain_id ? 1 : 0.3 }}
                      initial={{ width: 0 }} animate={{ width: `${score * 100}%` }} transition={{ duration: 0.6 }} />
                  </div>
                  <span className="text-[10px] font-mono w-8 text-[var(--text-muted)]">{(score * 100).toFixed(0)}%</span>
                  {domain === data.routing.domain_id && <CheckCircle2 className="w-3 h-3 text-[var(--accent)]" />}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[var(--text-muted)]">Routing data available after analysis completes.</p>
          )}
        </Panel>

        {/* Similar Samples (from FAISS + Neo4j cross-sample correlation) */}
        {similarLines.length > 0 && (
          <Panel title="Similar Samples" icon={GitCompare}>
            <div className="space-y-2">
              {similarLines.map((line, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)]">
                  <GitCompare className="w-3.5 h-3.5 text-[var(--secondary)] mt-0.5 flex-shrink-0" />
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed font-mono">{line}</p>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {/* IOC Reputation (from Neo4j) */}
        {iocRepLines.length > 0 && (
          <Panel title="IOC Reputation (Graph)" icon={Shield}>
            <div className="space-y-1.5">
              {iocRepLines.map((line, i) => (
                <div key={i} className="flex items-center gap-2 text-xs font-mono">
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--danger)] flex-shrink-0" />
                  <span className="text-[var(--text-secondary)]">{line}</span>
                </div>
              ))}
            </div>
          </Panel>
        )}

        {/* Warnings */}
        {data.warnings.length > 0 && (
          <Panel title="Warnings" icon={AlertTriangle}>
            <div className="space-y-1.5">
              {data.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 p-2 rounded-lg bg-[var(--warning)]/5 border border-[var(--warning)]/10">
                  <AlertTriangle className="w-3.5 h-3.5 text-[var(--warning)] mt-0.5 flex-shrink-0" />
                  <p className="text-xs text-[var(--text-secondary)]">{w}</p>
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>

      <div className="space-y-4">
        {/* Kimi Enrichment */}
        {data.kimi_enrichment_used && (
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/5">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-blue-500/20">
              <Sparkles className="w-3.5 h-3.5 text-blue-400" />
              <h3 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Kimi Enrichment</h3>
            </div>
            <div className="p-4 flex flex-wrap gap-1.5">
              {data.enrichment_gaps_filled.map((gap) => (
                <span key={gap} className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/15 text-blue-300 border border-blue-500/20">
                  {gap.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* File Details */}
        <Panel title="File Details" icon={Hash}>
          <div className="space-y-2">
            <DetailRow label="Name" value={data.fileName} mono />
            <DetailRow label="Type" value={data.fileType} />
            <DetailRow label="Size" value={data.fileSize} />
            {data.fileHash && <DetailRow label="SHA256" value={data.fileHash.slice(0, 16) + "..."} mono copyable={data.fileHash} />}
            <DetailRow label="Analyzed" value={new Date(data.timestamp).toLocaleString()} />
          </div>
        </Panel>
      </div>
    </div>
  );
}

function EvidenceTab({ report }: { report: string }) {
  const techIds = [...new Set([...(report.matchAll(/T\d{4}(?:\.\d{3})?/g))].map(m => m[0]))];
  const ips = [...new Set([...(report.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g))].map(m => m[0]).filter(ip => !ip.startsWith("192.168") && !ip.startsWith("10.")))];
  const domains = [...new Set([...(report.matchAll(/\b(?:[a-z0-9\-]+\.)+(?:xyz|com|net|org|io|ru|cn)\b/gi))].map(m => m[0].toLowerCase()))];

  return (
    <div className="space-y-4 max-w-4xl">
      <Panel title="ATT&CK Techniques" icon={Radar}>
        {techIds.length > 0 ? (
          <div className="flex flex-wrap gap-2">
            {techIds.map(tid => (
              <a key={tid} href={`https://attack.mitre.org/techniques/${tid.replace(".", "/")}`}
                target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[var(--accent-glow)] border border-[var(--border-accent)] text-xs font-mono font-bold text-[var(--accent)] hover:border-[var(--accent)] transition-colors">
                {tid} <ExternalLink className="w-3 h-3 opacity-60" />
              </a>
            ))}
          </div>
        ) : <p className="text-xs text-[var(--text-muted)]">No ATT&CK IDs found yet.</p>}
      </Panel>
      {(ips.length > 0 || domains.length > 0) && (
        <Panel title="Extracted IOCs" icon={Crosshair}>
          <div className="space-y-1.5">
            {ips.slice(0, 10).map(ip => (
              <div key={ip} className="flex items-center gap-2 text-xs font-mono">
                <span className="px-1.5 py-0.5 rounded bg-[var(--danger)]/10 text-[var(--danger)] text-[10px]">IP</span>
                <span className="text-[var(--text-secondary)]">{ip}</span>
                <button onClick={() => navigator.clipboard.writeText(ip)} className="ml-auto p-0.5 text-[var(--text-muted)] hover:text-[var(--accent)] cursor-pointer"><Copy className="w-3 h-3" /></button>
              </div>
            ))}
            {domains.slice(0, 10).map(d => (
              <div key={d} className="flex items-center gap-2 text-xs font-mono">
                <span className="px-1.5 py-0.5 rounded bg-[var(--warning)]/10 text-[var(--warning)] text-[10px]">DOM</span>
                <span className="text-[var(--text-secondary)]">{d}</span>
                <button onClick={() => navigator.clipboard.writeText(d)} className="ml-auto p-0.5 text-[var(--text-muted)] hover:text-[var(--accent)] cursor-pointer"><Copy className="w-3 h-3" /></button>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function Panel({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[var(--border)]">
        <Icon className="w-3.5 h-3.5 text-[var(--text-muted)]" />
        <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider">{title}</h3>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function DetailRow({ label, value, mono, copyable }: { label: string; value: string; mono?: boolean; copyable?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">{label}</span>
      <div className="flex items-center gap-1">
        <span className={cn("text-xs text-[var(--text-secondary)]", mono && "font-mono")}>{value}</span>
        {copyable && (
          <button onClick={() => navigator.clipboard.writeText(copyable)} className="p-0.5 rounded hover:bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors cursor-pointer">
            <Copy className="w-3 h-3" />
          </button>
        )}
      </div>
    </div>
  );
}
