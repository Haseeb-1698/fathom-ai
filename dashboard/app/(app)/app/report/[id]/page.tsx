"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { motion } from "framer-motion";
import {
  FileText, Download, Printer, Share2, Copy, ExternalLink,
  ShieldAlert, ShieldCheck, AlertTriangle, Clock, Hash,
  Brain, Crosshair, Radar, Activity, Network, Search,
  Target, Zap, Eye, BookOpen, Loader2, Sparkles,
} from "lucide-react";
import { cn, getSeverityColor, getVerdictColor } from "@/lib/utils";
import Link from "next/link";
import {
  loadAnalysis, loadReport, saveReport, generateStructuredReport,
  inferVerdict, extractFamily, formatFileSize,
  type StructuredReport, type IOC, type Technique, type ReportSection,
} from "@/lib/fathom-api";
import { ChatPanel } from "@/components/analysis/chat-panel";

// ── Icon map (string → component) ────────────────────────────────────────────
const ICON_MAP: Record<string, React.ElementType> = {
  BookOpen, Search, Activity, Network, Crosshair, Radar,
  Target, AlertTriangle, Brain, Eye, Zap,
};

// ── Section nav config ────────────────────────────────────────────────────────
const SECTION_ICONS: Record<string, React.ElementType> = {
  "executive-summary": BookOpen,
  "static-analysis": Search,
  "dynamic-analysis": Activity,
  "network-indicators": Network,
  "ioc-extraction": Crosshair,
  "mitre-mapping": Radar,
  "detection-rules": Target,
  "risk-assessment": AlertTriangle,
  "expert-consensus": Brain,
  "evidence-gaps": Eye,
  "remediation": Zap,
};

export default function ReportPage() {
  const params = useParams();
  const id = params?.id as string;

  const [report, setReport] = useState<StructuredReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState("executive-summary");
  const [capeContext, setCapeContext] = useState("");

  useEffect(() => {
    loadReportData();
  }, [id]);

  async function loadReportData() {
    setLoading(true);
    setError(null);

    // 1. Try cached report first
    const cached = loadReport();
    if (cached) {
      setReport(cached);
      setLoading(false);
      return;
    }

    // 2. Get analysis result from session
    const analysis = loadAnalysis();
    if (!analysis?.report) {
      setError("No analysis data found. Please upload and analyze a file first.");
      setLoading(false);
      return;
    }

    setCapeContext(analysis.report);

    // 3. Generate structured report from analysis text
    setGenerating(true);
    try {
      const { verdict, confidence } = inferVerdict(analysis.report);
      const family = extractFamily(analysis.report);

      const structured = await generateStructuredReport(
        analysis.report,
        {
          sha256: analysis.sha256,
          md5: analysis.md5,
          file_name: analysis.file_name,
          family,
        },
        analysis.kimi_enrichment_used,
      );

      // Merge with analysis metadata
      const full: StructuredReport = {
        ...structured,
        verdict: verdict,
        confidence: confidence,
        malwareFamily: structured.malwareFamily || family,
      };

      saveReport(full);
      setReport(full);
    } catch (e: any) {
      // Fallback: build report from analysis text directly
      const { verdict, confidence } = inferVerdict(analysis.report);
      const family = extractFamily(analysis.report);
      const fallback = buildFallbackReport(analysis.report, verdict, confidence, family);
      setReport(fallback);
    } finally {
      setGenerating(false);
      setLoading(false);
    }
  }

  if (loading || generating) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-48px)]">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 text-[var(--accent)] animate-spin" />
          <p className="text-sm text-[var(--text-muted)]">
            {generating ? "Generating structured report sections..." : "Loading report..."}
          </p>
          {generating && (
            <p className="text-xs text-[var(--text-muted)]">
              Kimi is analyzing each section from the evidence
            </p>
          )}
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-48px)]">
        <div className="text-center space-y-3">
          <AlertTriangle className="w-8 h-8 text-[var(--danger)] mx-auto" />
          <p className="text-sm text-[var(--danger)]">{error || "Report not available."}</p>
          <Link href="/app/upload" className="text-xs text-[var(--accent)] hover:underline">
            Upload a file to analyze
          </Link>
        </div>
      </div>
    );
  }

  const analysis = loadAnalysis();

  return (
    <div className="flex h-[calc(100vh-48px)]">
      {/* ── Left: Section Navigation ──────────────────── */}
      <nav className="w-56 flex-shrink-0 border-r border-[var(--border)] bg-[var(--bg-surface)] overflow-y-auto hidden lg:block">
        <div className="p-3 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-[var(--accent)]" />
            <span className="text-xs font-semibold text-[var(--text-secondary)]">Report Sections</span>
          </div>
        </div>
        <div className="py-1">
          {report.sections.map((section, i) => {
            const Icon = SECTION_ICONS[section.id] || FileText;
            return (
              <button
                key={section.id}
                onClick={() => {
                  setActiveSection(section.id);
                  document.getElementById(section.id)?.scrollIntoView({ behavior: "smooth" });
                }}
                className={cn(
                  "w-full flex items-center gap-2 px-3 py-2 text-left text-xs transition-colors cursor-pointer",
                  activeSection === section.id
                    ? "text-[var(--accent)] bg-[var(--accent-glow)] border-r-2 border-[var(--accent)]"
                    : "text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--bg-card)]"
                )}
              >
                <span className="text-[10px] text-[var(--text-muted)] font-mono w-4">
                  {(i + 1).toString().padStart(2, "0")}
                </span>
                <Icon className="w-3 h-3 flex-shrink-0" />
                <span className="truncate">{section.title}</span>
              </button>
            );
          })}
        </div>
      </nav>

      {/* ── Right: Report Content ─────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {/* Sticky header */}
        <div className="sticky top-0 z-10 flex items-center justify-between px-6 py-3 border-b border-[var(--border)] bg-[var(--bg-surface)]/95 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold uppercase"
              style={{
                backgroundColor: `${getVerdictColor(report.verdict)}15`,
                color: getVerdictColor(report.verdict),
                border: `1px solid ${getVerdictColor(report.verdict)}30`,
              }}
            >
              {report.verdict === "malicious"
                ? <ShieldAlert className="w-3.5 h-3.5" />
                : <ShieldCheck className="w-3.5 h-3.5" />}
              {report.verdict}
            </div>
            <span className="text-sm font-mono text-[var(--text-primary)]">
              {analysis?.file_name || "sample"}
            </span>
            <span className="text-xs text-[var(--text-muted)]">{report.malwareFamily}</span>
            {report.kimi_enrichment_used && (
              <div className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border border-blue-500/30 bg-blue-500/10 text-blue-400">
                <Sparkles className="w-3 h-3" />
                Kimi Enriched
              </div>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <ActionButton icon={Copy} label="Copy" onClick={() => navigator.clipboard.writeText(report.report_text)} />
            <ActionButton icon={Printer} label="Print" onClick={() => window.print()} />
            <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--accent)] text-[var(--bg-primary)] text-xs font-semibold hover:bg-[var(--accent-dim)] transition-colors cursor-pointer">
              <Download className="w-3.5 h-3.5" />
              PDF
            </button>
          </div>
        </div>

        {/* Meta bar */}
        <div className="px-6 py-4 border-b border-[var(--border)] bg-[var(--bg-card)]">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetaItem label="Risk Score" value={`${report.riskScore.toFixed(1)}/10`} color="var(--danger)" />
            <MetaItem label="Confidence" value={`${report.confidence}%`} color="var(--accent)" />
            <MetaItem label="IOCs Found" value={report.iocs.length.toString()} color="var(--warning)" />
            <MetaItem label="ATT&CK Techniques" value={report.techniques.length.toString()} color="var(--secondary)" />
          </div>
          <div className="flex items-center gap-4 mt-3 text-[10px] text-[var(--text-muted)]">
            {analysis?.sha256 && (
              <span className="flex items-center gap-1">
                <Hash className="w-3 h-3" />
                SHA256: <span className="font-mono">{analysis.sha256.slice(0, 24)}...</span>
              </span>
            )}
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {new Date(report.generated_at).toLocaleString()}
            </span>
          </div>
        </div>

        {/* Sections */}
        <div className="px-6 py-6 space-y-6 max-w-4xl print:max-w-none">
          {report.sections.map((section, i) => {
            const Icon = SECTION_ICONS[section.id] || FileText;
            return (
              <motion.section
                key={section.id}
                id={section.id}
                className="scroll-mt-20"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
              >
                <div className="flex items-center gap-2 mb-3">
                  <div className="p-1.5 rounded-lg bg-[var(--accent-glow)]">
                    <Icon className="w-4 h-4 text-[var(--accent)]" />
                  </div>
                  <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                    <span className="text-[var(--text-muted)] font-mono mr-2">
                      {(i + 1).toString().padStart(2, "0")}
                    </span>
                    {section.title}
                  </h2>
                </div>

                {section.iocTable ? (
                  <IOCTable iocs={report.iocs} />
                ) : section.mitreTable ? (
                  <MITRETable techniques={report.techniques} />
                ) : (
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-4">
                    <p className="text-xs text-[var(--text-secondary)] leading-relaxed whitespace-pre-line">
                      {section.content || "No data available for this section."}
                    </p>
                  </div>
                )}
              </motion.section>
            );
          })}

          {/* Raw report text (collapsible) */}
          <details className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
            <summary className="px-4 py-3 text-xs font-semibold text-[var(--text-secondary)] cursor-pointer hover:bg-[var(--bg-elevated)] transition-colors">
              Raw Analysis Report (full text)
            </summary>
            <div className="px-4 pb-4">
              <pre className="text-[10px] text-[var(--text-muted)] leading-relaxed whitespace-pre-wrap font-mono overflow-x-auto">
                {report.report_text}
              </pre>
            </div>
          </details>
        </div>
      </div>

      {/* Chat panel */}
      <ChatPanel capeContext={capeContext} sessionId={id} />
    </div>
  );
}

// ── Fallback report builder (when API call fails) ─────────────────────────────

function buildFallbackReport(
  text: string,
  verdict: StructuredReport["verdict"],
  confidence: number,
  family: string,
): StructuredReport {
  const riskScore = verdict === "malicious" ? 8.5 : verdict === "suspicious" ? 5.0 : 2.0;

  // Split by ## headers
  const sectionMap: Record<string, string> = {};
  let current = "";
  let currentKey = "";
  for (const line of text.split("\n")) {
    if (line.startsWith("## ")) {
      if (currentKey) sectionMap[currentKey] = current.trim();
      currentKey = line.slice(3).trim().toLowerCase();
      current = "";
    } else {
      current += line + "\n";
    }
  }
  if (currentKey) sectionMap[currentKey] = current.trim();

  const get = (key: string) =>
    sectionMap[key] || sectionMap[Object.keys(sectionMap).find((k) => k.includes(key)) || ""] || "";

  const sections: ReportSection[] = [
    { id: "executive-summary", title: "Executive Summary", icon: "BookOpen", content: get("executive") || text.slice(0, 600) },
    { id: "static-analysis", title: "Static Analysis", icon: "Search", content: get("static") },
    { id: "dynamic-analysis", title: "Dynamic Behavior", icon: "Activity", content: get("behavioral") || get("dynamic") },
    { id: "network-indicators", title: "Network Indicators", icon: "Network", content: get("network") || get("ioc") },
    { id: "ioc-extraction", title: "IOC Extraction", icon: "Crosshair", iocTable: true },
    { id: "mitre-mapping", title: "MITRE ATT&CK Mapping", icon: "Radar", mitreTable: true },
    { id: "risk-assessment", title: "Risk Assessment", icon: "AlertTriangle", content: get("threat") || get("risk") },
    { id: "remediation", title: "Remediation Steps", icon: "Zap", content: get("remediation") },
  ].filter((s) => s.iocTable || s.mitreTable || (s.content && s.content.length > 10));

  // Extract techniques and IOCs from text
  const techIds = [...new Set(text.match(/T\d{4}(?:\.\d{3})?/g) || [])];
  const techniques: Technique[] = techIds.slice(0, 10).map((id) => ({
    id, name: id, tactic: "Unknown", severity: "medium",
  }));

  const ipMatches = text.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [];
  const domainMatches = text.match(/\b(?:[a-z0-9\-]+\.)+(?:xyz|com|net|org|io|ru|cn)\b/gi) || [];
  const iocs: IOC[] = [
    ...ipMatches.filter((ip) => !ip.startsWith("192.168") && !ip.startsWith("10.")).slice(0, 5).map((v) => ({ type: "ip", value: v, severity: "high" as const })),
    ...domainMatches.slice(0, 5).map((v) => ({ type: "domain", value: v.toLowerCase(), severity: "high" as const })),
  ];

  return {
    verdict, confidence, riskScore, malwareFamily: family,
    sections, iocs, techniques,
    report_text: text,
    kimi_enrichment_used: false,
    generated_at: new Date().toISOString(),
  };
}

// ── Sub-components ────────────────────────────────────────────────────────────

function IOCTable({ iocs }: { iocs: IOC[] }) {
  if (!iocs.length) return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-4 text-xs text-[var(--text-muted)]">
      No IOCs extracted from this sample.
    </div>
  );
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[var(--border)] bg-[var(--bg-surface)]">
            {["Type", "Value", "Severity"].map((h) => (
              <th key={h} className="text-left py-2 px-3 text-[var(--text-muted)] font-medium uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={i} className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-elevated)] transition-colors">
              <td className="py-2 px-3">
                <span className="px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-secondary)] font-mono text-[10px] uppercase">{ioc.type}</span>
              </td>
              <td className="py-2 px-3 font-mono text-[var(--text-primary)] break-all">{ioc.value}</td>
              <td className="py-2 px-3">
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                  style={{ backgroundColor: `${getSeverityColor(ioc.severity)}15`, color: getSeverityColor(ioc.severity) }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: getSeverityColor(ioc.severity) }} />
                  {ioc.severity}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MITRETable({ techniques }: { techniques: Technique[] }) {
  if (!techniques.length) return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-4 text-xs text-[var(--text-muted)]">
      No ATT&CK techniques mapped for this sample.
    </div>
  );
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[var(--border)] bg-[var(--bg-surface)]">
            {["ID", "Technique", "Tactic", "Severity", "Ref"].map((h) => (
              <th key={h} className={cn("py-2 px-3 text-[var(--text-muted)] font-medium uppercase tracking-wider", h === "Ref" ? "text-right" : "text-left")}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {techniques.map((tech, i) => (
            <tr key={i} className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-elevated)] transition-colors">
              <td className="py-2 px-3 font-mono font-bold text-[var(--accent)]">{tech.id}</td>
              <td className="py-2 px-3 text-[var(--text-primary)]">{tech.name}</td>
              <td className="py-2 px-3">
                <span className="px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-secondary)] text-[10px]">{tech.tactic}</span>
              </td>
              <td className="py-2 px-3">
                <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                  style={{ backgroundColor: `${getSeverityColor(tech.severity)}15`, color: getSeverityColor(tech.severity) }}>
                  {tech.severity}
                </span>
              </td>
              <td className="py-2 px-3 text-right">
                <a href={`https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}`}
                  target="_blank" rel="noopener noreferrer"
                  className="text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors cursor-pointer">
                  <ExternalLink className="w-3 h-3 inline" />
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MetaItem({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div>
      <p className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mb-0.5">{label}</p>
      <p className="text-lg font-bold" style={{ color }}>{value}</p>
    </div>
  );
}

function ActionButton({ icon: Icon, label, onClick }: { icon: React.ElementType; label: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} title={label}
      className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--bg-card)] transition-colors cursor-pointer">
      <Icon className="w-3.5 h-3.5" />
    </button>
  );
}
