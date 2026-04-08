"use client";

import { motion } from "framer-motion";
import {
  Upload, Shield, CheckCircle, Brain, Loader2, Sparkles, Info,
} from "lucide-react";
import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { useState, useEffect, useRef } from "react";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://134.199.201.243:7860";
const FULL_REPORT_PROMPT =
  "Analyze this CAPE sandbox report. Provide executive summary, ATT&CK technique mappings, behavioral indicators, IOCs, and threat assessment.";

export default function AnalyzePage() {
  const [dragActive, setDragActive] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [enableEnrichment, setEnrichment] = useState(false);
  const [streamingText, setStreamingText] = useState("");
  const [statusText, setStatusText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => () => { abortRef.current?.abort(); }, []);

  async function handleFile(file: File) {
    setError(null);
    setStreamingText("");
    setStatusText("Uploading...");
    setAnalyzing(true);
    abortRef.current = new AbortController();

    try {
      const form = new FormData();
      form.append("file", file);
      const uploadRes = await fetch(`${API_URL}/api/upload`, {
        method: "POST",
        body: form,
        signal: abortRef.current.signal,
      });
      if (!uploadRes.ok) throw new Error(`Upload failed: ${await uploadRes.text()}`);
      const { brief_id } = await uploadRes.json();
      await runAnalysis(brief_id);
    } catch (e: any) {
      if (e.name !== "AbortError") setError(e.message);
      setAnalyzing(false);
    }
  }

  async function runAnalysis(briefId: string) {
    setStatusText("Connecting...");
    setStreamingText("");

    try {
      const res = await fetch(`${API_URL}/api/analyze/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: FULL_REPORT_PROMPT,
          enable_enrichment: enableEnrichment,
          cape_task_id: briefId,
        }),
        signal: abortRef.current?.signal,
      });
      if (!res.ok) throw new Error(`Analysis failed: ${res.status}`);
      if (!res.body) throw new Error("No response body");

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

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
            if (ev.type === "status") setStatusText(ev.text);
            else if (ev.type === "chunk") setStreamingText((p) => p + ev.text);
            else if (ev.type === "done") { setAnalyzing(false); setStatusText(""); }
          } catch { /* ignore */ }
        }
      }
    } catch (e: any) {
      if (e.name !== "AbortError") setError(e.message);
    } finally {
      setAnalyzing(false);
    }
  }

  return (
    <div className="min-h-screen">
      <TopBar title="Analyze" />
      <div className="max-w-5xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">

          <FadeUp>
            <div>
              <h2 className="text-2xl font-bold text-[var(--text-primary)]">Malware Analysis</h2>
              <p className="text-sm text-[var(--text-muted)] mt-1">
                Upload a CAPE report or PE binary for AI-powered multi-expert analysis
              </p>
            </div>
          </FadeUp>

          {/* Enrichment toggle */}
          <FadeUp delay={0.05}>
            <div className="flex items-center gap-3 p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
              <button
                role="switch"
                aria-checked={enableEnrichment}
                onClick={() => setEnrichment((v) => !v)}
                className={cn(
                  "relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none",
                  enableEnrichment ? "bg-[var(--accent)]" : "bg-[var(--border)]"
                )}
              >
                <span className={cn(
                  "inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform",
                  enableEnrichment ? "translate-x-4" : "translate-x-1"
                )} />
              </button>
              <Sparkles className={cn("w-4 h-4", enableEnrichment ? "text-[var(--accent)]" : "text-[var(--text-muted)]")} />
              <span className={cn("text-sm font-medium", enableEnrichment ? "text-[var(--accent)]" : "text-[var(--text-secondary)]")}>
                Kimi Enrichment
              </span>
              <span className="text-xs text-[var(--text-muted)]">
                — live threat intel, IOC correlation &amp; ATT&amp;CK enrichment via Azure swarm
              </span>
              <div className="ml-auto group relative">
                <Info className="w-4 h-4 text-[var(--text-muted)] cursor-help" />
                <div className="absolute right-0 top-6 w-64 p-3 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)] text-xs text-[var(--text-secondary)] opacity-0 group-hover:opacity-100 transition-opacity z-10 pointer-events-none">
                  Runs 4 parallel Kimi-K2.5 agents for live threat intelligence, IOC reputation,
                  ATT&amp;CK sub-technique enrichment, and malware family context.
                  Adds ~60–100s to analysis time.
                </div>
              </div>
            </div>
          </FadeUp>

          {/* Drop zone */}
          <FadeUp delay={0.1}>
            <motion.label
              htmlFor="showcase-file-upload"
              className={cn(
                "relative border-2 border-dashed rounded-2xl p-16 text-center cursor-pointer transition-all duration-300 block",
                dragActive
                  ? "border-[var(--accent)] bg-[var(--accent-glow)]"
                  : "border-[var(--border)] bg-[var(--bg-card)] hover:border-[var(--border-accent)] hover:bg-[var(--bg-card-hover)]"
              )}
              onDragEnter={() => setDragActive(true)}
              onDragLeave={() => setDragActive(false)}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                setDragActive(false);
                const f = e.dataTransfer.files[0];
                if (f) handleFile(f);
              }}
              whileHover={{ scale: 1.005 }}
            >
              <input
                id="showcase-file-upload"
                type="file"
                className="sr-only"
                accept=".json,.exe,.dll,.sys"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
              />
              {analyzing ? (
                <div className="flex flex-col items-center gap-4">
                  <Loader2 className="w-12 h-12 text-[var(--accent)] animate-spin" />
                  <p className="text-[var(--accent)] font-medium">{statusText || "Analyzing..."}</p>
                  {enableEnrichment && (
                    <div className="flex gap-2 mt-2">
                      {["Fathom", "Swarm ×4", "Synthesis"].map((label, i) => (
                        <motion.span
                          key={label}
                          className="px-2 py-1 rounded text-xs bg-[var(--accent-glow)] text-[var(--accent)] border border-[var(--border-accent)]"
                          initial={{ opacity: 0, scale: 0.8 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ delay: 0.5 + i * 0.3 }}
                        >
                          {label}
                        </motion.span>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <>
                  <Upload className={cn("w-12 h-12 mx-auto mb-4", dragActive ? "text-[var(--accent)]" : "text-[var(--text-muted)]")} />
                  <p className="text-[var(--text-primary)] font-medium mb-1">
                    Drop a CAPE report (.json) or PE binary (.exe/.dll)
                  </p>
                  <p className="text-xs text-[var(--text-muted)]">Max 50 MB</p>
                </>
              )}
            </motion.label>
          </FadeUp>

          {error && (
            <FadeUp>
              <div className="p-4 rounded-xl border border-[var(--danger)]/30 bg-[var(--danger)]/5 text-sm text-[var(--danger)]">
                {error}
              </div>
            </FadeUp>
          )}

          {/* Streaming output */}
          {streamingText && (
            <FadeUp>
              <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Brain className="w-4 h-4 text-[var(--accent)]" />
                  <span className="text-sm font-semibold text-[var(--text-primary)]">Analysis Report</span>
                  {analyzing && <Loader2 className="w-3 h-3 text-[var(--accent)] animate-spin ml-auto" />}
                </div>
                <div className="prose prose-sm prose-invert max-w-none text-[var(--text-secondary)] text-sm leading-relaxed whitespace-pre-wrap font-mono">
                  {streamingText}
                  {analyzing && <span className="animate-pulse">▋</span>}
                </div>
              </div>
            </FadeUp>
          )}

          {/* Pipeline visualization */}
          <ScrollReveal>
            <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Analysis Pipeline</h3>
            <div className="flex items-center gap-3">
              {[
                { icon: <Upload className="w-4 h-4" />, label: "Upload", desc: "File ingestion" },
                { icon: <Brain className="w-4 h-4" />, label: "Route", desc: "Domain router" },
                { icon: <Shield className="w-4 h-4" />, label: "Fathom", desc: "Expert inference" },
                ...(enableEnrichment
                  ? [{ icon: <Sparkles className="w-4 h-4" />, label: "Swarm ×4", desc: "Kimi agents" }]
                  : []),
                { icon: <CheckCircle className="w-4 h-4" />, label: "Report", desc: "Final verdict" },
              ].map((step, i, arr) => (
                <div key={i} className="flex items-center gap-3 flex-1">
                  <motion.div
                    className="flex-1 p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] text-center"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 * i }}
                    whileHover={{ borderColor: "var(--accent)", y: -2 }}
                  >
                    <div className="text-[var(--accent)] flex justify-center mb-2">{step.icon}</div>
                    <p className="text-xs font-medium text-[var(--text-primary)]">{step.label}</p>
                    <p className="text-[10px] text-[var(--text-muted)]">{step.desc}</p>
                  </motion.div>
                  {i < arr.length - 1 && (
                    <motion.div
                      className="text-[var(--accent)]"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 0.4 }}
                      transition={{ delay: 0.3 + i * 0.1 }}
                    >
                      →
                    </motion.div>
                  )}
                </div>
              ))}
            </div>
          </ScrollReveal>

        </StaggerContainer>
      </div>
    </div>
  );
}
