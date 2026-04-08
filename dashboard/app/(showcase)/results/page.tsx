"use client";

import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { motion } from "framer-motion";
import { BarChart3, TrendingUp, AlertTriangle, Shield, Target } from "lucide-react";

export default function ResultsPage() {
  return (
    <div className="min-h-screen">
      <TopBar title="Results & Evaluation" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">
          <FadeUp>
            <h2 className="text-2xl font-bold text-[var(--text-primary)]">Evaluation Results</h2>
            <p className="text-sm text-[var(--text-muted)] mt-1">
              promptfoo benchmarks, accuracy metrics, and red-teaming results
            </p>
          </FadeUp>

          {/* Metric Cards */}
          <FadeUp delay={0.1}>
            <div className="grid grid-cols-4 gap-4">
              {[
                { label: "Overall Accuracy", value: "—", icon: <Target className="w-5 h-5" />, color: "var(--accent)", desc: "Awaiting training" },
                { label: "Avg Confidence", value: "—", icon: <TrendingUp className="w-5 h-5" />, color: "var(--secondary)", desc: "Per-expert average" },
                { label: "Red Team Pass", value: "—", icon: <Shield className="w-5 h-5" />, color: "#3B82F6", desc: "Jailbreak resistance" },
                { label: "Hallucination Rate", value: "—", icon: <AlertTriangle className="w-5 h-5" />, color: "#F59E0B", desc: "RAG grounding check" },
              ].map((m, i) => (
                <motion.div
                  key={i}
                  className="p-5 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.08 * i }}
                >
                  <div className="flex items-center gap-2 mb-3" style={{ color: m.color }}>{m.icon}</div>
                  <p className="text-2xl font-bold text-[var(--text-primary)]">{m.value}</p>
                  <p className="text-xs text-[var(--text-muted)] mt-1">{m.label}</p>
                  <p className="text-[10px] text-[var(--text-muted)]">{m.desc}</p>
                </motion.div>
              ))}
            </div>
          </FadeUp>

          {/* Per-Expert Results Table (placeholder) */}
          <FadeUp delay={0.2}>
            <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Per-Expert Benchmarks</h3>
            <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-8 text-center">
              <BarChart3 className="w-12 h-12 mx-auto text-[var(--text-muted)] mb-3" />
              <p className="text-sm text-[var(--text-muted)]">Benchmark results will appear here after training completes</p>
              <p className="text-xs text-[var(--text-muted)] mt-1">Powered by promptfoo evaluation framework</p>
            </div>
          </FadeUp>

          {/* Chart Placeholders */}
          <ScrollReveal>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-6 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
                <h4 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Training Loss Curves</h4>
                <div className="h-48 flex items-center justify-center border border-dashed border-[var(--border)] rounded-lg">
                  <span className="text-xs text-[var(--text-muted)]">Recharts line chart — loss over steps</span>
                </div>
              </div>
              <div className="p-6 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
                <h4 className="text-sm font-semibold text-[var(--text-primary)] mb-3">Expert Accuracy Radar</h4>
                <div className="h-48 flex items-center justify-center border border-dashed border-[var(--border)] rounded-lg">
                  <span className="text-xs text-[var(--text-muted)]">Recharts radar chart — per-domain scores</span>
                </div>
              </div>
            </div>
          </ScrollReveal>
        </StaggerContainer>
      </div>
    </div>
  );
}
