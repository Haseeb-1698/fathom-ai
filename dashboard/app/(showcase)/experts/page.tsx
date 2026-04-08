"use client";

import { TopBar } from "@/components/layout/top-bar";
import { ExpertCard } from "@/components/ui/expert-card";
import { StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { EXPERTS, MODEL_CONFIG } from "@/lib/constants";
import { formatNumber } from "@/lib/utils";
import { motion } from "framer-motion";
import { Brain, Layers, Zap, Settings2 } from "lucide-react";

export default function ExpertsPage() {
  const totalRows = EXPERTS.reduce((s, e) => s + e.datasetRows, 0);

  return (
    <div className="min-h-screen">
      <TopBar title="Expert Adapters" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">
          {/* Header */}
          <FadeUp>
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-2xl font-bold text-[var(--text-primary)]">Expert Adapters</h2>
                <p className="text-sm text-[var(--text-muted)] mt-1">
                  {EXPERTS.length} domain-specialized LoRA adapters | {formatNumber(totalRows)} total training rows
                </p>
              </div>
            </div>
          </FadeUp>

          {/* Model Config Banner */}
          <FadeUp delay={0.1}>
            <div className="p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-[var(--accent)]" />
                <span className="text-xs text-[var(--text-muted)]">Base:</span>
                <span className="text-xs font-mono text-[var(--text-primary)]">{MODEL_CONFIG.base}</span>
              </div>
              <div className="w-px h-4 bg-[var(--border)]" />
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[var(--secondary)]" />
                <span className="text-xs text-[var(--text-muted)]">Method:</span>
                <span className="text-xs font-mono text-[var(--text-primary)]">{MODEL_CONFIG.method} r={MODEL_CONFIG.rank} α={MODEL_CONFIG.alpha}</span>
              </div>
              <div className="w-px h-4 bg-[var(--border)]" />
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[var(--warning)]" />
                <span className="text-xs text-[var(--text-muted)]">Quant:</span>
                <span className="text-xs font-mono text-[var(--text-primary)]">{MODEL_CONFIG.quantization}</span>
              </div>
              <div className="w-px h-4 bg-[var(--border)]" />
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-[#3B82F6]" />
                <span className="text-xs text-[var(--text-muted)]">GPU:</span>
                <span className="text-xs font-mono text-[var(--text-primary)]">{MODEL_CONFIG.targetGpu}</span>
              </div>
            </div>
          </FadeUp>

          {/* Expert Grid */}
          <FadeUp delay={0.2}>
            <div className="grid grid-cols-2 gap-4">
              {EXPERTS.map((expert, i) => (
                <ExpertCard key={expert.id} expert={expert} index={i} />
              ))}
            </div>
          </FadeUp>

          {/* Training Order */}
          <ScrollReveal>
            <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Training Order</h3>
            <div className="flex items-center gap-2 overflow-x-auto pb-2">
              {["Unified v2", "E2 Dynamic", "E7 Reports", "E5 ThreatIntel", "E1 Static", "E3 Network", "E4 Forensics", "E6 Detection", "E8 Analyst"].map((name, i) => (
                <div key={i} className="flex items-center gap-2">
                  <motion.div
                    className="px-3 py-2 rounded-lg border border-[var(--border)] bg-[var(--bg-card)] text-xs font-medium text-[var(--text-secondary)] whitespace-nowrap"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.08 }}
                  >
                    <span className="text-[var(--text-muted)] mr-1">{i + 1}.</span>
                    {name}
                  </motion.div>
                  {i < 8 && <span className="text-[var(--text-muted)]">→</span>}
                </div>
              ))}
            </div>
          </ScrollReveal>
        </StaggerContainer>
      </div>
    </div>
  );
}
