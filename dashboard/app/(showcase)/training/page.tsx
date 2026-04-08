"use client";

import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { MODEL_CONFIG, TRAINING_ORDER, EXPERTS } from "@/lib/constants";
import { motion } from "framer-motion";
import { Cpu, Layers, Zap, Clock, ArrowRight, CheckCircle2, Circle, Play } from "lucide-react";

const TRAINING_STEPS = [
  { id: "unified", name: "Unified v2", steps: 6000, status: "pending" },
  { id: "e2", name: "E2 Dynamic", steps: 2200, status: "pending" },
  { id: "e7", name: "E7 Reports", steps: 23000, status: "pending" },
  { id: "e5", name: "E5 ThreatIntel", steps: 3000, status: "pending" },
  { id: "e1", name: "E1 Static", steps: 2750, status: "pending" },
  { id: "e3", name: "E3 Network", steps: 2000, status: "pending" },
  { id: "e4", name: "E4 Forensics", steps: 140, status: "pending" },
  { id: "e6", name: "E6 Detection", steps: 1375, status: "pending" },
  { id: "e8", name: "E8 Analyst", steps: 546, status: "pending" },
];

export default function TrainingPage() {
  return (
    <div className="min-h-screen">
      <TopBar title="Training" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">
          {/* Header */}
          <FadeUp>
            <h2 className="text-2xl font-bold text-[var(--text-primary)]">Training Workflow</h2>
            <p className="text-sm text-[var(--text-muted)] mt-1">
              Sequential LoRA fine-tuning pipeline on {MODEL_CONFIG.targetGpu}
            </p>
          </FadeUp>

          {/* Config Summary */}
          <FadeUp delay={0.1}>
            <div className="grid grid-cols-4 gap-4">
              {[
                { icon: <Cpu className="w-4 h-4" />, label: "Framework", value: MODEL_CONFIG.framework, color: "var(--accent)" },
                { icon: <Layers className="w-4 h-4" />, label: "LoRA Config", value: `r=${MODEL_CONFIG.rank} α=${MODEL_CONFIG.alpha}`, color: "var(--secondary)" },
                { icon: <Zap className="w-4 h-4" />, label: "Precision", value: `${MODEL_CONFIG.quantization} + ${MODEL_CONFIG.precision}`, color: "#F59E0B" },
                { icon: <Clock className="w-4 h-4" />, label: "Est. Time", value: "~40 hrs total", color: "#3B82F6" },
              ].map((item, i) => (
                <motion.div
                  key={i}
                  className="p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.05 * i }}
                >
                  <div className="flex items-center gap-2 mb-2" style={{ color: item.color }}>{item.icon}<span className="text-xs text-[var(--text-muted)]">{item.label}</span></div>
                  <p className="text-sm font-medium text-[var(--text-primary)]">{item.value}</p>
                </motion.div>
              ))}
            </div>
          </FadeUp>

          {/* Training Pipeline Visual */}
          <FadeUp delay={0.2}>
            <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Pipeline</h3>
            <div className="space-y-3">
              {TRAINING_STEPS.map((step, i) => (
                <motion.div
                  key={step.id}
                  className="flex items-center gap-4 p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] hover:bg-[var(--bg-card-hover)] transition-colors"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.05 * i }}
                >
                  <span className="text-xs text-[var(--text-muted)] w-6">{i + 1}</span>
                  <Circle className="w-4 h-4 text-[var(--text-muted)]" />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-[var(--text-primary)]">{step.name}</p>
                    <p className="text-xs text-[var(--text-muted)]">{step.steps.toLocaleString()} steps</p>
                  </div>
                  {/* Progress bar placeholder */}
                  <div className="w-48 h-2 rounded-full bg-[var(--bg-elevated)]">
                    <div className="h-full rounded-full bg-[var(--border)]" style={{ width: "0%" }} />
                  </div>
                  <span className="text-xs text-[var(--text-muted)] w-16 text-right">Pending</span>
                </motion.div>
              ))}
            </div>
          </FadeUp>

          {/* Architecture Diagram Placeholder */}
          <ScrollReveal>
            <h3 className="text-lg font-semibold text-[var(--text-primary)] mb-4">Training Architecture</h3>
            <div className="p-8 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] text-center">
              <div className="flex items-center justify-center gap-4 flex-wrap">
                <div className="px-4 py-2 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)] text-sm text-[var(--text-secondary)]">
                  Qwen2.5-7B-Instruct
                </div>
                <ArrowRight className="w-4 h-4 text-[var(--text-muted)]" />
                <div className="px-4 py-2 rounded-lg bg-[var(--accent-glow)] border border-[var(--border-accent)] text-sm text-[var(--accent)]">
                  LoRA Adapter (r=32)
                </div>
                <ArrowRight className="w-4 h-4 text-[var(--text-muted)]" />
                <div className="px-4 py-2 rounded-lg bg-[var(--secondary-glow)] border border-[var(--secondary)]/20 text-sm text-[var(--secondary)]">
                  Expert Checkpoint
                </div>
                <ArrowRight className="w-4 h-4 text-[var(--text-muted)]" />
                <div className="px-4 py-2 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)] text-sm text-[var(--text-secondary)]">
                  HF Hub Upload
                </div>
              </div>
            </div>
          </ScrollReveal>
        </StaggerContainer>
      </div>
    </div>
  );
}
