"use client";

import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { DATASETS } from "@/lib/constants";
import { formatNumber, getStatusColor } from "@/lib/utils";
import { motion } from "framer-motion";
import { Database, HardDrive, ExternalLink, Download, CheckCircle2 } from "lucide-react";

export default function DatasetsPage() {
  const totalRows = DATASETS.reduce((s, d) => s + d.rows, 0);
  const readyCount = DATASETS.filter((d) => d.status === "ready").length;

  return (
    <div className="min-h-screen">
      <TopBar title="Datasets" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">
          {/* Header */}
          <FadeUp>
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-2xl font-bold text-[var(--text-primary)]">Dataset Explorer</h2>
                <p className="text-sm text-[var(--text-muted)] mt-1">
                  {DATASETS.length} datasets | {formatNumber(totalRows)} total rows | {readyCount} ready
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
                <HardDrive className="w-3.5 h-3.5" />
                HF Hub: umer07/fathom-expert-data
              </div>
            </div>
          </FadeUp>

          {/* Stats */}
          <FadeUp delay={0.1}>
            <div className="grid grid-cols-3 gap-4">
              <div className="p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
                <p className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">processed/</p>
                <p className="text-lg font-bold text-[var(--text-primary)]">
                  {formatNumber(DATASETS.filter(d => d.location === "processed").reduce((s, d) => s + d.rows, 0))} rows
                </p>
                <p className="text-xs text-[var(--text-muted)]">Plan A legacy datasets</p>
              </div>
              <div className="p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
                <p className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">experts/</p>
                <p className="text-lg font-bold text-[var(--accent)]">
                  {formatNumber(DATASETS.filter(d => d.location === "experts").reduce((s, d) => s + d.rows, 0))} rows
                </p>
                <p className="text-xs text-[var(--text-muted)]">Plan B new expert data</p>
              </div>
              <div className="p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)]">
                <p className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">infra/</p>
                <p className="text-lg font-bold text-[var(--secondary)]">2 files</p>
                <p className="text-xs text-[var(--text-muted)]">FAISS index + domain centroids</p>
              </div>
            </div>
          </FadeUp>

          {/* Dataset Table */}
          <FadeUp delay={0.2}>
            <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-[var(--text-muted)] text-xs uppercase tracking-wider">
                    <th className="text-left px-4 py-3">Dataset</th>
                    <th className="text-left px-4 py-3">Expert</th>
                    <th className="text-right px-4 py-3">Rows</th>
                    <th className="text-right px-4 py-3">Size</th>
                    <th className="text-center px-4 py-3">Location</th>
                    <th className="text-center px-4 py-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {DATASETS.map((d, i) => (
                    <motion.tr
                      key={d.id}
                      className="border-b border-[var(--border)]/50 hover:bg-[var(--bg-card-hover)] transition-colors"
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.02 * i }}
                    >
                      <td className="px-4 py-3">
                        <div>
                          <p className="font-medium text-[var(--text-primary)]">{d.name}</p>
                          <p className="text-xs text-[var(--text-muted)] font-mono">{d.file}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[var(--text-secondary)] text-xs">{d.expertId || "—"}</td>
                      <td className="px-4 py-3 text-right font-mono text-[var(--text-primary)]">
                        {d.rows > 0 ? formatNumber(d.rows) : "—"}
                      </td>
                      <td className="px-4 py-3 text-right text-[var(--text-muted)]">{d.size}</td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-xs px-2 py-0.5 rounded font-mono bg-[var(--bg-elevated)] text-[var(--text-secondary)]">
                          {d.location}/
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span
                          className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full"
                          style={{ backgroundColor: `${getStatusColor(d.status)}15`, color: getStatusColor(d.status) }}
                        >
                          <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: getStatusColor(d.status) }} />
                          {d.status}
                        </span>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </FadeUp>
        </StaggerContainer>
      </div>
    </div>
  );
}
