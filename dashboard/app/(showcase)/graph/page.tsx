"use client";

import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp } from "@/components/animations/motion-wrapper";
import { motion } from "framer-motion";
import { Network, Search, Filter, ZoomIn } from "lucide-react";
import { CyberButton } from "@/components/ui/cyber-button";

export default function GraphPage() {
  return (
    <div className="min-h-screen">
      <TopBar title="Knowledge Graph" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-6">
          <FadeUp>
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-2xl font-bold text-[var(--text-primary)]">Knowledge Graph</h2>
                <p className="text-sm text-[var(--text-muted)] mt-1">
                  Neo4j-backed threat intelligence graph — IOCs, techniques, actors, campaigns
                </p>
              </div>
              <div className="flex gap-2">
                <CyberButton variant="ghost" size="sm"><Filter className="w-3.5 h-3.5" /> Filter</CyberButton>
                <CyberButton variant="ghost" size="sm"><ZoomIn className="w-3.5 h-3.5" /> Zoom</CyberButton>
              </div>
            </div>
          </FadeUp>

          {/* Search */}
          <FadeUp delay={0.1}>
            <div className="flex gap-3">
              <div className="flex-1 flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[var(--bg-card)] border border-[var(--border)]">
                <Search className="w-4 h-4 text-[var(--text-muted)]" />
                <input
                  type="text"
                  placeholder="Search IOCs, techniques, actors..."
                  className="bg-transparent flex-1 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none"
                />
              </div>
              <CyberButton variant="primary" size="md">Search Graph</CyberButton>
            </div>
          </FadeUp>

          {/* Graph Canvas */}
          <FadeUp delay={0.2}>
            <div className="relative rounded-xl border border-[var(--border)] bg-[var(--bg-surface)] overflow-hidden" style={{ height: "60vh" }}>
              {/* Graph renders here — react-force-graph-2d */}
              <div className="absolute inset-0 cyber-grid opacity-20" />
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <Network className="w-16 h-16 mx-auto text-[var(--accent)] opacity-30 mb-4" />
                  <p className="text-sm text-[var(--text-muted)]">Interactive force-directed graph</p>
                  <p className="text-xs text-[var(--text-muted)] mt-1">Powered by react-force-graph + Neo4j</p>
                </div>
              </div>

              {/* Node Type Legend */}
              <div className="absolute bottom-4 left-4 flex gap-3 p-3 rounded-lg bg-[var(--bg-card)]/80 backdrop-blur border border-[var(--border)]">
                {[
                  { label: "File", color: "#00D4AA" },
                  { label: "Behavior", color: "#7C3AED" },
                  { label: "IOC", color: "#EF4444" },
                  { label: "Technique", color: "#F59E0B" },
                  { label: "Actor", color: "#3B82F6" },
                  { label: "Campaign", color: "#EC4899" },
                ].map((n) => (
                  <div key={n.label} className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: n.color }} />
                    <span className="text-[10px] text-[var(--text-muted)]">{n.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </FadeUp>
        </StaggerContainer>
      </div>
    </div>
  );
}
