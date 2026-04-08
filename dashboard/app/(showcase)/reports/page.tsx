"use client";

import { TopBar } from "@/components/layout/top-bar";
import { StaggerContainer, FadeUp } from "@/components/animations/motion-wrapper";
import { motion } from "framer-motion";
import { FileText, Download, Eye, Calendar, Shield } from "lucide-react";
import { CyberButton } from "@/components/ui/cyber-button";
import { getVerdictColor } from "@/lib/utils";

const DEMO_REPORTS = [
  { id: "1", file: "emotet_loader.exe", verdict: "malicious", confidence: 94, date: "2026-03-27", experts: ["E1", "E2", "E5"], family: "Emotet" },
  { id: "2", file: "invoice_q1.pdf", verdict: "suspicious", confidence: 67, date: "2026-03-27", experts: ["E1", "E6"], family: "Unknown" },
  { id: "3", file: "update_service.dll", verdict: "malicious", confidence: 89, date: "2026-03-26", experts: ["E1", "E2", "E3"], family: "Cobalt Strike" },
  { id: "4", file: "sample4.dll", verdict: "malicious", confidence: 95, date: "2026-04-01", experts: ["E2", "E7"], family: "DridexV4" },
  { id: "5", file: "Bootstapper.exe", verdict: "malicious", confidence: 100, date: "2026-04-02", experts: ["E1", "E2", "E5"], family: "Vidar" },
];

export default function ReportsPage() {
  return (
    <div className="min-h-screen">
      <TopBar title="Reports" />

      <div className="max-w-6xl mx-auto px-8 py-10">
        <StaggerContainer className="space-y-8">
          <FadeUp>
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-2xl font-bold text-[var(--text-primary)]">Analysis Reports</h2>
                <p className="text-sm text-[var(--text-muted)] mt-1">
                  Past analysis results — upload a file in the working app to generate real reports
                </p>
              </div>
              <CyberButton variant="secondary" size="sm">
                <Download className="w-3.5 h-3.5" /> Export All
              </CyberButton>
            </div>
          </FadeUp>

          <FadeUp delay={0.1}>
            <div className="space-y-3">
              {DEMO_REPORTS.map((report, i) => {
                const verdictColor = getVerdictColor(report.verdict);
                return (
                  <motion.div
                    key={report.id}
                    className="flex items-center gap-4 p-4 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] hover:border-[var(--border-accent)] transition-colors"
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.06 * i }}
                  >
                    <div className="p-2 rounded-lg flex-shrink-0"
                      style={{ backgroundColor: `${verdictColor}15`, color: verdictColor }}>
                      <Shield className="w-5 h-5" />
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-[var(--text-primary)] font-mono truncate">
                        {report.file}
                      </p>
                      <div className="flex items-center gap-3 mt-1 flex-wrap">
                        <span className="text-xs px-2 py-0.5 rounded-full font-medium"
                          style={{ backgroundColor: `${verdictColor}15`, color: verdictColor }}>
                          {report.verdict}
                        </span>
                        <span className="text-xs text-[var(--text-muted)]">{report.family}</span>
                        <span className="text-xs text-[var(--text-muted)]">{report.confidence}% confidence</span>
                        <span className="text-xs text-[var(--text-muted)] flex items-center gap-1">
                          <Calendar className="w-3 h-3" /> {report.date}
                        </span>
                      </div>
                    </div>

                    <div className="flex gap-1 flex-shrink-0">
                      {report.experts.map((e) => (
                        <span key={e} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-muted)]">{e}</span>
                      ))}
                    </div>

                    <CyberButton variant="ghost" size="sm">
                      <Eye className="w-3.5 h-3.5" /> View
                    </CyberButton>
                  </motion.div>
                );
              })}
            </div>
          </FadeUp>

          <FadeUp delay={0.3}>
            <div className="p-6 rounded-xl border border-dashed border-[var(--border)] bg-[var(--bg-card)] text-center">
              <FileText className="w-10 h-10 mx-auto text-[var(--text-muted)] mb-3" />
              <p className="text-sm text-[var(--text-muted)]">
                Real reports appear here after analyzing files in{" "}
                <a href="/app/upload" className="text-[var(--accent)] hover:underline">/app/upload</a>
              </p>
            </div>
          </FadeUp>
        </StaggerContainer>
      </div>
    </div>
  );
}
