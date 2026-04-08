"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: { value: number; positive: boolean };
  glowColor?: string;
  delay?: number;
}

export function StatCard({ label, value, icon, trend, glowColor = "var(--accent)", delay = 0 }: StatCardProps) {
  return (
    <motion.div
      className={cn(
        "relative p-5 rounded-xl border border-[var(--border)]",
        "bg-[var(--bg-card)] card-hover overflow-hidden"
      )}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay }}
    >
      {/* Top glow line */}
      <div
        className="absolute top-0 left-0 right-0 h-[1px]"
        style={{ background: `linear-gradient(90deg, transparent, ${glowColor}, transparent)` }}
      />

      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase tracking-wider text-[var(--text-muted)] mb-1">{label}</p>
          <p className="text-2xl font-bold text-[var(--text-primary)]">{value}</p>
          {trend && (
            <p className={cn("text-xs mt-1", trend.positive ? "text-[var(--success)]" : "text-[var(--danger)]")}>
              {trend.positive ? "+" : ""}{trend.value}%
            </p>
          )}
        </div>
        <div className="p-2 rounded-lg bg-[var(--bg-elevated)]" style={{ color: glowColor }}>
          {icon}
        </div>
      </div>
    </motion.div>
  );
}
