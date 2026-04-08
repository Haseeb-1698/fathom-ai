"use client";

import { motion } from "framer-motion";
import {
  FileCode, Play, Wifi, Search, Globe,
  ShieldAlert, FileText, MonitorCheck,
} from "lucide-react";
import { cn, formatNumber, getStatusColor } from "@/lib/utils";
import type { Expert } from "@/types";

const ICON_MAP: Record<string, React.ElementType> = {
  FileCode, Play, Wifi, Search, Globe,
  ShieldAlert, FileText, MonitorCheck,
};

export function ExpertCard({ expert, index }: { expert: Expert; index: number }) {
  const Icon = ICON_MAP[expert.icon] || FileCode;

  return (
    <motion.div
      className={cn(
        "relative p-5 rounded-xl border border-[var(--border)]",
        "bg-[var(--bg-card)] card-hover overflow-hidden group"
      )}
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: index * 0.08 }}
      whileHover={{ scale: 1.02 }}
    >
      {/* Accent top border */}
      <div
        className="absolute top-0 left-0 right-0 h-[2px]"
        style={{ background: expert.color }}
      />

      {/* Background glow on hover */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500"
        style={{
          background: `radial-gradient(circle at 50% 0%, ${expert.color}15, transparent 70%)`,
        }}
      />

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center gap-3 mb-3">
          <div
            className="p-2 rounded-lg"
            style={{ backgroundColor: `${expert.color}15`, color: expert.color }}
          >
            <Icon className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">{expert.name}</h3>
            <span className="text-xs font-mono text-[var(--text-muted)] uppercase">{expert.id}</span>
          </div>
          <div
            className="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium"
            style={{
              backgroundColor: `${getStatusColor(expert.status)}15`,
              color: getStatusColor(expert.status),
            }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: getStatusColor(expert.status) }} />
            {expert.status}
          </div>
        </div>

        {/* Description */}
        <p className="text-xs text-[var(--text-secondary)] mb-4 line-clamp-2">{expert.description}</p>

        {/* Stats */}
        <div className="flex items-center justify-between text-xs">
          <span className="text-[var(--text-muted)]">
            Dataset: <span className="text-[var(--text-secondary)] font-mono">{formatNumber(expert.datasetRows)}</span> rows
          </span>
          {expert.accuracy && (
            <span style={{ color: expert.color }}>
              {expert.accuracy}% acc
            </span>
          )}
        </div>
      </div>
    </motion.div>
  );
}
