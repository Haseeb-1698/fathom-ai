"use client";

import { motion } from "framer-motion";
import { Bell, Search, Settings, Activity } from "lucide-react";

export function TopBar({ title }: { title: string }) {
  return (
    <motion.header
      className="h-16 flex items-center justify-between px-6 border-b border-[var(--border)] bg-[var(--bg-surface)]/80 backdrop-blur-xl sticky top-0 z-40"
      initial={{ y: -20, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold text-[var(--text-primary)]">{title}</h1>
        <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-[var(--success)]/10 border border-[var(--success)]/20">
          <Activity className="w-3 h-3 text-[var(--success)]" />
          <span className="text-xs text-[var(--success)] font-medium">System Online</span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        {/* Search */}
        <button className="p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card)] transition-colors">
          <Search className="w-4 h-4" />
        </button>
        {/* Notifications */}
        <button className="p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card)] transition-colors relative">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-[var(--accent)]" />
        </button>
        {/* Settings */}
        <button className="p-2 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card)] transition-colors">
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </motion.header>
  );
}
