import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

export function getSeverityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: "#EF4444",
    high: "#F97316",
    medium: "#F59E0B",
    low: "#3B82F6",
    info: "#6B7280",
  };
  return map[severity] || map.info;
}

export function getVerdictColor(verdict: string): string {
  const map: Record<string, string> = {
    malicious: "#EF4444",
    suspicious: "#F59E0B",
    benign: "#10B981",
    unknown: "#6B7280",
  };
  return map[verdict] || map.unknown;
}

export function getStatusColor(status: string): string {
  const map: Record<string, string> = {
    trained: "#10B981",
    training: "#F59E0B",
    pending: "#6B7280",
    failed: "#EF4444",
    ready: "#10B981",
    downloading: "#3B82F6",
    completed: "#10B981",
    running: "#F59E0B",
    queued: "#6B7280",
    error: "#EF4444",
  };
  return map[status] || "#6B7280";
}
