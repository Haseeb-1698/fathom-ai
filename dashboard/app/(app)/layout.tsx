"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import { motion } from "framer-motion";
import {
  Upload, ScanSearch, FileText, Network,
  Fingerprint, ChevronRight, Activity, LogOut, User,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";
import { signOutUser } from "@/lib/firebase";
import { ChatHistory } from "@/components/analysis/chat-history";

const APP_NAV = [
  { label: "Upload", href: "/app/upload", icon: Upload },
  { label: "Analysis", href: "/app/analysis", icon: ScanSearch },
  { label: "Report", href: "/app/report", icon: FileText },
  { label: "Graph", href: "/app/graph", icon: Network },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, loading } = useAuth();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!loading && !user) {
      // In development, allow access without auth for testing
      if (process.env.NODE_ENV !== "development") {
        router.push("/login");
      }
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--bg-primary)]">
        <div className="w-5 h-5 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  // In dev, allow unauthenticated access
  if (!user && process.env.NODE_ENV === "development") {
    // continue rendering without auth
  } else if (!user) {
    return null;
  }

  return (
    <div className="flex flex-col min-h-screen">
      {/* ── Top Navigation Bar ─────────────────────────────── */}
      <header className="h-12 flex items-center justify-between px-4 border-b border-[var(--border)] bg-[var(--bg-surface)]/90 backdrop-blur-xl sticky top-0 z-50">
        {/* Left: Logo + Nav */}
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2 group">
            <Fingerprint
              className="w-5 h-5 text-[var(--accent)] group-hover:drop-shadow-[0_0_8px_var(--accent-glow-strong)] transition-all"
              strokeWidth={1.5}
            />
            <span className="text-sm font-bold gradient-text-teal hidden sm:inline">FATHOM</span>
          </Link>

          <div className="h-5 w-px bg-[var(--border)]" />

          <nav className="flex items-center gap-1">
            {APP_NAV.map((item) => {
              const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer",
                    isActive
                      ? "text-[var(--accent)]"
                      : "text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--bg-card)]"
                  )}
                >
                  {isActive && (
                    <motion.div
                      className="absolute inset-0 rounded-md bg-[var(--accent-glow)] border border-[var(--border-accent)]"
                      layoutId="appNav"
                      transition={{ type: "spring", stiffness: 400, damping: 30 }}
                    />
                  )}
                  <item.icon className="w-3.5 h-3.5 relative z-10" />
                  <span className="relative z-10 hidden md:inline">{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right: Status + User */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-[var(--success)]/10 border border-[var(--success)]/20">
            <Activity className="w-2.5 h-2.5 text-[var(--success)]" />
            <span className="text-[10px] text-[var(--success)] font-medium">Pipeline Ready</span>
          </div>

          {/* User avatar + sign out */}
          <div className="flex items-center gap-2">
            <ChatHistory />
            {user.photoURL ? (
              <img src={user.photoURL} alt={user.displayName || "User"}
                className="w-6 h-6 rounded-full border border-[var(--border)]" />
            ) : (
              <div className="w-6 h-6 rounded-full bg-[var(--accent-glow)] border border-[var(--border-accent)] flex items-center justify-center">
                <User className="w-3 h-3 text-[var(--accent)]" />
              </div>
            )}
            <span className="text-[10px] text-[var(--text-muted)] hidden md:inline max-w-[100px] truncate">
              {user.displayName || user.email}
            </span>
            <button
              onClick={() => signOutUser().then(() => router.push("/login"))}
              className="p-1 rounded hover:bg-[var(--bg-card)] text-[var(--text-muted)] hover:text-[var(--danger)] transition-colors cursor-pointer"
              title="Sign out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>

          <Link href="/" className="flex items-center gap-1 text-[10px] text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors cursor-pointer">
            Showcase
            <ChevronRight className="w-3 h-3" />
          </Link>
        </div>
      </header>

      <main className="flex-1 overflow-y-auto">{children}</main>
    </div>
  );
}
