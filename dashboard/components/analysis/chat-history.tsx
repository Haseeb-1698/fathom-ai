"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { History, MessageSquare, ChevronRight, Clock, Shield, X, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";
import { loadChatSessions, type ChatSession } from "@/lib/firebase";

interface ChatHistoryProps {
  /** Called when user clicks a session — parent can restore it */
  onSelectSession?: (sessionId: string, sampleName: string) => void;
  className?: string;
}

export function ChatHistory({ onSelectSession, className }: ChatHistoryProps) {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !user) return;
    setLoading(true);
    loadChatSessions(user.uid)
      .then(setSessions)
      .finally(() => setLoading(false));
  }, [open, user]);

  if (!user) return null;

  return (
    <div className={cn("relative", className)}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border)] bg-[var(--bg-card)] text-xs text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-accent)] transition-colors cursor-pointer"
      >
        <History className="w-3.5 h-3.5" />
        Chat History
      </button>

      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />

            {/* Panel */}
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.97 }}
              transition={{ duration: 0.15 }}
              className="absolute right-0 top-10 w-80 z-50 rounded-xl border border-[var(--border)] bg-[var(--bg-surface)] shadow-2xl overflow-hidden"
            >
              <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)] bg-[var(--bg-card)]">
                <div className="flex items-center gap-2">
                  <History className="w-3.5 h-3.5 text-[var(--accent)]" />
                  <span className="text-xs font-semibold text-[var(--text-primary)]">Your Conversations</span>
                </div>
                <button onClick={() => setOpen(false)} className="p-1 rounded hover:bg-[var(--bg-elevated)] text-[var(--text-muted)] cursor-pointer">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="max-h-80 overflow-y-auto">
                {loading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-5 h-5 text-[var(--accent)] animate-spin" />
                  </div>
                ) : sessions.length === 0 ? (
                  <div className="flex flex-col items-center gap-2 py-8 px-4 text-center">
                    <MessageSquare className="w-8 h-8 text-[var(--text-muted)]" />
                    <p className="text-xs text-[var(--text-muted)]">No conversations yet</p>
                    <p className="text-[10px] text-[var(--text-muted)]">
                      Start chatting with Fathom about a sample
                    </p>
                  </div>
                ) : (
                  <div className="divide-y divide-[var(--border)]">
                    {sessions.map((session) => (
                      <button
                        key={session.sessionId}
                        onClick={() => {
                          onSelectSession?.(session.sessionId, session.sampleName || "");
                          setOpen(false);
                        }}
                        className="w-full flex items-start gap-3 px-4 py-3 hover:bg-[var(--bg-elevated)] transition-colors text-left cursor-pointer"
                      >
                        <div className="p-1.5 rounded-lg bg-[var(--accent-glow)] flex-shrink-0 mt-0.5">
                          <Shield className="w-3 h-3 text-[var(--accent)]" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium text-[var(--text-primary)] truncate">
                            {session.sampleName || "Unknown sample"}
                          </p>
                          <p className="text-[10px] text-[var(--text-muted)] truncate mt-0.5">
                            {session.lastMessage || "No messages"}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-[9px] text-[var(--text-muted)] flex items-center gap-0.5">
                              <MessageSquare className="w-2.5 h-2.5" />
                              {session.messageCount} messages
                            </span>
                          </div>
                        </div>
                        <ChevronRight className="w-3.5 h-3.5 text-[var(--text-muted)] flex-shrink-0 mt-1" />
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <div className="px-4 py-2.5 border-t border-[var(--border)] bg-[var(--bg-card)]">
                <p className="text-[10px] text-[var(--text-muted)] text-center">
                  Conversations are private to your account
                </p>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
