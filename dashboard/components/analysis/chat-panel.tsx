"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { MessageSquare, Send, Bot, User, ChevronDown, Zap, History, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth-context";
import { saveChatMessage, saveChatSession, loadChatMessages } from "@/lib/firebase";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://134.199.201.243:7860";

interface Message {
  role: "user" | "assistant";
  content: string;
  ts: number;
  cached?: boolean;
}

interface ChatPanelProps {
  capeContext?: string;  // evidence text — sent to model as context, not stored
  sessionId?: string;   // links this chat to a specific analysis session
  sampleSha256?: string;
  className?: string;
}

const SUGGESTED = [
  "What ATT&CK techniques were used?",
  "Explain the C2 communication",
  "How do I detect this malware?",
  "What persistence mechanisms were found?",
];

export function ChatPanel({
  capeContext = "",
  sessionId,
  sampleSha256 = "",
  className,
}: ChatPanelProps) {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [historyLoaded, setHistoryLoaded] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const sid = sessionId || "default";

  // ── Load user's chat history from Firebase when panel opens ──────────────
  useEffect(() => {
    if (!open || historyLoaded) return;

    if (!user) {
      // Not logged in — show welcome message only
      setMessages([{
        role: "assistant",
        content: "I'm Fathom. Ask me anything about this sample — techniques, IOCs, remediation, or threat actor context.",
        ts: Date.now(),
      }]);
      setHistoryLoaded(true);
      return;
    }

    setLoadingHistory(true);
    loadChatMessages(user.uid, sid)
      .then((msgs) => {
        if (msgs.length === 0) {
          setMessages([{
            role: "assistant",
            content: "I'm Fathom. Ask me anything about this sample — techniques, IOCs, remediation, or threat actor context.",
            ts: Date.now(),
          }]);
        } else {
          // Restore previous conversation
          setMessages(msgs.map((m) => ({
            role: m.role,
            content: m.content,
            ts: m.ts ? (m.ts as any).toMillis?.() ?? Date.now() : Date.now(),
          })));
        }
      })
      .catch(() => {
        setMessages([{
          role: "assistant",
          content: "I'm Fathom. Ask me anything about this sample.",
          ts: Date.now(),
        }]);
      })
      .finally(() => {
        setLoadingHistory(false);
        setHistoryLoaded(true);
      });
  }, [open, historyLoaded, user, sid]);

  // ── Auto-scroll ───────────────────────────────────────────────────────────
  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [open, messages]);

  // ── Focus input on open ───────────────────────────────────────────────────
  useEffect(() => {
    if (open && !loadingHistory) setTimeout(() => inputRef.current?.focus(), 80);
  }, [open, loadingHistory]);

  // ── Send message ──────────────────────────────────────────────────────────
  const send = useCallback(async (text?: string) => {
    const msg = (text ?? input).trim();
    if (!msg || streaming) return;
    setInput("");

    const userMsg: Message = { role: "user", content: msg, ts: Date.now() };
    setMessages((prev) => [...prev, userMsg]);
    setStreaming(true);

    // Add empty assistant placeholder for streaming
    setMessages((prev) => [...prev, { role: "assistant", content: "", ts: Date.now() }]);

    abortRef.current = new AbortController();
    let fullText = "";

    try {
      const res = await fetch(`${API_URL}/api/chat/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: msg,
          session_id: sid,
          cape_context: capeContext,
          history: [],  // backend loads from Neo4j/FAISS — universal cache
        }),
        signal: abortRef.current.signal,
      });

      if (!res.ok || !res.body) throw new Error(`Chat error: ${res.status}`);

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            if (ev.type === "chunk") {
              fullText += ev.text;
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  ...updated[updated.length - 1],
                  content: fullText,
                };
                return updated;
              });
            }
          } catch { /* ignore */ }
        }
      }

      // ── Persist to Firebase (per-user history) ────────────────────────────
      if (user && fullText) {
        const sampleName = sampleSha256
          ? `Sample ${sampleSha256.slice(0, 8)}...`
          : "Unknown sample";
        saveChatMessage(user.uid, sid, "user", msg, sampleSha256).catch(() => {});
        saveChatMessage(user.uid, sid, "assistant", fullText, sampleSha256).catch(() => {});
        // Update session record so it appears in history sidebar
        saveChatSession(
          user.uid, sid, sampleName, sampleSha256,
          fullText.slice(0, 120),
          messages.length + 2,
        ).catch(() => {});
      }

    } catch (e: any) {
      if (e.name === "AbortError") {
        // User stopped — keep whatever was streamed
        return;
      }
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = {
          ...updated[updated.length - 1],
          content: `Error: ${e.message}`,
        };
        return updated;
      });
    } finally {
      setStreaming(false);
    }
  }, [input, streaming, capeContext, sid, user, sampleSha256]);

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className={cn("fixed bottom-6 right-6 z-50", className)}>
      {/* Floating button */}
      <AnimatePresence>
        {!open && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            onClick={() => setOpen(true)}
            className="flex items-center gap-2 px-4 py-3 rounded-2xl bg-[var(--accent)] text-[var(--bg-primary)] text-sm font-semibold shadow-lg hover:bg-[var(--accent-dim)] transition-colors cursor-pointer"
          >
            <MessageSquare className="w-4 h-4" />
            Ask Fathom
          </motion.button>
        )}
      </AnimatePresence>

      {/* Chat window */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="w-[420px] h-[560px] flex flex-col rounded-2xl border border-[var(--border)] bg-[var(--bg-surface)] shadow-2xl overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)] bg-[var(--bg-card)]">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse" />
                <span className="text-sm font-semibold text-[var(--text-primary)]">Fathom Chat</span>
                {user && (
                  <span className="text-[10px] text-[var(--text-muted)] px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] flex items-center gap-1">
                    <History className="w-2.5 h-2.5" />
                    history saved
                  </span>
                )}
              </div>
              <button
                onClick={() => { abortRef.current?.abort(); setOpen(false); }}
                className="p-1 rounded hover:bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
              >
                <ChevronDown className="w-4 h-4" />
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {loadingHistory ? (
                <div className="flex items-center justify-center h-full">
                  <div className="flex flex-col items-center gap-2">
                    <Loader2 className="w-5 h-5 text-[var(--accent)] animate-spin" />
                    <p className="text-[10px] text-[var(--text-muted)]">Loading your conversation history...</p>
                  </div>
                </div>
              ) : (
                <>
                  {messages.map((msg, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={cn("flex gap-2", msg.role === "user" ? "flex-row-reverse" : "flex-row")}
                    >
                      <div className={cn(
                        "w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5",
                        msg.role === "user"
                          ? "bg-[var(--accent)] text-[var(--bg-primary)]"
                          : "bg-[var(--bg-elevated)] text-[var(--accent)]"
                      )}>
                        {msg.role === "user" ? <User className="w-3 h-3" /> : <Bot className="w-3 h-3" />}
                      </div>
                      <div className={cn(
                        "max-w-[82%] px-3 py-2 rounded-xl text-xs leading-relaxed",
                        msg.role === "user"
                          ? "bg-[var(--accent)] text-[var(--bg-primary)] rounded-tr-sm"
                          : "bg-[var(--bg-card)] text-[var(--text-secondary)] border border-[var(--border)] rounded-tl-sm"
                      )}>
                        <p className="whitespace-pre-wrap">{msg.content}</p>
                        {streaming && i === messages.length - 1 && msg.role === "assistant" && (
                          <span className="inline-block w-1.5 h-3 bg-[var(--accent)] animate-pulse ml-0.5 align-middle" />
                        )}
                        {msg.cached && (
                          <span className="inline-flex items-center gap-0.5 ml-2 text-[9px] text-[var(--accent)] opacity-60">
                            <Zap className="w-2.5 h-2.5" /> cached
                          </span>
                        )}
                      </div>
                    </motion.div>
                  ))}

                  {/* Suggested questions — only when fresh session */}
                  {messages.length === 1 && !streaming && (
                    <div className="space-y-1.5 pt-1">
                      <p className="text-[10px] text-[var(--text-muted)] px-1">Suggested questions:</p>
                      {SUGGESTED.map((q) => (
                        <button
                          key={q}
                          onClick={() => send(q)}
                          className="w-full text-left px-3 py-1.5 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)] text-[10px] text-[var(--text-secondary)] hover:border-[var(--accent)]/40 hover:text-[var(--accent)] transition-colors cursor-pointer"
                        >
                          {q}
                        </button>
                      ))}
                    </div>
                  )}
                </>
              )}
              <div ref={bottomRef} />
            </div>

            {/* Input */}
            <div className="p-3 border-t border-[var(--border)] bg-[var(--bg-card)]">
              <div className="flex items-center gap-2">
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && send()}
                  placeholder="Ask about techniques, IOCs, remediation..."
                  className="flex-1 px-3 py-2 rounded-lg bg-[var(--bg-elevated)] border border-[var(--border)] text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none transition-colors"
                  disabled={streaming || loadingHistory}
                />
                <button
                  onClick={() => streaming ? abortRef.current?.abort() : send()}
                  disabled={loadingHistory}
                  className={cn(
                    "p-2 rounded-lg transition-colors cursor-pointer",
                    streaming
                      ? "bg-[var(--danger)]/20 text-[var(--danger)] hover:bg-[var(--danger)]/30"
                      : input.trim() && !loadingHistory
                        ? "bg-[var(--accent)] text-[var(--bg-primary)] hover:bg-[var(--accent-dim)]"
                        : "bg-[var(--bg-elevated)] text-[var(--text-muted)] cursor-not-allowed"
                  )}
                >
                  <Send className="w-3.5 h-3.5" />
                </button>
              </div>
              <p className="text-[10px] text-[var(--text-muted)] mt-1.5 text-center">
                {user
                  ? `History saved to your account · model cache is shared`
                  : "Sign in to save your conversation history"}
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
