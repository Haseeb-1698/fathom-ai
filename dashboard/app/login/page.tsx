"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Fingerprint, Globe, GitBranch, Loader2, Shield } from "lucide-react";
import { signInWithGoogle, signInWithGithub } from "@/lib/firebase";

export default function LoginPage() {
  const router = useRouter();
  const [loading, setLoading] = useState<"google" | "github" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleGoogle() {
    setLoading("google");
    setError(null);
    try {
      await signInWithGoogle();
      router.push("/app/upload");
    } catch (e: any) {
      if (e.code === "auth/configuration-not-found") {
        setError("Google sign-in is not enabled yet. Enable it in Firebase Console → Authentication → Sign-in method.");
      } else if (e.code === "auth/popup-closed-by-user") {
        setError(null); // user cancelled, not an error
      } else {
        setError(e.message || "Sign-in failed");
      }
    } finally {
      setLoading(null);
    }
  }

  async function handleGithub() {
    setLoading("github");
    setError(null);
    try {
      await signInWithGithub();
      router.push("/app/upload");
    } catch (e: any) {
      if (e.code === "auth/configuration-not-found") {
        setError("GitHub sign-in is not enabled yet. Enable it in Firebase Console → Authentication → Sign-in method.");
      } else if (e.code === "auth/popup-closed-by-user") {
        setError(null);
      } else {
        setError(e.message || "Sign-in failed");
      }
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg-primary)]">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-sm"
      >
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="p-3 rounded-2xl bg-[var(--accent-glow)] border border-[var(--border-accent)] mb-4">
            <Fingerprint className="w-8 h-8 text-[var(--accent)]" strokeWidth={1.5} />
          </div>
          <h1 className="text-2xl font-bold gradient-text-teal">FATHOM</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            AI-Powered Malware Analysis
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--bg-card)] p-6 space-y-4">
          <div className="text-center mb-2">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Sign in to continue
            </h2>
            <p className="text-xs text-[var(--text-muted)] mt-1">
              Your analysis history and chat sessions are saved to your account
            </p>
          </div>

          {/* Google */}
          <button
            onClick={handleGoogle}
            disabled={loading !== null}
            className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] hover:bg-[var(--bg-card-hover)] hover:border-[var(--border-accent)] transition-all text-sm font-medium text-[var(--text-primary)] cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading === "google" ? (
              <Loader2 className="w-4 h-4 animate-spin text-[var(--accent)]" />
            ) : (
              <Globe className="w-4 h-4" />
            )}
            Continue with Google
          </button>

          {/* GitHub */}
          <button
            onClick={handleGithub}
            disabled={loading !== null}
            className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl border border-[var(--border)] bg-[var(--bg-elevated)] hover:bg-[var(--bg-card-hover)] hover:border-[var(--border-accent)] transition-all text-sm font-medium text-[var(--text-primary)] cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading === "github" ? (
              <Loader2 className="w-4 h-4 animate-spin text-[var(--accent)]" />
            ) : (
              <GitBranch className="w-4 h-4" />
            )}
            Continue with GitHub
          </button>

          {error && (
            <p className="text-xs text-[var(--danger)] text-center">{error}</p>
          )}

          {/* Dev bypass — remove before production */}
          {process.env.NODE_ENV === "development" && (
            <button
              onClick={() => router.push("/app/upload")}
              className="w-full py-2 text-[10px] text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors cursor-pointer border border-dashed border-[var(--border)] rounded-lg"
            >
              Skip auth (dev only)
            </button>
          )}

          <div className="flex items-center gap-2 pt-2">
            <Shield className="w-3.5 h-3.5 text-[var(--text-muted)] flex-shrink-0" />
            <p className="text-[10px] text-[var(--text-muted)] leading-relaxed">
              Your files are analyzed in an isolated environment. No data is shared with third parties.
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
