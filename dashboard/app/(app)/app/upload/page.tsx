"use client";

import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Upload,
  FileJson,
  FileCode,
  Hash,
  ArrowRight,
  X,
  Shield,
  Clock,
  HardDrive,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Fingerprint,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface FileMetadata {
  name: string;
  size: number;
  type: string;
  lastModified: number;
}

export default function UploadPage() {
  const [dragActive, setDragActive] = useState(false);
  const [file, setFile] = useState<FileMetadata | null>(null);
  const [hashInput, setHashInput] = useState("");
  const [analyzing, setAnalyzing] = useState(false);

  const handleDrag = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.type === "dragenter" || e.type === "dragover") {
        setDragActive(true);
      } else if (e.type === "dragleave") {
        setDragActive(false);
      }
    },
    []
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);
      const dropped = e.dataTransfer.files[0];
      if (dropped) {
        setFile({
          name: dropped.name,
          size: dropped.size,
          type: dropped.type || getFileType(dropped.name),
          lastModified: dropped.lastModified,
        });
      }
    },
    []
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files?.[0];
      if (selected) {
        setFile({
          name: selected.name,
          size: selected.size,
          type: selected.type || getFileType(selected.name),
          lastModified: selected.lastModified,
        });
      }
    },
    []
  );

  const handleAnalyze = async () => {
    if (!canAnalyze) return;
    setAnalyzing(true);

    const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://134.199.201.243:7860";

    try {
      let briefId: string | null = null;

      if (file) {
        const input = document.getElementById("app-file-input") as HTMLInputElement;
        const actualFile = input?.files?.[0];
        if (actualFile) {
          // Use shared uploadFile helper
          const { uploadFile, saveUpload } = await import("@/lib/fathom-api");
          const result = await uploadFile(actualFile);
          briefId = result.brief_id;
          saveUpload(result);
        }
      } else if (hashInput.length >= 32) {
        const { saveUpload } = await import("@/lib/fathom-api");
        saveUpload({
          brief_id: hashInput,
          sha256: hashInput,
          file_type: "pe_binary",
          file_name: hashInput.slice(0, 16) + "...",
          file_size: 0,
          ioc_count: 0,
          behavior_count: 0,
        });
        briefId = hashInput;
      }

      window.location.href = `/app/analysis/${briefId || "new"}`;
    } catch (e: any) {
      setAnalyzing(false);
      alert(`Error: ${e.message}`);
    }
  };

  const clearFile = () => {
    setFile(null);
    setAnalyzing(false);
  };

  const canAnalyze =
    (file !== null || hashInput.length >= 32) && !analyzing;

  return (
    <div className="max-w-5xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-xl font-semibold text-[var(--text-primary)] mb-1">
          New Analysis
        </h1>
        <p className="text-sm text-[var(--text-muted)]">
          Submit a CAPE report, PE file, or hash for multi-expert analysis
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ── Left: Drop Zone + Hash Input (2 cols) ─────── */}
        <div className="lg:col-span-2 space-y-4">
          {/* Drop Zone */}
          <motion.div
            className={cn(
              "relative rounded-xl border-2 border-dashed transition-all duration-200 cursor-pointer",
              dragActive
                ? "border-[var(--accent)] bg-[var(--accent-glow)] shadow-[0_0_40px_var(--accent-glow)]"
                : file
                  ? "border-[var(--success)]/40 bg-[var(--success)]/5"
                  : "border-[var(--border)] bg-[var(--bg-card)] hover:border-[var(--text-muted)] hover:bg-[var(--bg-card-hover)]"
            )}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
          >
            <input
              type="file"
              id="app-file-input"
              accept=".json,.exe,.dll,.elf,.pdf,.doc,.docx,.xls,.xlsx,.ps1,.bat,.vbs,.js"
              onChange={handleFileSelect}
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
            />

            <AnimatePresence mode="wait">
              {file ? (
                <motion.div
                  key="file-info"
                  className="p-6"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-lg bg-[var(--success)]/10 text-[var(--success)]">
                        {file.name.endsWith(".json") ? (
                          <FileJson className="w-5 h-5" />
                        ) : (
                          <FileCode className="w-5 h-5" />
                        )}
                      </div>
                      <div>
                        <p className="text-sm font-mono font-medium text-[var(--text-primary)]">
                          {file.name}
                        </p>
                        <div className="flex items-center gap-3 mt-0.5">
                          <span className="text-xs text-[var(--text-muted)] flex items-center gap-1">
                            <HardDrive className="w-3 h-3" />
                            {formatFileSize(file.size)}
                          </span>
                          <span className="text-xs text-[var(--text-muted)] flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(file.lastModified).toLocaleDateString()}
                          </span>
                          <span className="text-xs px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--text-secondary)] font-mono">
                            {getFileType(file.name)}
                          </span>
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.preventDefault();
                        clearFile();
                      }}
                      className="relative z-20 p-1 rounded hover:bg-[var(--bg-elevated)] text-[var(--text-muted)] hover:text-[var(--danger)] transition-colors cursor-pointer"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="drop-prompt"
                  className="py-16 flex flex-col items-center gap-3"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                >
                  <div
                    className={cn(
                      "p-3 rounded-xl transition-colors",
                      dragActive
                        ? "bg-[var(--accent)]/20 text-[var(--accent)]"
                        : "bg-[var(--bg-elevated)] text-[var(--text-muted)]"
                    )}
                  >
                    <Upload className="w-6 h-6" />
                  </div>
                  <div className="text-center">
                    <p className="text-sm text-[var(--text-secondary)]">
                      Drop a file here or{" "}
                      <span className="text-[var(--accent)] font-medium">
                        browse
                      </span>
                    </p>
                    <p className="text-xs text-[var(--text-muted)] mt-1">
                      CAPE report (.json) &middot; PE binary (.exe, .dll) &middot;
                      ELF &middot; Scripts &middot; Documents
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>

          {/* Divider */}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-px bg-[var(--border)]" />
            <span className="text-xs text-[var(--text-muted)] font-medium uppercase tracking-wider">
              or enter hash
            </span>
            <div className="flex-1 h-px bg-[var(--border)]" />
          </div>

          {/* Hash Input */}
          <motion.div
            className="flex items-center gap-2"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.1 }}
          >
            <div className="flex-1 relative">
              <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
              <input
                type="text"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                placeholder="SHA256 or MD5 hash"
                className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-[var(--bg-card)] border border-[var(--border)] text-sm font-mono text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]/30 transition-colors"
              />
            </div>
          </motion.div>

          {/* Analyze Button */}
          <motion.button
            onClick={handleAnalyze}
            disabled={!canAnalyze}
            className={cn(
              "w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-semibold transition-all cursor-pointer",
              canAnalyze
                ? "bg-[var(--accent)] text-[var(--bg-primary)] hover:bg-[var(--accent-dim)] glow-teal"
                : "bg-[var(--bg-elevated)] text-[var(--text-muted)] cursor-not-allowed"
            )}
            whileHover={canAnalyze ? { scale: 1.01 } : {}}
            whileTap={canAnalyze ? { scale: 0.99 } : {}}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.2 }}
          >
            {analyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Run Analysis
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </motion.button>
        </div>

        {/* ── Right: Pipeline Preview + Info (1 col) ──── */}
        <motion.div
          className="space-y-4"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          {/* Pipeline Steps */}
          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
              Analysis Pipeline
            </h3>
            <div className="space-y-2.5">
              {PIPELINE_STEPS.map((step, i) => (
                <div key={i} className="flex items-center gap-2.5">
                  <div
                    className={cn(
                      "w-6 h-6 rounded-md flex items-center justify-center text-[10px] font-bold",
                      analyzing && i === 0
                        ? "bg-[var(--accent)] text-[var(--bg-primary)]"
                        : "bg-[var(--bg-elevated)] text-[var(--text-muted)]"
                    )}
                  >
                    {i + 1}
                  </div>
                  <div className="flex-1">
                    <p className="text-xs font-medium text-[var(--text-secondary)]">
                      {step.name}
                    </p>
                    <p className="text-[10px] text-[var(--text-muted)]">
                      {step.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Supported Formats */}
          <div className="rounded-xl border border-[var(--border)] bg-[var(--bg-card)] p-4">
            <h3 className="text-xs font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
              Supported Formats
            </h3>
            <div className="grid grid-cols-2 gap-1.5">
              {FORMATS.map((fmt) => (
                <div
                  key={fmt.ext}
                  className="flex items-center gap-1.5 text-xs text-[var(--text-muted)]"
                >
                  <span className="w-1 h-1 rounded-full bg-[var(--accent)]" />
                  <span className="font-mono text-[var(--text-secondary)]">
                    {fmt.ext}
                  </span>
                  <span className="text-[10px]">{fmt.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Storage Note */}
          <div className="rounded-xl border border-[var(--accent)]/20 bg-[var(--accent)]/5 p-3 flex items-start gap-2">
            <Shield className="w-3.5 h-3.5 text-[var(--accent)] mt-0.5 flex-shrink-0" />
            <p className="text-[10px] text-[var(--accent)]/80 leading-relaxed">
              Files are stored securely in MinIO object storage (S3-compatible).
              Analysis results are retained for cross-sample correlation and
              future threat intelligence enrichment.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}

// ── Constants ────────────────────────────────────────────

const PIPELINE_STEPS = [
  {
    name: "Evidence Extraction",
    desc: "Parse file structure, extract IOCs",
  },
  {
    name: "Cross-Sample Similarity",
    desc: "FAISS search for related samples",
  },
  {
    name: "Domain Routing",
    desc: "Classify query → select expert adapters",
  },
  {
    name: "Graph Context",
    desc: "Neo4j behavior relationships injected",
  },
  {
    name: "RAG Retrieval",
    desc: "Fetch relevant ATT&CK context",
  },
  {
    name: "Expert Analysis",
    desc: "Run inference through LoRA adapters",
  },
  {
    name: "Report Generation",
    desc: "Aggregate findings into analyst report",
  },
];

const FORMATS = [
  { ext: ".json", label: "CAPE report" },
  { ext: ".exe", label: "PE binary" },
  { ext: ".dll", label: "PE library" },
  { ext: ".elf", label: "Linux binary" },
  { ext: ".pdf", label: "Document" },
  { ext: ".ps1", label: "PowerShell" },
  { ext: ".bat", label: "Batch script" },
  { ext: ".vbs", label: "VBScript" },
];

// ── Helpers ──────────────────────────────────────────────

function getFileType(name: string): string {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  const map: Record<string, string> = {
    json: "CAPE Report",
    exe: "PE Executable",
    dll: "PE Library",
    elf: "ELF Binary",
    pdf: "PDF Document",
    ps1: "PowerShell",
    bat: "Batch Script",
    vbs: "VBScript",
    js: "JavaScript",
  };
  return map[ext] || ext.toUpperCase();
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
