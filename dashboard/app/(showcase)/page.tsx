"use client";

import { motion } from "framer-motion";
import { Shield, Database, Brain, Activity, Cpu, Network, Upload, ArrowRight } from "lucide-react";
import { TopBar } from "@/components/layout/top-bar";
import { StatCard } from "@/components/ui/stat-card";
import { CyberButton } from "@/components/ui/cyber-button";
import { FingerprintHero } from "@/components/animations/fingerprint-hero";
import { ParticlesBackground } from "@/components/animations/particles-background";
import { CharacterReveal, StaggerContainer, FadeUp, ScrollReveal } from "@/components/animations/motion-wrapper";
import { ExpertCard } from "@/components/ui/expert-card";
import { EXPERTS } from "@/lib/constants";
import Link from "next/link";

export default function OverviewPage() {
  return (
    <div className="min-h-screen">
      <TopBar title="Overview" />

      {/* ── Hero Section (Aratek-inspired) ──────────────────── */}
      <section className="relative h-[520px] flex items-center overflow-hidden border-b border-[var(--border)]">
        <ParticlesBackground count={50} />

        {/* Cyber grid background */}
        <div className="absolute inset-0 cyber-grid opacity-30" />

        {/* Radial gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[var(--bg-primary)]/50 to-[var(--bg-primary)]" />

        <div className="relative z-10 flex items-center justify-between w-full max-w-6xl mx-auto px-8">
          {/* Left: Text */}
          <div className="flex-1 max-w-xl">
            <motion.div
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[var(--border-accent)] bg-[var(--accent-glow)] mb-6"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <span className="w-2 h-2 rounded-full bg-[var(--accent)] animate-pulse" />
              <span className="text-xs text-[var(--accent)] font-medium">Mixture-of-Experts Framework</span>
            </motion.div>

            <h1 className="text-5xl font-bold leading-tight mb-4">
              <CharacterReveal text="FATHOM" className="gradient-text-teal" delay={0.4} />
              <br />
              <motion.span
                className="text-[var(--text-secondary)] text-3xl font-light"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 1.2 }}
              >
                AI-Powered Malware Analysis
              </motion.span>
            </h1>

            <motion.p
              className="text-[var(--text-muted)] text-base leading-relaxed mb-8 max-w-md"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.4 }}
            >
              8 specialized expert adapters trained on domain-specific cybersecurity data,
              orchestrated by intelligent routing with RAG-enhanced context retrieval.
            </motion.p>

            <motion.div
              className="flex gap-3"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.6 }}
            >
              <Link href="/analyze">
                <CyberButton variant="primary" size="lg">
                  <Upload className="w-4 h-4" />
                  Analyze File
                </CyberButton>
              </Link>
              <Link href="/experts">
                <CyberButton variant="secondary" size="lg">
                  View Experts
                  <ArrowRight className="w-4 h-4" />
                </CyberButton>
              </Link>
            </motion.div>
          </div>

          {/* Right: Fingerprint visualization */}
          <motion.div
            className="w-72 h-72 flex-shrink-0"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.6, duration: 0.8 }}
          >
            <FingerprintHero />
          </motion.div>
        </div>
      </section>

      {/* ── Stats Grid ─────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-8 py-10">
        <div className="grid grid-cols-4 gap-4">
          <StatCard label="Expert Adapters" value="8" icon={<Brain className="w-5 h-5" />} glowColor="var(--accent)" delay={0} />
          <StatCard label="Dataset Rows" value="340K+" icon={<Database className="w-5 h-5" />} glowColor="var(--secondary)" delay={0.1} />
          <StatCard label="RAG Index" value="Active" icon={<Network className="w-5 h-5" />} glowColor="#3B82F6" delay={0.2} />
          <StatCard label="Model" value="Qwen2.5-7B" icon={<Cpu className="w-5 h-5" />} glowColor="#F59E0B" delay={0.3} />
        </div>
      </section>

      {/* ── Expert Grid ────────────────────────────────────── */}
      <ScrollReveal>
        <section className="max-w-6xl mx-auto px-8 pb-10">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-xl font-semibold text-[var(--text-primary)]">Expert Adapters</h2>
              <p className="text-sm text-[var(--text-muted)]">8 domain-specialized LoRA adapters</p>
            </div>
            <Link href="/experts">
              <CyberButton variant="ghost" size="sm">
                View All <ArrowRight className="w-3 h-3" />
              </CyberButton>
            </Link>
          </div>
          <div className="grid grid-cols-4 gap-4">
            {EXPERTS.map((expert, i) => (
              <ExpertCard key={expert.id} expert={expert} index={i} />
            ))}
          </div>
        </section>
      </ScrollReveal>

      {/* ── Architecture Overview ──────────────────────────── */}
      <ScrollReveal>
        <section className="max-w-6xl mx-auto px-8 pb-16">
          <h2 className="text-xl font-semibold text-[var(--text-primary)] mb-6">System Architecture</h2>
          <div className="grid grid-cols-3 gap-4">
            {[
              { title: "Domain Router", desc: "Centroid-based routing selects optimal experts for each query", icon: <Activity className="w-5 h-5" />, color: "var(--accent)" },
              { title: "RAG Pipeline", desc: "FAISS index retrieves relevant context from security knowledge base", icon: <Database className="w-5 h-5" />, color: "var(--secondary)" },
              { title: "Knowledge Graph", desc: "Neo4j stores relationships between IOCs, techniques, and actors", icon: <Network className="w-5 h-5" />, color: "#3B82F6" },
            ].map((item, i) => (
              <motion.div
                key={i}
                className="p-6 rounded-xl border border-[var(--border)] bg-[var(--bg-card)] card-hover"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 * i }}
              >
                <div className="p-2 rounded-lg inline-flex mb-3" style={{ backgroundColor: `${item.color}15`, color: item.color }}>
                  {item.icon}
                </div>
                <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-1">{item.title}</h3>
                <p className="text-xs text-[var(--text-muted)]">{item.desc}</p>
              </motion.div>
            ))}
          </div>
        </section>
      </ScrollReveal>
    </div>
  );
}
