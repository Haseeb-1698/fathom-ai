"use client";

import { motion } from "framer-motion";

// ── Aratek-inspired fingerprint SVG with animated scan line ──
export function FingerprintHero({ className }: { className?: string }) {
  return (
    <div className={`relative ${className || ""}`}>
      {/* Outer glow ring */}
      <motion.div
        className="absolute inset-0 rounded-full"
        style={{
          background: "radial-gradient(circle, rgba(0,212,170,0.15) 0%, transparent 70%)",
        }}
        animate={{ scale: [1, 1.1, 1], opacity: [0.3, 0.6, 0.3] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
      />

      {/* Fingerprint SVG */}
      <svg
        viewBox="0 0 200 200"
        className="w-full h-full"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Concentric fingerprint arcs */}
        {[30, 42, 54, 66, 78, 88].map((r, i) => (
          <motion.ellipse
            key={i}
            cx="100"
            cy="105"
            rx={r}
            ry={r * 1.15}
            stroke="var(--accent)"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeDasharray={`${r * 0.8} ${r * 0.4}`}
            fill="none"
            initial={{ pathLength: 0, opacity: 0 }}
            animate={{ pathLength: 1, opacity: 0.4 + i * 0.1 }}
            transition={{
              pathLength: { duration: 1.5, delay: i * 0.15, ease: "easeInOut" },
              opacity: { duration: 0.8, delay: i * 0.15 },
            }}
          />
        ))}

        {/* Center dot */}
        <motion.circle
          cx="100"
          cy="105"
          r="4"
          fill="var(--accent)"
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.4 }}
        />

        {/* Scan line sweeping across */}
        <motion.line
          x1="20"
          y1="0"
          x2="20"
          y2="200"
          stroke="var(--accent)"
          strokeWidth="2"
          opacity="0.6"
          animate={{ x1: [20, 180, 20], x2: [20, 180, 20] }}
          transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
        />

        {/* Corner brackets (cyber HUD feel) */}
        <motion.path
          d="M 25 25 L 25 45 M 25 25 L 45 25"
          stroke="var(--accent)"
          strokeWidth="2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.6 }}
          transition={{ delay: 0.5 }}
        />
        <motion.path
          d="M 175 25 L 175 45 M 175 25 L 155 25"
          stroke="var(--accent)"
          strokeWidth="2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.6 }}
          transition={{ delay: 0.6 }}
        />
        <motion.path
          d="M 25 175 L 25 155 M 25 175 L 45 175"
          stroke="var(--accent)"
          strokeWidth="2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.6 }}
          transition={{ delay: 0.7 }}
        />
        <motion.path
          d="M 175 175 L 175 155 M 175 175 L 155 175"
          stroke="var(--accent)"
          strokeWidth="2"
          initial={{ opacity: 0 }}
          animate={{ opacity: 0.6 }}
          transition={{ delay: 0.8 }}
        />
      </svg>

      {/* Particle dots around fingerprint */}
      {Array.from({ length: 8 }).map((_, i) => {
        const angle = (i / 8) * Math.PI * 2;
        const radius = 55;
        return (
          <motion.div
            key={i}
            className="absolute w-1 h-1 rounded-full bg-[var(--accent)]"
            style={{
              left: `calc(50% + ${Math.cos(angle) * radius}px)`,
              top: `calc(50% + ${Math.sin(angle) * radius}px)`,
            }}
            animate={{
              opacity: [0, 1, 0],
              scale: [0, 1, 0],
            }}
            transition={{
              duration: 2,
              delay: i * 0.25,
              repeat: Infinity,
              ease: "easeInOut",
            }}
          />
        );
      })}
    </div>
  );
}
