"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface CyberButtonProps {
  children: React.ReactNode;
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md" | "lg";
  className?: string;
  onClick?: () => void;
  disabled?: boolean;
}

export function CyberButton({
  children,
  variant = "primary",
  size = "md",
  className,
  onClick,
  disabled,
}: CyberButtonProps) {
  const variants = {
    primary: "bg-[var(--accent)] text-[var(--bg-primary)] hover:bg-[var(--accent-dim)] glow-teal",
    secondary: "bg-transparent border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent-glow)]",
    ghost: "bg-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card)]",
  };

  const sizes = {
    sm: "px-3 py-1.5 text-xs",
    md: "px-5 py-2.5 text-sm",
    lg: "px-7 py-3 text-base",
  };

  return (
    <motion.button
      className={cn(
        "rounded-lg font-medium transition-all duration-200 inline-flex items-center gap-2",
        variants[variant],
        sizes[size],
        disabled && "opacity-50 cursor-not-allowed",
        className
      )}
      whileHover={disabled ? {} : { scale: 1.02 }}
      whileTap={disabled ? {} : { scale: 0.98 }}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </motion.button>
  );
}
