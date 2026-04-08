"use client";

import { useState, useCallback, useRef, useMemo, useEffect } from "react";
import dynamic from "next/dynamic";
import { motion, AnimatePresence } from "framer-motion";
import {
  Network,
  Search,
  ZoomIn,
  ZoomOut,
  Maximize2,
  X,
  Filter,
  Eye,
  EyeOff,
  FileCode,
  Bug,
  Crosshair,
  Radar,
  Users,
  Layers,
  Info,
  Loader2,
} from "lucide-react";
import { cn, getSeverityColor } from "@/lib/utils";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-full">
      <div className="text-xs text-[var(--text-muted)]">Loading graph...</div>
    </div>
  ),
});

// ── Node Types ───────────────────────────────────────────

const NODE_TYPES = {
  file: { color: "#00D4AA", icon: "F", label: "File" },
  behavior: { color: "#F59E0B", icon: "B", label: "Behavior" },
  ioc: { color: "#EF4444", icon: "I", label: "IOC" },
  technique: { color: "#7C3AED", icon: "T", label: "Technique" },
  actor: { color: "#EC4899", icon: "A", label: "Actor" },
  campaign: { color: "#3B82F6", icon: "C", label: "Campaign" },
} as const;

type NodeType = keyof typeof NODE_TYPES;

interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  severity?: string;
  properties?: Record<string, string>;
}

interface GraphLink {
  source: string;
  target: string;
  label: string;
  weight?: number;
}

// ── Mock Graph Data ──────────────────────────────────────

const MOCK_NODES: GraphNode[] = [
  { id: "file-1", label: "email_attachment.exe", type: "file", severity: "critical", properties: { sha256: "a1b2c3...7890", size: "245.7 KB", type: "PE32" } },
  { id: "beh-1", label: "Process Injection", type: "behavior", severity: "critical", properties: { api: "VirtualAllocEx", target: "explorer.exe" } },
  { id: "beh-2", label: "Registry Persistence", type: "behavior", severity: "high", properties: { key: "HKLM\\...\\Run\\svchost_update" } },
  { id: "beh-3", label: "Anti-Debug Check", type: "behavior", severity: "medium", properties: { api: "IsDebuggerPresent" } },
  { id: "beh-4", label: "C2 Communication", type: "behavior", severity: "critical", properties: { protocol: "HTTPS", port: "443" } },
  { id: "ioc-1", label: "update-service.malware-c2.xyz", type: "ioc", severity: "critical", properties: { type: "domain" } },
  { id: "ioc-2", label: "185.220.101.42", type: "ioc", severity: "critical", properties: { type: "ip", geo: "Netherlands" } },
  { id: "ioc-3", label: "Global\\{A1B2C3D4-E5F6}", type: "ioc", severity: "high", properties: { type: "mutex" } },
  { id: "ioc-4", label: "svchost_update.exe", type: "ioc", severity: "medium", properties: { type: "file" } },
  { id: "tech-1", label: "T1055.001 - DLL Injection", type: "technique", properties: { tactic: "Defense Evasion" } },
  { id: "tech-2", label: "T1547.001 - Run Keys", type: "technique", properties: { tactic: "Persistence" } },
  { id: "tech-3", label: "T1497.001 - Sandbox Evasion", type: "technique", properties: { tactic: "Defense Evasion" } },
  { id: "tech-4", label: "T1071.001 - Web Protocols", type: "technique", properties: { tactic: "C2" } },
  { id: "actor-1", label: "Cobalt Strike", type: "actor", properties: { confidence: "high", category: "Commercial RAT" } },
  { id: "campaign-1", label: "Email Phishing Wave Q1-2026", type: "campaign", properties: { status: "Active", firstSeen: "2026-01" } },
];

const MOCK_LINKS: GraphLink[] = [
  { source: "file-1", target: "beh-1", label: "executes", weight: 3 },
  { source: "file-1", target: "beh-2", label: "creates", weight: 2 },
  { source: "file-1", target: "beh-3", label: "checks", weight: 1 },
  { source: "file-1", target: "beh-4", label: "establishes", weight: 3 },
  { source: "beh-1", target: "tech-1", label: "maps_to", weight: 2 },
  { source: "beh-2", target: "tech-2", label: "maps_to", weight: 2 },
  { source: "beh-3", target: "tech-3", label: "maps_to", weight: 1 },
  { source: "beh-4", target: "tech-4", label: "maps_to", weight: 2 },
  { source: "beh-4", target: "ioc-1", label: "contacts", weight: 3 },
  { source: "beh-4", target: "ioc-2", label: "resolves_to", weight: 3 },
  { source: "beh-1", target: "ioc-4", label: "drops", weight: 2 },
  { source: "file-1", target: "ioc-3", label: "creates_mutex", weight: 1 },
  { source: "file-1", target: "actor-1", label: "attributed_to", weight: 2 },
  { source: "actor-1", target: "campaign-1", label: "part_of", weight: 2 },
  { source: "ioc-1", target: "campaign-1", label: "associated_with", weight: 1 },
];

export default function GraphPage() {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const graphRef = useRef<any>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [visibleTypes, setVisibleTypes] = useState<Set<NodeType>>(
    new Set(Object.keys(NODE_TYPES) as NodeType[])
  );
  const [nodes, setNodes] = useState<GraphNode[]>(MOCK_NODES);
  const [links, setLinks] = useState<GraphLink[]>(MOCK_LINKS);
  const [loadingGraph, setLoadingGraph] = useState(false);

  // Try to load real graph data for the last analyzed sample
  useEffect(() => {
    const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://134.199.201.243:7860";
    const stored = (() => {
      try { return JSON.parse(sessionStorage.getItem("fathom_last_analysis") || "null"); }
      catch { return null; }
    })();

    if (!stored?.graph_id) {
      // No real data — keep mock nodes for demo purposes
      return;
    }

    setLoadingGraph(true);
    fetch(`${API_URL}/api/graph`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query_name: "sample_graph", sample_hash: stored.graph_id }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.nodes?.length > 0) {
          const mappedNodes: GraphNode[] = data.nodes.map((n: any) => ({
            id: String(n.id),
            label: n.properties?.name || n.properties?.value || n.properties?.technique_id || String(n.id),
            type: (n.labels?.[0]?.toLowerCase() as NodeType) in NODE_TYPES
              ? (n.labels[0].toLowerCase() as NodeType)
              : "file",
            properties: n.properties,
          }));
          const mappedLinks: GraphLink[] = data.edges.map((e: any) => ({
            source: String(e.source),
            target: String(e.target),
            label: e.type || "related",
          }));
          setNodes(mappedNodes);
          setLinks(mappedLinks);
        }
        // If no nodes returned, keep mock data — graph is still useful for demo
      })
      .catch(() => { /* keep mock data on error */ })
      .finally(() => setLoadingGraph(false));
  }, []);

  // Track container dimensions with ResizeObserver
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      if (width > 0 && height > 0) {
        setDimensions({ width: Math.floor(width), height: Math.floor(height) });
      }
    });
    ro.observe(el);
    // Set initial dimensions
    setDimensions({
      width: Math.floor(el.clientWidth) || 800,
      height: Math.floor(el.clientHeight) || 600,
    });
    return () => ro.disconnect();
  }, []);

  const filteredData = useMemo(() => {
    const filteredNodes = nodes.filter((n) => {
      if (!visibleTypes.has(n.type)) return false;
      if (searchQuery && !n.label.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      return true;
    });
    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredLinks = links.filter(
      (l) => nodeIds.has(l.source as string) && nodeIds.has(l.target as string)
    );
    return { nodes: filteredNodes, links: filteredLinks };
  }, [nodes, links, visibleTypes, searchQuery]);

  const toggleType = (type: NodeType) => {
    setVisibleTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  const nodeCanvasObject = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as GraphNode & { x: number; y: number };
      const config = NODE_TYPES[n.type];
      const radius = n.id === selectedNode?.id ? 10 : 7;
      const fontSize = 10 / globalScale;

      // Glow for selected
      if (n.id === selectedNode?.id) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, radius + 4, 0, 2 * Math.PI);
        ctx.fillStyle = `${config.color}30`;
        ctx.fill();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = config.color;
      ctx.fill();
      ctx.strokeStyle = `${config.color}60`;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Type icon letter
      ctx.font = `bold ${fontSize * 1.2}px monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = "#060a0a";
      ctx.fillText(config.icon, n.x, n.y);

      // Label below
      if (globalScale > 0.7) {
        ctx.font = `${fontSize}px sans-serif`;
        ctx.fillStyle = "#94a3b8";
        ctx.textAlign = "center";
        ctx.fillText(
          n.label.length > 25 ? n.label.slice(0, 25) + "..." : n.label,
          n.x,
          n.y + radius + fontSize + 2
        );
      }
    },
    [selectedNode]
  );

  const linkCanvasObject = useCallback(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const src = link.source;
      const tgt = link.target;
      if (typeof src !== "object" || !src.x) return;

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);
      ctx.strokeStyle = "rgba(100, 116, 139, 0.15)";
      ctx.lineWidth = (link.weight || 1) * 0.5;
      ctx.stroke();

      // Link label
      if (globalScale > 1.2) {
        const mx = (src.x + tgt.x) / 2;
        const my = (src.y + tgt.y) / 2;
        const fontSize = 7 / globalScale;
        ctx.font = `${fontSize}px sans-serif`;
        ctx.fillStyle = "rgba(100, 116, 139, 0.5)";
        ctx.textAlign = "center";
        ctx.fillText(link.label, mx, my);
      }
    },
    []
  );

  return (
    <div className="flex h-[calc(100vh-48px)] relative">
      {/* ── Graph Canvas ──────────────────────────────── */}
      <div ref={containerRef} className="flex-1 bg-[#040608] relative overflow-hidden">
        {loadingGraph && (
          <div className="absolute top-4 right-4 z-10 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-card)]/90 backdrop-blur border border-[var(--border)]">
            <Loader2 className="w-3.5 h-3.5 text-[var(--accent)] animate-spin" />
            <span className="text-[10px] text-[var(--text-muted)]">Loading graph data...</span>
          </div>
        )}
        <ForceGraph2D
          ref={graphRef}
          graphData={filteredData}
          nodeId="id"
          nodeCanvasObject={nodeCanvasObject}
          linkCanvasObject={linkCanvasObject}
          onNodeClick={(node: any) => setSelectedNode(node as GraphNode)}
          onBackgroundClick={() => setSelectedNode(null)}
          backgroundColor="#040608"
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={0.8}
          d3AlphaDecay={0.02}
          d3VelocityDecay={0.3}
          cooldownTicks={100}
          width={dimensions.width}
          height={dimensions.height}
        />

        {/* Controls Overlay */}
        <div className="absolute top-4 left-4 flex flex-col gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search nodes..."
              className="pl-8 pr-3 py-2 w-56 rounded-lg bg-[var(--bg-card)]/90 backdrop-blur border border-[var(--border)] text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none transition-colors"
            />
          </div>

          {/* Type Filters */}
          <div className="flex flex-wrap gap-1">
            {(Object.entries(NODE_TYPES) as [NodeType, (typeof NODE_TYPES)[NodeType]][]).map(
              ([type, config]) => (
                <button
                  key={type}
                  onClick={() => toggleType(type)}
                  className={cn(
                    "flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium transition-all cursor-pointer border",
                    visibleTypes.has(type)
                      ? "bg-[var(--bg-card)]/90 border-[var(--border)] backdrop-blur"
                      : "bg-transparent border-transparent opacity-40"
                  )}
                  style={{ color: config.color }}
                >
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: config.color }}
                  />
                  {config.label}
                </button>
              )
            )}
          </div>
        </div>

        {/* Zoom Controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-1">
          <button
            onClick={() => graphRef.current?.zoom(2, 300)}
            className="p-2 rounded-lg bg-[var(--bg-card)]/90 backdrop-blur border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => graphRef.current?.zoom(0.5, 300)}
            className="p-2 rounded-lg bg-[var(--bg-card)]/90 backdrop-blur border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={() => graphRef.current?.zoomToFit(400)}
            className="p-2 rounded-lg bg-[var(--bg-card)]/90 backdrop-blur border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        {/* Stats Overlay */}
        <div className="absolute bottom-4 left-4 flex items-center gap-3 px-3 py-1.5 rounded-lg bg-[var(--bg-card)]/80 backdrop-blur border border-[var(--border)]">
          <span className="text-[10px] text-[var(--text-muted)]">
            <span className="text-[var(--text-secondary)] font-mono">{filteredData.nodes.length}</span> nodes
          </span>
          <span className="text-[10px] text-[var(--text-muted)]">
            <span className="text-[var(--text-secondary)] font-mono">{filteredData.links.length}</span> edges
          </span>
        </div>
      </div>

      {/* ── Node Detail Panel ─────────────────────────── */}
      <AnimatePresence>
        {selectedNode && (
          <motion.div
            className="w-80 border-l border-[var(--border)] bg-[var(--bg-surface)] overflow-y-auto flex-shrink-0"
            initial={{ x: 320, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 320, opacity: 0 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
          >
            {/* Panel Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border)]">
              <div className="flex items-center gap-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: NODE_TYPES[selectedNode.type].color }}
                />
                <span className="text-xs font-semibold text-[var(--text-secondary)] uppercase">
                  {NODE_TYPES[selectedNode.type].label}
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded hover:bg-[var(--bg-card)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Node Info */}
            <div className="p-4 space-y-4">
              <div>
                <p className="text-sm font-mono font-medium text-[var(--text-primary)] break-all">
                  {selectedNode.label}
                </p>
                {selectedNode.severity && (
                  <span
                    className="inline-flex items-center gap-1 mt-1.5 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase"
                    style={{
                      backgroundColor: `${getSeverityColor(selectedNode.severity)}15`,
                      color: getSeverityColor(selectedNode.severity),
                    }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ backgroundColor: getSeverityColor(selectedNode.severity) }}
                    />
                    {selectedNode.severity}
                  </span>
                )}
              </div>

              {/* Properties */}
              {selectedNode.properties && (
                <div>
                  <h4 className="text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-2">
                    Properties
                  </h4>
                  <div className="space-y-1.5">
                    {Object.entries(selectedNode.properties).map(([key, val]) => (
                      <div
                        key={key}
                        className="flex items-center justify-between py-1.5 px-2 rounded bg-[var(--bg-card)] border border-[var(--border)]"
                      >
                        <span className="text-[10px] text-[var(--text-muted)]">
                          {key}
                        </span>
                        <span className="text-[10px] font-mono text-[var(--text-secondary)]">
                          {val}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Connected Edges */}
              <div>
                <h4 className="text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider mb-2">
                  Connections
                </h4>
                <div className="space-y-1">
                  {links.filter(
                    (l) =>
                      (l.source as string) === selectedNode.id ||
                      (l.target as string) === selectedNode.id
                  ).map((link, i) => {
                    const isSource = (link.source as string) === selectedNode.id;
                    const otherId = isSource ? (link.target as string) : (link.source as string);
                    const otherNode = nodes.find((n) => n.id === otherId);
                    if (!otherNode) return null;
                    return (
                      <button
                        key={i}
                        onClick={() => setSelectedNode(otherNode)}
                        className="w-full flex items-center gap-2 py-1.5 px-2 rounded bg-[var(--bg-card)] border border-[var(--border)] hover:border-[var(--accent)]/30 transition-colors text-left cursor-pointer"
                      >
                        <span
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: NODE_TYPES[otherNode.type].color }}
                        />
                        <span className="text-[10px] text-[var(--text-secondary)] truncate flex-1">
                          {otherNode.label}
                        </span>
                        <span className="text-[9px] text-[var(--text-muted)] italic flex-shrink-0">
                          {link.label}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
