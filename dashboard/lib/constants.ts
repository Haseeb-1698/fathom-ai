import type { Expert, Dataset, NavItem } from "@/types";

export const NAV_ITEMS: NavItem[] = [
  { label: "Overview", href: "/", icon: "LayoutDashboard" },
  { label: "Analyze", href: "/analyze", icon: "Shield" },
  { label: "Experts", href: "/experts", icon: "Brain" },
  { label: "Datasets", href: "/datasets", icon: "Database" },
  { label: "Training", href: "/training", icon: "Cpu" },
  { label: "Results", href: "/results", icon: "BarChart3" },
  { label: "Graph", href: "/graph", icon: "Network" },
  { label: "Reports", href: "/reports", icon: "FileText" },
];

export const EXPERTS: Expert[] = [
  {
    id: "e1", name: "Static Analysis", domain: "static",
    description: "PE headers, imports, strings, entropy, packing detection",
    icon: "FileCode", color: "#00D4AA", status: "pending",
    datasetRows: 11000, datasetFile: "e1_static.jsonl",
  },
  {
    id: "e2", name: "Dynamic Analysis", domain: "dynamic",
    description: "Sandbox behavior, API calls, process trees, registry changes",
    icon: "Play", color: "#7C3AED", status: "pending",
    datasetRows: 11594, datasetFile: "e2_dynamic.jsonl",
  },
  {
    id: "e3", name: "Network Analysis", domain: "network",
    description: "C2 traffic, DNS patterns, protocol anomalies, packet analysis",
    icon: "Wifi", color: "#3B82F6", status: "pending",
    datasetRows: 19991, datasetFile: "e3_network.jsonl",
  },
  {
    id: "e4", name: "Digital Forensics", domain: "forensics",
    description: "Memory forensics, disk artifacts, timeline analysis, evidence handling",
    icon: "Search", color: "#F59E0B", status: "pending",
    datasetRows: 19183, datasetFile: "e4_forensics.jsonl",
  },
  {
    id: "e5", name: "Threat Intelligence", domain: "threatintel",
    description: "IOC correlation, threat actor profiling, campaign tracking, OSINT",
    icon: "Globe", color: "#EF4444", status: "pending",
    datasetRows: 12327, datasetFile: "e5_threatintel.jsonl",
  },
  {
    id: "e6", name: "Detection Engineering", domain: "detection",
    description: "YARA/Sigma rules, detection logic, alert triage, false positive analysis",
    icon: "ShieldAlert", color: "#EC4899", status: "pending",
    datasetRows: 19986, datasetFile: "e6_detection.jsonl",
  },
  {
    id: "e7", name: "Report Writing", domain: "reports",
    description: "Malware reports, executive summaries, technical writeups, IOC documentation",
    icon: "FileText", color: "#8B5CF6", status: "pending",
    datasetRows: 94063, datasetFile: "e7_reports.jsonl",
  },
  {
    id: "e8", name: "SOC Analyst", domain: "analyst",
    description: "Incident response, alert triage, playbook execution, threat hunting",
    icon: "MonitorCheck", color: "#14B8A6", status: "pending",
    datasetRows: 19504, datasetFile: "e8_analyst.jsonl",
  },
];

export const DATASETS: Dataset[] = [
  {
    id: "unified", name: "Unified v2 (Augmented)", file: "v2_unified_augmented.jsonl",
    rows: 123912, size: "~450MB", location: "processed", status: "ready",
    source: "Multi-source aggregation", description: "Base fine-tuning dataset with augmented malware analysis conversations",
  },
  {
    id: "e1", name: "E1 Static", file: "e1_static.jsonl", rows: 11000,
    size: "8.7MB", location: "experts", expertId: "e1", status: "ready",
    source: "EMBER2024 + PowerShell corpus", description: "PE analysis, packing detection, import table analysis",
  },
  {
    id: "e2", name: "E2 Dynamic", file: "e2_dynamic.jsonl", rows: 8881,
    size: "~30MB", location: "processed", expertId: "e2", status: "ready",
    source: "CAPE sandbox reports", description: "Sandbox behavioral analysis, API traces, process trees",
  },
  {
    id: "e3", name: "E3 Network", file: "e3_network.jsonl", rows: 19991,
    size: "~25MB", location: "experts", expertId: "e3", status: "ready",
    source: "CTU-13 + CICIDS + DNS + topup_v2", description: "Network traffic analysis, C2 detection, DNS anomalies",
  },
  {
    id: "e4", name: "E4 Forensics", file: "e4_forensics.jsonl", rows: 19183,
    size: "~24MB", location: "experts", expertId: "e4", status: "ready",
    source: "OSSEM + Sigma + MFSecInstruct + topup_v2", description: "Memory forensics, disk artifacts, timeline reconstruction",
  },
  {
    id: "e5", name: "E5 ThreatIntel", file: "e5_threatintel.jsonl", rows: 12327,
    size: "~40MB", location: "processed", expertId: "e5", status: "ready",
    source: "MITRE ATT&CK + CTI reports", description: "Threat actor profiles, IOC correlation, campaign analysis",
  },
  {
    id: "e5_aug", name: "E5 ThreatIntel Aug", file: "e5_threatintel_aug.jsonl", rows: 832,
    size: "~2MB", location: "experts", expertId: "e5", status: "ready",
    source: "OTX + MalwareBazaar", description: "Supplemental threat intelligence from live feeds",
  },
  {
    id: "e6", name: "E6 Detection", file: "e6_detection.jsonl", rows: 19986,
    size: "~28MB", location: "experts", expertId: "e6", status: "ready",
    source: "Sigma + YARA + NIST + topup_v2", description: "Detection rule writing and analysis",
  },
  {
    id: "e7", name: "E7 Reports", file: "e7_reports.jsonl", rows: 94063,
    size: "~300MB", location: "processed", expertId: "e7", status: "ready",
    source: "Malware report corpus", description: "Technical report writing and executive summaries",
  },
  {
    id: "e8", name: "E8 Analyst", file: "e8_analyst.jsonl", rows: 19504,
    size: "~26MB", location: "experts", expertId: "e8", status: "ready",
    source: "SOC playbooks + ShareGPT + CTI QA + topup_v2", description: "SOC workflow, alert triage, incident response",
  },
  {
    id: "cape", name: "CAPE Reports", file: "cape_hf_reports.jsonl", rows: 2713,
    size: "~8MB", location: "experts", status: "ready",
    source: "unileon-robotics/malware-samples", description: "CAPE sandbox JSON reports converted to training data",
  },
  {
    id: "cti", name: "CTI Supplement", file: "cti_supplement.jsonl", rows: 104240,
    size: "~350MB", location: "experts", status: "ready",
    source: "Multi-source CTI aggregation", description: "Supplemental cyber threat intelligence corpus",
  },
];

export const TRAINING_ORDER = [
  "unified", "e2", "e7", "e5", "e1", "e3", "e4", "e6", "e8",
];

export const MODEL_CONFIG = {
  base: "Qwen/Qwen2.5-7B-Instruct",
  method: "LoRA",
  rank: 32,
  alpha: 64,
  quantization: "4-bit (bitsandbytes)",
  flashAttn: "fa2",
  precision: "bf16",
  framework: "LlamaFactory",
  targetGpu: "AMD MI300X 192GB",
};
