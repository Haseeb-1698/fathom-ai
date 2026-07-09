import { useCallback, useMemo, useState } from "react";
import { useDropzone } from "react-dropzone";
import axios from "axios";
import YaraMatches from "./YaraMatches";
import YaraExplain from "./YaraExplain";
import StaticView from "./StaticView";
import StaticMiniSummary from "./StaticMiniSummary";
import ReportGenerator from "./ReportGenerator";
import SystemStatus from "./SystemStatus";
import BasicView from "./BasicView";
import DynamicView from "./DynamicView";
import LoadingAnimation from "./LoadingAnimation";
import BugCompanion from "./BugCompanion";


const API_BASE = "http://127.0.0.1:8000"; // change if needed

export default function UploadPanel({ onResult }) {
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState("basic"); // "basic" | "advanced" | "yara" | "static" | "dynamic" | "status"
  const [loading, setLoading] = useState(false);
  const [showLoadingAnimation, setShowLoadingAnimation] = useState(false);
  const [fname, setFname] = useState("");

  const onDrop = useCallback(
    async (accepted) => {
      if (accepted.length === 0) return;
      const file = accepted[0];
      setFname(file.name);

      const fd = new FormData();
      fd.append("file", file);

      try {
        setLoading(true);
        setShowLoadingAnimation(true);
        
        // Start the API call
        const apiCall = axios.post(`${API_BASE}/api/upload`, fd, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        
        // Wait for the API call to complete
        const res = await apiCall;
        
        // Don't hide loading animation immediately - let it complete its 20-second cycle
        // The LoadingAnimation component will call onLoadingComplete when done
        setResult(res.data);
        onResult?.(res.data);
        setActiveTab("basic");
      } catch (e) {
        setShowLoadingAnimation(false);
        setLoading(false);
        alert("Upload failed: " + (e?.message || "Unknown error"));
      }
    },
    [onResult]
  );

  const handleLoadingComplete = useCallback(() => {
    setShowLoadingAnimation(false);
    setLoading(false);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });

  const yaraMatchesTop = Array.isArray(result?.heuristics?.yara?.matches) ? result.heuristics.yara.matches : [];
  const finalType = (result?.final_guess?.type || "").toLowerCase();
  const isPdf = finalType === "pdf";
  const isOffice = finalType === "office_ooxml" || finalType === "office_ole" || !!result?.static?.office;
  const isPe = finalType === "pe" || finalType === "dll" || !!result?.static?.pe;
  const isStaticSupported = isPdf || isOffice || isPe;

  const basic = useMemo(() => {
    if (!result) return null;

    const guess = result?.final_guess || {};
    const type = guess?.type || "unknown";
    const reasons = Array.isArray(guess?.reasons) ? guess.reasons : [];
    const sha256 = result?.sha256 || "";
    const size = result?.size_bytes;
    const yaraMatches = yaraMatchesTop;
    const conf = result?.confidence;
    const confLevel = result?.confidence_level;
    const confClass = confLevel === "high" ? "pill-conf-high" : confLevel === "medium" ? "pill-conf-med" : "pill-conf-low";
    const confTitle = "Confidence is computed from: +45 magic/header, +45 structural probe, +10 extension match, +8 each YARA strong, +2 each YARA hint, -10 extension mismatch, +5 macro flag.";
    const pdfSig = result?.signatures?.pdf;
    const oox = result?.signatures?.office_ooxml;
    const ole = result?.signatures?.office_ole;
    const macros = Boolean(oox?.has_vba_project || ole?.has_vba_project);
    const encrypted = Boolean(pdfSig?.is_encrypted || oox?.has_encryption);
    const entropy = result?.heuristics?.entropy;

    const humanSize = typeof size === "number" ? formatBytes(size) : "—";
    const label = typeLabel(type);

    return (
      <div className="card">
        <div
          className="row"
          style={{ justifyContent: "space-between", alignItems: "center" }}
        >
          <div className="row" style={{ gap: 12, alignItems: "center" }}>
            <span className="badge">{label}</span>
            {result?.route && <span className="badge">Route: {result.route}</span>}
            {typeof conf === "number" && (
              <span className={`pill ${confClass}`} title={confTitle}>confidence: {conf}{confLevel ? ` (${confLevel})` : ""}</span>
            )}
            {macros && <span className="pill pill-strong">macros detected</span>}
            {encrypted && <span className="pill pill-hint">encrypted</span>}
          </div>
          <span style={{ color: "#0a3e0a", fontWeight: 700 }}>
            {fname || result?.filename || ""}
          </span>
        </div>

        <div className="hr" />

        <div className="grid">
          <div className="kv">
            <label>SHA-256</label>
            <code style={{ wordBreak: "break-all" }}>{sha256 || "—"}</code>
          </div>
          <div className="kv">
            <label>Size</label>
            <code>{humanSize}</code>
          </div>
          <div className="kv">
            <label>Detected</label>
            <code>{label}</code>
          </div>
          <div className="kv">
            <label>Scanned</label>
            <code>{result?.scanned_at || "—"}</code>
          </div>
          {typeof conf === "number" && (
            <div className="kv">
              <label>Confidence</label>
              <code title={confTitle}>{conf}{confLevel ? ` (${confLevel})` : ""}</code>
            </div>
          )}
        </div>

        {reasons?.length > 0 && (
          <>
            <div className="hr" />
            <div>
              <strong>Why we think so</strong>
              <div style={{ display: "grid", gap: 8, marginTop: 8 }}>
                {reasons.map((r, i) => (
                  <div className="reason" key={i}>
                    {r}
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        {/* --- YARA section (only shows when matches exist) --- */}
        {yaraMatches.length > 0 && (
          <>
            <div className="hr" />
            <YaraMatches matches={yaraMatches} />
          </>
        )}

        {/* --- Entropy (PE/DLL only) --- */}
        {entropy && (typeof entropy.overall === "number" || typeof entropy.max_section === "number") && (
          <>
            <div className="hr" />
            <div className="section">
              <div className="y-head">
                <span className="pill pill-muted">Entropy</span>
              </div>
              <div className="grid">
                {typeof entropy.overall === "number" && (
                  <div className="kv"><label>Overall</label><code>{entropy.overall.toFixed(2)}</code></div>
                )}
                {typeof entropy.max_section === "number" && (
                  <div className="kv"><label>Max section</label><code>{entropy.max_section.toFixed(2)}</code></div>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    );
  }, [result, fname, yaraMatchesTop]);

  const advanced = useMemo(() => {
    if (!result) return null;

    const jsonStr = JSON.stringify(result, null, 2);

    const copy = async () => {
      try {
        await navigator.clipboard.writeText(jsonStr);
      } catch {}
    };

    const download = () => {
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const sha = result?.sha256 || "report";
      a.href = url;
      a.download = `${sha}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    };

    return (
      <div className="card">
        <div
          className="row"
          style={{ justifyContent: "space-between", alignItems: "center" }}
        >
          <div className="row" style={{ gap: 10 }}>
            <span className="badge">Full JSON logs</span>
            {result?.sha256 && <code>sha256:{result.sha256}</code>}
          </div>
          <div className="row">
            <button className="btn small" onClick={copy}>
              Copy
            </button>
            <button className="btn ghost small" onClick={download}>
              Download
            </button>
          </div>
        </div>
        <div className="jsonbox">
          <pre style={{ margin: 0 }}>{jsonStr}</pre>
        </div>
      </div>
    );
  }, [result]);

  const yaraExplain = useMemo(() => {
    if (!result) return null;
    return <YaraExplain matches={yaraMatchesTop} />;
  }, [result, yaraMatchesTop]);

  return (
    <>
      {/* Professional Loading Animation */}
      <LoadingAnimation 
        isVisible={showLoadingAnimation} 
        onComplete={handleLoadingComplete}
      />

      {/* Cute Bug Companion */}
      <BugCompanion 
        fileType={result?.final_guess?.type} 
        isVisible={!!result && !showLoadingAnimation}
      />

      {/* Upload */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div {...getRootProps()} className="dropzone">
          <input {...getInputProps()} />
          <div className="drop-icon">📁 Drag & drop a file here, or click to select</div>
          <p>
            {isDragActive
              ? "Release to upload…"
              : "Advanced file analysis with AI-powered threat detection"}
          </p>
        </div>
        {loading && !showLoadingAnimation && (
          <p style={{ marginTop: 10, color: "#ffffff", fontWeight: 700 }}>
            Preparing analysis...
          </p>
        )}
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button
          className={`tab ${activeTab === "basic" ? "active" : ""}`}
          onClick={() => setActiveTab("basic")}
          disabled={!result}
        >
          Basic
        </button>
        <button
          className={`tab ${activeTab === "advanced" ? "active" : ""}`}
          onClick={() => setActiveTab("advanced")}
          disabled={!result}
        >
          Advanced (JSON)
        </button>
        <button
          className={`tab ${activeTab === "yara" ? "active" : ""}`}
          onClick={() => setActiveTab("yara")}
          disabled={!result || (yaraMatchesTop?.length || 0) === 0}
        >
          YARA Explain
        </button>
        <button
          className={`tab ${activeTab === "static" ? "active" : ""}`}
          onClick={() => setActiveTab("static")}
          disabled={!result || !isStaticSupported}
          title={!isStaticSupported ? "Static view available for PDFs & Office" : undefined}
        >
          Static
        </button>
        <button
          className={`tab ${activeTab === "dynamic" ? "active" : ""}`}
          onClick={() => setActiveTab("dynamic")}
          disabled={!result}
        >
          Dynamic
        </button>

        <button
          className={`tab ${activeTab === "status" ? "active" : ""}`}
          onClick={() => setActiveTab("status")}
        >
          Status
        </button>
      </div>

      {/* Panels */}
      {!result && (
        <div className="card" style={{ marginTop: 12 }}>
          <span className="badge">No file analyzed yet</span>
          <p style={{ marginTop: 8, color: "#333" }}>
            Upload a sample to see the summary here. The Advanced tab will show raw JSON logs.
          </p>
        </div>
      )}

      {result && activeTab === "basic" && (
        <div style={{ marginTop: 12 }}>
          <BasicView record={result} />
        </div>
      )}
      {result && activeTab === "advanced" && <div style={{ marginTop: 12 }}>{advanced}</div>}
      {result && activeTab === "yara" && <div style={{ marginTop: 12 }}>{yaraExplain}</div>}
      {result && activeTab === "static" && (
        <div style={{ marginTop: 12 }}>
          <StaticView record={result} />
          {/* Professional Static Analysis Report Generator */}
          <ReportGenerator record={result} />
        </div>
      )}
      {result && activeTab === "dynamic" && (
        <div style={{ marginTop: 12 }}>
          <DynamicView record={result} />
        </div>
      )}

      {activeTab === "status" && (
        <div style={{ marginTop: 12 }}>
          <SystemStatus />
        </div>
      )}
    </>
  );
}

/* Helpers */
function formatBytes(bytes) {
  if (bytes === 0 || !Number.isFinite(bytes)) return "0 B";
  const k = 1024,
    dm = 1,
    sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

function typeLabel(t) {
  switch ((t || "").toLowerCase()) {
    case "pe":
      return "Windows PE (EXE)";
    case "dll":
      return "Windows DLL";
    case "pdf":
      return "PDF";
    case "office_ooxml":
      return "Office (OOXML)";
    case "office_ole":
      return "Office (OLE/CFB)";
    case "zip":
      return "ZIP/Container";
    case "unknown":
    default:
      return "Unknown";
  }
}
