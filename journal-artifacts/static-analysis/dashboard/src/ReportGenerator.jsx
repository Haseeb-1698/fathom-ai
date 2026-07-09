import { useState } from "react";
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000";

export default function ReportGenerator({ record }) {
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  if (!record || !record.sha256) {
    return null;
  }

  const generateReport = async () => {
    setGenerating(true);
    setError(null);
    setSuccess(null);

    try {
      // Generate the PDF report
      const response = await axios.post(`${API_BASE}/api/report/generate/${record.sha256}`);
      const { filename } = response.data;

      // Trigger download
      const downloadUrl = `${API_BASE}/api/report/download/${filename}`;
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setSuccess("Static analysis report generated successfully!");
      
    } catch (err) {
      console.error("Report generation failed:", err);
      const errorMsg = err.response?.data?.detail || "Failed to generate report";
      
      if (err.response?.status === 503) {
        setError("PDF report generation is not available. Please install the required dependencies on the server.");
      } else {
        setError(errorMsg);
      }
    } finally {
      setGenerating(false);
    }
  };

  const getAnalysisType = () => {
    const type = (record?.final_guess?.type || "unknown").toLowerCase();
    switch (type) {
      case "pe": return "Windows PE Static Analysis";
      case "dll": return "Windows DLL Static Analysis";
      case "pdf": return "PDF Document Static Analysis";
      case "office_ooxml": return "Office Document Static Analysis (OOXML)";
      case "office_ole": return "Office Document Static Analysis (OLE)";
      default: return "File Static Analysis";
    }
  };

  const getThreatIndicators = () => {
    const indicators = [];
    const type = (record?.final_guess?.type || "unknown").toLowerCase();
    
    // YARA matches
    const yaraMatches = record?.heuristics?.yara?.matches || [];
    if (yaraMatches.length > 0) {
      indicators.push(`${yaraMatches.length} behavioral signatures`);
    }
    
    // Type-specific indicators
    if (type === "pe" || type === "dll") {
      const pe = record?.static?.pe || {};
      const suspiciousImports = pe?.suspicious_imports || [];
      const highEntropySections = record?.counts?.high_entropy_section_count || 0;
      
      if (suspiciousImports.length > 0) {
        indicators.push(`${suspiciousImports.length} suspicious API imports`);
      }
      if (highEntropySections > 0) {
        indicators.push(`${highEntropySections} high-entropy sections`);
      }
      if (!pe?.signatures?.authenticode?.present) {
        indicators.push("unsigned executable");
      }
    } else if (type === "pdf") {
      const counts = record?.counts || {};
      if (counts.js_objects_total > 0) {
        indicators.push(`${counts.js_objects_total} JavaScript objects`);
      }
      if (counts.auto_actions_total > 0) {
        indicators.push(`${counts.auto_actions_total} auto-actions`);
      }
    } else if (type.includes("office")) {
      const office = record?.static?.office || {};
      const flags = office?.flags || {};
      if (flags.macro_present) {
        indicators.push("VBA macros detected");
      }
      if (flags.suspicious_auto_exec) {
        indicators.push("auto-execution macros");
      }
    }
    
    return indicators;
  };

  const threatIndicators = getThreatIndicators();
  const confidence = record?.confidence || 0;
  const confidenceLevel = record?.confidence_level || "unknown";

  return (
    <div className="card" style={{ marginTop: 20, border: "2px solid #e2e8f0" }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ flex: 1 }}>
          <div className="row" style={{ alignItems: "center", gap: 10, marginBottom: 8 }}>
            <span className="badge" style={{ backgroundColor: "#2d3748", color: "white" }}>
              Static Analysis Report
            </span>
            <span className="pill pill-muted">Professional Documentation</span>
          </div>
          
          <h3 style={{ margin: "0 0 12px 0", color: "#2d3748", fontSize: "18px" }}>
            {getAnalysisType()}
          </h3>
          
          <div style={{ marginBottom: 16 }}>
            <div className="grid" style={{ gap: 8, fontSize: "13px" }}>
              <div className="kv">
                <label>Sample Hash</label>
                <code style={{ fontSize: "11px" }}>{record.sha256}</code>
              </div>
              <div className="kv">
                <label>Analysis Confidence</label>
                <code>{confidence}% ({confidenceLevel})</code>
              </div>
              <div className="kv">
                <label>Threat Indicators</label>
                <code>{threatIndicators.length > 0 ? threatIndicators.length : "None detected"}</code>
              </div>
            </div>
          </div>

          {threatIndicators.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <strong style={{ fontSize: "13px", color: "#744210" }}>Key Findings:</strong>
              <ul style={{ 
                margin: "4px 0 0 0", 
                paddingLeft: 18, 
                fontSize: "12px", 
                color: "#744210",
                maxHeight: "120px",
                overflowY: "auto"
              }}>
                {threatIndicators.map((indicator, i) => (
                  <li key={i}>{indicator}</li>
                ))}
              </ul>
            </div>
          )}

          <div style={{ fontSize: "12px", color: "#4a5568", lineHeight: "1.4" }}>
            <strong>Report Contents:</strong> File metadata, structural analysis, behavioral indicators, 
            IOC extraction, entropy analysis, signature matching, threat assessment, and technical recommendations.
          </div>
        </div>
        
        <div style={{ marginLeft: 20 }}>
          <button 
            className="btn" 
            onClick={generateReport}
            disabled={generating}
            style={{ 
              minWidth: "160px",
              backgroundColor: generating ? "#a0aec0" : "#2d3748",
              color: "white",
              fontWeight: "600"
            }}
          >
            {generating ? "Generating Report..." : "Generate Static Report"}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ 
          marginTop: 16, 
          padding: 12, 
          backgroundColor: "#fed7d7", 
          border: "1px solid #fc8181", 
          borderRadius: 4,
          color: "#742a2a",
          fontSize: "13px"
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {success && (
        <div style={{ 
          marginTop: 16, 
          padding: 12, 
          backgroundColor: "#c6f6d5", 
          border: "1px solid #68d391", 
          borderRadius: 4,
          color: "#22543d",
          fontSize: "13px"
        }}>
          <strong>Success:</strong> {success}
        </div>
      )}

      <div className="hr" style={{ margin: "16px 0 12px 0" }} />

      <div style={{ fontSize: "11px", color: "#718096" }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <span>
            <strong>Format:</strong> Professional PDF • <strong>Classification:</strong> Static Analysis • <strong>Standard:</strong> Industry Best Practices
          </span>
          <span>
            Fathom Static Analysis Engine v1.0
          </span>
        </div>
      </div>
    </div>
  );
}