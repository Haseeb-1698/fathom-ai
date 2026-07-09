import { useState, useEffect } from "react";
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000";

export default function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [pdfStatus, setPdfStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch general status
      const statusResponse = await axios.get(`${API_BASE}/api/status`);
      setStatus(statusResponse.data);

      // Fetch detailed PDF status
      const pdfResponse = await axios.get(`${API_BASE}/api/status/pdf`);
      setPdfStatus(pdfResponse.data);

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const testPdfAnalysis = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/test/pdf`);
      alert(`PDF Test Result: ${response.data.message}`);
    } catch (err) {
      alert(`PDF Test Failed: ${err.response?.data?.message || err.message}`);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <div className="badge">System Status</div>
        <p>Loading system status...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="badge">System Status</div>
        <div style={{ color: "#e53e3e", marginTop: 8 }}>
          Error loading status: {error}
        </div>
        <button className="btn" onClick={fetchStatus} style={{ marginTop: 12 }}>
          Retry
        </button>
      </div>
    );
  }

  const getStatusIcon = (available) => available ? "✅" : "❌";
  const getStatusColor = (available) => available ? "#22543d" : "#742a2a";

  return (
    <div style={{ display: "grid", gap: 16 }}>
      {/* Overall System Status */}
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <div className="badge">System Status</div>
          <span style={{ color: "#22543d", fontWeight: "600" }}>
            {status?.status === "healthy" ? "🟢 Healthy" : "🔴 Issues"}
          </span>
        </div>

        <div className="grid" style={{ marginTop: 12, gap: 8 }}>
          <div className="kv">
            <label>Max File Size</label>
            <code>{status?.system?.max_file_size || "64 MB"}</code>
          </div>
          <div className="kv">
            <label>YARA Rules</label>
            <code style={{ color: "#ffffff" }}>
              {getStatusIcon(status?.system?.yara_available)} {status?.system?.yara_available ? "Available" : "Not Available"}
            </code>
          </div>
          <div className="kv">
            <label>Report Generation</label>
            <code style={{ color: "#ffffff" }}>
              {getStatusIcon(status?.report_generation?.available)} {status?.report_generation?.available ? "Available" : "Not Available"}
            </code>
          </div>
        </div>

        {status?.capabilities && (
          <div style={{ marginTop: 12 }}>
            <strong style={{ color: "#ffffff" }}>Supported File Types:</strong>
            <div style={{ marginTop: 4 }}>
              {status.capabilities.file_types.map((type, i) => (
                <span key={i} className="pill pill-muted" style={{ marginRight: 8 }}>
                  {type}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* PDF Analysis Status */}
      <div className="card">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <div className="badge">PDF Analysis Capabilities</div>
          <button className="btn small" onClick={testPdfAnalysis}>
            Test PDF Analysis
          </button>
        </div>

        <div style={{ marginTop: 12 }}>
          <div className="kv">
            <label>Enhanced Analysis</label>
            <code style={{ color: "#ffffff" }}>
              {getStatusIcon(pdfStatus?.enhanced_analysis)} {pdfStatus?.enhanced_analysis ? "Enabled" : "Basic Only"}
            </code>
          </div>
          <div className="kv">
            <label>Libraries Available</label>
            <code>{pdfStatus?.library_count || "Unknown"}</code>
          </div>
        </div>

        {pdfStatus?.libraries && (
          <div style={{ marginTop: 12 }}>
            <strong style={{ color: "#ffffff" }}>PDF Libraries:</strong>
            <div className="grid" style={{ marginTop: 8, gap: 4 }}>
              {Object.entries(pdfStatus.libraries).map(([lib, available]) => (
                <div key={lib} className="kv">
                  <label>{lib}</label>
                  <code style={{ color: "#ffffff" }}>
                    {getStatusIcon(available)} {available ? "Available" : "Missing"}
                  </code>
                </div>
              ))}
            </div>
          </div>
        )}

        {pdfStatus?.recommendations && pdfStatus.recommendations.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <strong style={{ color: "#ffffff" }}>Recommendations:</strong>
            <ul style={{ marginTop: 4, paddingLeft: 18 }}>
              {pdfStatus.recommendations.map((rec, i) => (
                <li key={i} style={{ color: "#ffffff", fontSize: "14px" }}>{rec}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Installation Instructions */}
      {pdfStatus && !pdfStatus.enhanced_analysis && (
        <div className="card" style={{ backgroundColor: "#fef5e7", border: "1px solid #f6ad55" }}>
          <div className="badge" style={{ backgroundColor: "#f6ad55", color: "white" }}>
            Installation Required
          </div>
          <div style={{ marginTop: 8 }}>
            <p style={{ margin: 0, color: "#744210" }}>
              To enable enhanced PDF analysis with professional libraries, run:
            </p>
            <div style={{ 
              marginTop: 8, 
              padding: 8, 
              backgroundColor: "#2d3748", 
              color: "#e2e8f0", 
              fontFamily: "monospace",
              borderRadius: 4,
              fontSize: "13px"
            }}>
              # Windows Command Prompt<br/>
              install_pdf_libs.bat<br/><br/>
              # PowerShell<br/>
              .\install_pdf_libs.ps1<br/><br/>
              # Manual<br/>
              pip install PyMuPDF peepdf-3 PyPDF4 pdfplumber
            </div>
            <p style={{ margin: "8px 0 0 0", color: "#744210", fontSize: "12px" }}>
              After installation, restart your FastAPI server to enable enhanced capabilities.
            </p>
          </div>
        </div>
      )}

      <div style={{ textAlign: "center", marginTop: 8 }}>
        <button className="btn ghost small" onClick={fetchStatus}>
          Refresh Status
        </button>
      </div>
    </div>
  );
}