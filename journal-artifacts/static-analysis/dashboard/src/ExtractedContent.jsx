// ExtractedContent.jsx - Automatically display extracted PDF content
// Props: { record }

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

export default function ExtractedContent({ record }) {
  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isPdf = finalType === 'pdf';

  if (!isPdf) {
    return null;
  }

  const pdf = record?.static?.pdf || {};
  const extractedContent = pdf?.extracted_content || {};
  const embeddedFiles = extractedContent?.embedded_files || [];
  const javascriptObjects = extractedContent?.javascript_objects || [];

  // If no extracted content, don't show the section
  if (embeddedFiles.length === 0 && javascriptObjects.length === 0) {
    return null;
  }

  const getFileIcon = (filename, fileType) => {
    if (fileType === "PE/EXE") return '⚙️';
    if (fileType === "Batch Script") return '📜';
    if (fileType === "Script") return '🔧';
    if (fileType === "ZIP/Office") return '📦';
    if (fileType === "PDF") return '📄';
    if (fileType === "JPEG" || fileType === "PNG") return '🖼️';
    if (filename?.endsWith('.exe')) return '⚙️';
    if (filename?.endsWith('.bat') || filename?.endsWith('.cmd')) return '📜';
    if (filename?.endsWith('.js') || filename?.endsWith('.vbs')) return '🔧';
    return '📄';
  };

  const getFileTypeColor = (fileType) => {
    switch (fileType) {
      case 'PE/EXE': return '#e53e3e';
      case 'Batch Script': return '#d69e2e';
      case 'Script': return '#d69e2e';
      case 'ZIP/Office': return '#3182ce';
      case 'PDF': return '#38a169';
      case 'JPEG':
      case 'PNG': return '#38a169';
      default: return '#718096';
    }
  };

  const formatBytes = (bytes) => {
    if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${bytes} bytes`;
  };

  // Remove truncation - show full content with scrollable containers

  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div className="badge" style={{ backgroundColor: "#2d3748", color: "white" }}>
          Extracted Content
        </div>
        <span className="pill pill-muted">
          {embeddedFiles.length + javascriptObjects.length} items
        </span>
      </div>

      {/* Embedded Files */}
      {embeddedFiles.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div className="row" style={{ alignItems: "center", gap: 8, marginBottom: 12 }}>
            <strong style={{ fontSize: "13px", color: "#e53e3e" }}>
              🚨 Embedded Files ({embeddedFiles.length})
            </strong>
          </div>
          
          <div className="y-list">
            {embeddedFiles.map((file, i) => (
              <div key={i} className="y-item">
                <div className="y-line">
                  <span className="y-rule">
                    {getFileIcon(file.name, file.file_type)} {file.name}
                  </span>
                  <span 
                    className="pill pill-hint" 
                    style={{ 
                      backgroundColor: getFileTypeColor(file.file_type),
                      color: "white",
                      fontSize: "10px"
                    }}
                  >
                    {file.file_type || "Unknown"}
                  </span>
                </div>
                
                <div className="y-meta">
                  <span className="y-cap">Size:</span>
                  <span className="y-val">{formatBytes(file.size || 0)}</span>
                  {file.sha256 && (
                    <>
                      <span className="y-sep">•</span>
                      <span className="y-cap">SHA256:</span>
                      <span className="y-val">{file.sha256}</span>
                    </>
                  )}
                </div>

                {/* Show content preview for text files */}
                {file.content_preview && (
                  <div style={{ 
                    marginTop: 8, 
                    padding: 8, 
                    backgroundColor: "#f7fafc", 
                    borderRadius: 4,
                    fontSize: "11px",
                    fontFamily: "monospace",
                    border: "1px solid #e2e8f0"
                  }}>
                    <strong style={{ fontSize: "10px", color: "#000000" }}>Content Preview:</strong>
                    <pre style={{ 
                      margin: "4px 0 0 0", 
                      whiteSpace: "pre-wrap", 
                      wordBreak: "break-word",
                      color: "#000000"
                    }}>
                      <div style={{ 
                        maxHeight: "200px",
                        overflowY: "auto",
                        color: "#000000"
                      }}>
                        {file.content_preview}
                      </div>
                    </pre>
                  </div>
                )}

                {/* Show hex preview for binary files */}
                {file.raw_content && !file.content_preview && (
                  <div style={{ 
                    marginTop: 8, 
                    padding: 8, 
                    backgroundColor: "#f7fafc", 
                    borderRadius: 4,
                    fontSize: "11px",
                    fontFamily: "monospace",
                    border: "1px solid #e2e8f0"
                  }}>
                    <strong style={{ fontSize: "10px", color: "#000000" }}>Hex Preview:</strong>
                    <div style={{ 
                      margin: "4px 0 0 0", 
                      color: "#000000",
                      wordBreak: "break-all"
                    }}>
                      <div style={{ 
                        maxHeight: "100px",
                        overflowY: "auto",
                        fontSize: "11px",
                        color: "#000000"
                      }}>
                        {Array.from(file.raw_content, byte => 
                          byte.toString(16).padStart(2, '0')
                        ).join(' ')}
                      </div>
                    </div>
                  </div>
                )}

                {file.extraction_error && (
                  <div style={{ 
                    marginTop: 8, 
                    padding: 6, 
                    backgroundColor: "#fed7d7", 
                    borderRadius: 4,
                    fontSize: "11px",
                    color: "#000000"
                  }}>
                    <strong style={{ color: "#000000" }}>Extraction Error:</strong> {file.extraction_error}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* JavaScript Objects */}
      {javascriptObjects.length > 0 && (
        <div style={{ marginTop: embeddedFiles.length > 0 ? 24 : 16 }}>
          <div className="row" style={{ alignItems: "center", gap: 8, marginBottom: 12 }}>
            <strong style={{ fontSize: "13px", color: "#d69e2e" }}>
              🔧 JavaScript Objects ({javascriptObjects.length})
            </strong>
          </div>
          
          <div className="y-list">
            {javascriptObjects.map((js, i) => (
              <div key={i} className="y-item">
                <div className="y-line">
                  <span className="y-rule">
                    🔧 {js.type?.replace('_', ' ') || 'JavaScript'}
                  </span>
                  <span className="pill pill-hint" style={{ fontSize: "10px" }}>
                    {js.type || 'unknown'}
                  </span>
                </div>
                
                {js.name && (
                  <div className="y-meta">
                    <span className="y-cap">Name:</span>
                    <span className="y-val">{js.name}</span>
                  </div>
                )}

                {js.content && (
                  <div style={{ 
                    marginTop: 8, 
                    padding: 8, 
                    backgroundColor: "#fffbeb", 
                    borderRadius: 4,
                    fontSize: "11px",
                    fontFamily: "monospace",
                    border: "1px solid #f6ad55"
                  }}>
                    <strong style={{ fontSize: "10px", color: "#000000" }}>JavaScript Code:</strong>
                    <pre style={{ 
                      margin: "4px 0 0 0", 
                      whiteSpace: "pre-wrap", 
                      wordBreak: "break-word",
                      color: "#000000"
                    }}>
                      <div style={{ 
                        maxHeight: "300px",
                        overflowY: "auto",
                        color: "#000000"
                      }}>
                        {js.content}
                      </div>
                    </pre>
                  </div>
                )}

                {js.reference && (
                  <div className="y-meta">
                    <span className="y-cap">Object Reference:</span>
                    <span className="y-val">{js.reference}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary */}
      <div style={{ 
        marginTop: 16, 
        padding: 12, 
        backgroundColor: "#f7fafc", 
        borderRadius: 4,
        fontSize: "12px",
        color: "#000000"
      }}>
        <strong style={{ color: "#000000" }}>Extraction Summary:</strong> Found {embeddedFiles.length} embedded file(s) and {javascriptObjects.length} JavaScript object(s). 
        Content extracted automatically during PDF analysis using PyMuPDF and enhanced detection algorithms.
      </div>
    </div>
  );
}