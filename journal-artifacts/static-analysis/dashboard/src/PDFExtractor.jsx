// PDFExtractor.jsx - PDF Content Extraction Interface
// Props: { record }

import { useState } from 'react';
import axios from 'axios';

const API_BASE = "http://127.0.0.1:8000";

export default function PDFExtractor({ record }) {
  const [extracting, setExtracting] = useState(false);
  const [extractionResult, setExtractionResult] = useState(null);
  const [error, setError] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  if (!record || !record.sha256) {
    return null;
  }

  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isPdf = finalType === 'pdf';

  if (!isPdf) {
    return null;
  }

  const extractContent = async () => {
    setExtracting(true);
    setError(null);
    setExtractionResult(null);

    try {
      const response = await axios.post(`${API_BASE}/api/extract/pdf/${record.sha256}`);
      setExtractionResult(response.data);
      setShowDetails(true);
    } catch (err) {
      console.error("Extraction failed:", err);
      const errorMsg = err.response?.data?.detail || "Failed to extract PDF content";
      setError(errorMsg);
    } finally {
      setExtracting(false);
    }
  };

  const downloadFile = async (fileType, filename) => {
    try {
      const response = await axios.get(
        `${API_BASE}/api/extract/pdf/${record.sha256}/download/${fileType}/${filename}`,
        { responseType: 'blob' }
      );
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Download failed:", err);
      alert("Failed to download file: " + (err.response?.data?.detail || err.message));
    }
  };

  const cleanupExtraction = async () => {
    try {
      await axios.delete(`${API_BASE}/api/extract/pdf/${record.sha256}`);
      setExtractionResult(null);
      setShowDetails(false);
    } catch (err) {
      console.error("Cleanup failed:", err);
    }
  };

  const getFileIcon = (filename) => {
    if (filename.endsWith('.js')) return '🔧';
    if (filename.endsWith('.exe')) return '⚙️';
    if (filename.endsWith('.bat')) return '📜';
    if (filename.endsWith('.png') || filename.endsWith('.jpg')) return '🖼️';
    if (filename.endsWith('.ttf') || filename.endsWith('.otf')) return '🔤';
    return '📄';
  };

  const getFileTypeColor = (fileType) => {
    switch (fileType) {
      case 'embedded_files': return '#e53e3e';
      case 'javascript': return '#d69e2e';
      case 'images': return '#38a169';
      case 'fonts': return '#3182ce';
      default: return '#718096';
    }
  };

  return (
    <div className="card" style={{ marginTop: 20, border: "2px solid #e2e8f0" }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ flex: 1 }}>
          <div className="row" style={{ alignItems: "center", gap: 10, marginBottom: 8 }}>
            <span className="badge" style={{ backgroundColor: "#2d3748", color: "white" }}>
              PDF Content Extraction
            </span>
            <span className="pill pill-muted">Forensic Analysis</span>
          </div>
          
          <div style={{ fontSize: "13px", color: "#4a5568", lineHeight: "1.4" }}>
            Extract embedded files, JavaScript, images, and other content from this PDF for detailed analysis.
          </div>
        </div>
        
        <div style={{ marginLeft: 20 }}>
          <button 
            className="btn" 
            onClick={extractContent}
            disabled={extracting}
            style={{ 
              minWidth: "140px",
              backgroundColor: extracting ? "#a0aec0" : "#2d3748",
              color: "white",
              fontWeight: "600"
            }}
          >
            {extracting ? "Extracting..." : "Extract Content"}
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

      {extractionResult && (
        <div style={{ marginTop: 16 }}>
          <div className="hr" style={{ margin: "16px 0" }} />
          
          {/* Extraction Summary */}
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div className="badge">Extraction Results</div>
            <div className="row" style={{ gap: 8 }}>
              <button 
                className="btn ghost small" 
                onClick={() => setShowDetails(!showDetails)}
              >
                {showDetails ? "Hide Details" : "Show Details"}
              </button>
              <button 
                className="btn ghost small" 
                onClick={cleanupExtraction}
                style={{ color: "#e53e3e" }}
              >
                Cleanup
              </button>
            </div>
          </div>

          <div className="grid" style={{ gap: 8, fontSize: "13px", marginBottom: 16 }}>
            <div className="kv">
              <label>Embedded Files</label>
              <code style={{ color: getFileTypeColor('embedded_files') }}>
                {extractionResult.summary?.total_embedded_files || 0}
              </code>
            </div>
            <div className="kv">
              <label>JavaScript Objects</label>
              <code style={{ color: getFileTypeColor('javascript') }}>
                {extractionResult.summary?.total_javascript_objects || 0}
              </code>
            </div>
            <div className="kv">
              <label>Images</label>
              <code style={{ color: getFileTypeColor('images') }}>
                {extractionResult.summary?.total_images || 0}
              </code>
            </div>
            <div className="kv">
              <label>Fonts</label>
              <code style={{ color: getFileTypeColor('fonts') }}>
                {extractionResult.summary?.total_fonts || 0}
              </code>
            </div>
          </div>

          {showDetails && (
            <div>
              {/* Embedded Files */}
              {extractionResult.extracted_content?.embedded_files?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <strong style={{ fontSize: "13px", color: "#e53e3e" }}>
                    🚨 Embedded Files ({extractionResult.extracted_content.embedded_files.length})
                  </strong>
                  <div className="y-list" style={{ marginTop: 8 }}>
                    {extractionResult.extracted_content.embedded_files.map((file, i) => (
                      <div key={i} className="y-item">
                        <div className="y-line">
                          <span className="y-rule">
                            {getFileIcon(file.original_name)} {file.original_name}
                          </span>
                          <button 
                            className="btn ghost small"
                            onClick={() => downloadFile('embedded_files', file.original_name)}
                            style={{ fontSize: "11px" }}
                          >
                            Download
                          </button>
                        </div>
                        <div className="y-meta">
                          <span className="y-cap">Size:</span>
                          <span className="y-val">{file.size} bytes</span>
                          <span className="y-sep">•</span>
                          <span className="y-cap">SHA256:</span>
                          <span className="y-val">{file.sha256}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* JavaScript Objects */}
              {extractionResult.extracted_content?.javascript_objects?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <strong style={{ fontSize: "13px", color: "#d69e2e" }}>
                    🔧 JavaScript Objects ({extractionResult.extracted_content.javascript_objects.length})
                  </strong>
                  <div className="y-list" style={{ marginTop: 8 }}>
                    {extractionResult.extracted_content.javascript_objects.map((js, i) => (
                      <div key={i} className="y-item">
                        <div className="y-line">
                          <span className="y-rule">
                            🔧 {js.type.replace('_', ' ')}
                          </span>
                          <button 
                            className="btn ghost small"
                            onClick={() => {
                              const filename = js.extracted_path.split('/').pop() || js.extracted_path.split('\\').pop();
                              downloadFile('javascript', filename);
                            }}
                            style={{ fontSize: "11px" }}
                          >
                            Download
                          </button>
                        </div>
                        <div className="y-meta">
                          <span className="y-cap">Size:</span>
                          <span className="y-val">{js.size} bytes</span>
                          <span className="y-sep">•</span>
                          <span className="y-cap">Preview:</span>
                          <span className="y-val">{js.preview}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Images */}
              {extractionResult.extracted_content?.images?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <strong style={{ fontSize: "13px", color: "#38a169" }}>
                    🖼️ Images ({extractionResult.extracted_content.images.length})
                  </strong>
                  <div className="y-list" style={{ marginTop: 8 }}>
                    {extractionResult.extracted_content.images.map((img, i) => (
                      <div key={i} className="y-item">
                        <div className="y-line">
                          <span className="y-rule">
                            🖼️ Page {img.page} Image {img.index}
                          </span>
                          <button 
                            className="btn ghost small"
                            onClick={() => {
                              const filename = img.extracted_path.split('/').pop() || img.extracted_path.split('\\').pop();
                              downloadFile('images', filename);
                            }}
                            style={{ fontSize: "11px" }}
                          >
                            Download
                          </button>
                        </div>
                        <div className="y-meta">
                          <span className="y-cap">Size:</span>
                          <span className="y-val">{img.width}x{img.height}</span>
                          <span className="y-sep">•</span>
                          <span className="y-cap">Format:</span>
                          <span className="y-val">{img.colorspace}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Fonts */}
              {extractionResult.extracted_content?.fonts?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <strong style={{ fontSize: "13px", color: "#3182ce" }}>
                    🔤 Fonts ({extractionResult.extracted_content.fonts.length})
                  </strong>
                  <div className="y-list" style={{ 
                    marginTop: 8,
                    maxHeight: "200px",
                    overflowY: "auto"
                  }}>
                    {extractionResult.extracted_content.fonts.map((font, i) => (
                      <div key={i} className="y-item">
                        <div className="y-line">
                          <span className="y-rule">
                            🔤 {font.name}
                          </span>
                          {font.extracted_path && (
                            <button 
                              className="btn ghost small"
                              onClick={() => {
                                const filename = font.extracted_path.split('/').pop() || font.extracted_path.split('\\').pop();
                                downloadFile('fonts', filename);
                              }}
                              style={{ fontSize: "11px" }}
                            >
                              Download
                            </button>
                          )}
                        </div>
                        <div className="y-meta">
                          <span className="y-cap">Type:</span>
                          <span className="y-val">{font.type}</span>
                          <span className="y-sep">•</span>
                          <span className="y-cap">Page:</span>
                          <span className="y-val">{font.page}</span>
                          {font.size && (
                            <>
                              <span className="y-sep">•</span>
                              <span className="y-cap">Size:</span>
                              <span className="y-val">{font.size} bytes</span>
                            </>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Text Content */}
              {extractionResult.extracted_content?.text_content && (
                <div style={{ marginBottom: 16 }}>
                  <strong style={{ fontSize: "13px", color: "#718096" }}>
                    📄 Text Content
                  </strong>
                  <div style={{ 
                    marginTop: 8, 
                    padding: 12, 
                    backgroundColor: "#f7fafc", 
                    borderRadius: 4,
                    fontSize: "12px",
                    fontFamily: "monospace",
                    color: "#000000"
                  }}>
                    {extractionResult.extracted_content.text_content.preview}
                  </div>
                </div>
              )}

              {/* Extraction Errors */}
              {extractionResult.summary?.errors?.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <strong style={{ fontSize: "12px", color: "#e53e3e" }}>Extraction Warnings:</strong>
                  <div style={{ 
                    marginTop: 4,
                    maxHeight: "150px",
                    overflowY: "auto"
                  }}>
                    {extractionResult.summary.errors.map((error, i) => (
                      <div key={i} style={{ 
                        fontSize: "11px", 
                        color: "#742a2a", 
                        backgroundColor: "#fed7d7",
                        padding: "4px 8px",
                        borderRadius: "4px",
                        marginBottom: "4px"
                      }}>
                        {error}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="hr" style={{ margin: "16px 0 12px 0" }} />

      <div style={{ fontSize: "11px", color: "#718096" }}>
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <span>
            <strong>Extraction Engine:</strong> PyMuPDF + peepdf + pdfminer • <strong>Security:</strong> Sandboxed Analysis
          </span>
          <span>
            Fathom PDF Extractor v1.0
          </span>
        </div>
      </div>
    </div>
  );
}