import { useState, useEffect } from 'react';

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

export default function OfficeExtractor({ record }) {
  const [extracting, setExtracting] = useState(false);
  const [extractionResult, setExtractionResult] = useState(null);
  const [error, setError] = useState(null);
  const [autoExtracted, setAutoExtracted] = useState(false);

  const sha256 = record?.sha256;
  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isOffice = finalType.includes('office') || ['docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt'].some(ext => finalType.includes(ext));

  // Auto-extract macros when component loads
  useEffect(() => {
    if (isOffice && sha256 && !autoExtracted && !extracting && !extractionResult) {
      setAutoExtracted(true);
      handleExtraction();
    }
  }, [isOffice, sha256, autoExtracted, extracting, extractionResult]);

  if (!isOffice) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <div className="badge" style={{ marginBottom: 16 }}>Office Macro Extractor</div>
        <h3 style={{ color: 'var(--ink-4)', margin: '0 0 8px 0' }}>
          Not an Office Document
        </h3>
        <p style={{ color: 'var(--ink-4)', margin: 0 }}>
          Macro extraction is only available for Office documents (DOC, DOCX, XLS, XLSX, PPT, PPTX).
        </p>
      </div>
    );
  }

  const handleExtraction = async () => {
    if (!sha256) {
      setError('No SHA256 hash available');
      return;
    }

    setExtracting(true);
    setError(null);

    try {
      const response = await fetch(`http://127.0.0.1:8000/api/extract/office/${sha256}`, {
        method: 'POST'
      });

      if (response.ok) {
        const result = await response.json();
        setExtractionResult(result);
      } else {
        const errorText = await response.text();
        setError(`Extraction failed: ${errorText}`);
      }
    } catch (err) {
      setError(`Network error: ${err.message}`);
    } finally {
      setExtracting(false);
    }
  };

  const downloadMacro = async (fileType, filename) => {
    try {
      const response = await fetch(`http://127.0.0.1:8000/api/extract/office/${sha256}/download/${fileType}/${filename}`);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        alert('Download failed');
      }
    } catch (err) {
      alert(`Download error: ${err.message}`);
    }
  };





  return (
    <div className="card" style={{ marginTop: 16 }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div className="badge" style={{ backgroundColor: "#2d3748", color: "white" }}>
          Office Macro Analysis
        </div>
        {extracting && (
          <div className="row" style={{ gap: 8, alignItems: "center" }}>
            <span style={{ fontSize: "12px", color: "#4a5568" }}>Analyzing macros...</span>
            <div style={{ 
              width: "16px", 
              height: "16px", 
              border: "2px solid #e2e8f0", 
              borderTop: "2px solid #3182ce", 
              borderRadius: "50%", 
              animation: "spin 1s linear infinite" 
            }}></div>
          </div>
        )}
      </div>

      {/* Add CSS for spinner animation */}
      <style jsx>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
      `}</style>

      {error && (
        <div style={{ 
          marginTop: 16, 
          padding: 12, 
          backgroundColor: '#fed7d7', 
          borderRadius: 4,
          color: '#742a2a'
        }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Show initial extraction status */}
      {!extractionResult && !error && !extracting && (
        <div style={{ 
          marginTop: 16, 
          padding: 12, 
          backgroundColor: '#f7fafc', 
          borderRadius: 4,
          color: '#000000',
          textAlign: 'center'
        }}>
          <div style={{ fontSize: "13px" }}>
            🔍 Automatic macro extraction will begin shortly...
          </div>
        </div>
      )}

      {extractionResult && (
        <div style={{ marginTop: 16 }}>
          {/* Extraction Summary */}
          <div className="card">
            <div className="row" style={{ gap: 10, alignItems: 'center' }}>
              <span className="badge">Extraction Summary</span>
              <span className={`pill ${extractionResult.extraction_success ? 'pill-green' : 'pill-muted'}`}>
                {extractionResult.extraction_success ? 'Success' : 'No Macros Found'}
              </span>
            </div>
            
            <div className="grid" style={{ marginTop: 12, gap: 6, fontSize: '12px' }}>
              <KV label="Total Macros" value={extractionResult.summary?.total_macros || 0} />
              <KV label="Autoexec Macros" value={extractionResult.summary?.autoexec_macros || 0} />
              <KV label="Complex Macros" value={extractionResult.summary?.suspicious_macros || 0} />
              <KV label="Encoded Macros" value={extractionResult.summary?.obfuscated_macros || 0} />
              <KV label="Document Type" value={extractionResult.summary?.document_type || 'unknown'} />
              <KV label="Extraction Time" value={`${extractionResult.summary?.extraction_time || 0}s`} />
            </div>
          </div>

          {/* Extracted Macros */}
          {extractionResult.extracted_content?.macros?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <div className="row" style={{ alignItems: "center", gap: 8, marginBottom: 12 }}>
                <strong style={{ fontSize: "13px", color: "#2d3748" }}>
                  🔧 VBA Macros ({extractionResult.extracted_content.macros.length})
                </strong>
              </div>

              <div style={{ 
                maxHeight: "400px",
                overflowY: "auto"
              }}>
                {extractionResult.extracted_content.macros.map((macro, i) => {
                  return (
                    <div key={i} className="card" style={{ marginBottom: 12 }}>
                      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                        <div className="row" style={{ gap: 8, alignItems: "center" }}>
                          <strong style={{ fontSize: "12px" }}>
                            📄 {macro.module_name || `Macro ${i + 1}`}
                          </strong>
                          <span className="pill pill-hint" style={{ fontSize: "10px" }}>
                            {macro.size} bytes
                          </span>
                        </div>
                        
                        <button 
                          className="btn ghost small"
                          onClick={() => downloadMacro('macros', macro.filename)}
                          style={{ fontSize: "11px" }}
                        >
                          Download
                        </button>
                      </div>

                      <div className="grid" style={{ marginTop: 8, gap: 4, fontSize: "11px" }}>
                        <div className="kv">
                          <label>SHA256</label>
                          <code style={{ fontSize: "10px" }}>{macro.sha256?.substring(0, 16)}...</code>
                        </div>
                        <div className="kv">
                          <label>Extraction Method</label>
                          <code>{macro.extraction_method}</code>
                        </div>
                      </div>

                      {/* Analysis Results */}
                      {(macro.autoexec_indicators?.length > 0 || 
                        macro.suspicious_indicators?.length > 0 || 
                        macro.obfuscation_indicators?.length > 0) && (
                        <div style={{ marginTop: 8 }}>
                          <strong style={{ fontSize: "11px", color: "#4a5568" }}>Analysis Results:</strong>
                          
                          {macro.autoexec_indicators?.length > 0 && (
                            <div style={{ marginTop: 4 }}>
                              <span style={{ fontSize: "10px", color: "#4a5568", fontWeight: "600" }}>
                                Auto-execution: 
                              </span>
                              <span style={{ fontSize: "10px", marginLeft: 4 }}>
                                {macro.autoexec_indicators.slice(0, 3).join(', ')}
                                {macro.autoexec_indicators.length > 3 && ` (+${macro.autoexec_indicators.length - 3} more)`}
                              </span>
                            </div>
                          )}
                          
                          {macro.suspicious_indicators?.length > 0 && (
                            <div style={{ marginTop: 4 }}>
                              <span style={{ fontSize: "10px", color: "#4a5568", fontWeight: "600" }}>
                                API Calls: 
                              </span>
                              <span style={{ fontSize: "10px", marginLeft: 4 }}>
                                {macro.suspicious_indicators.slice(0, 3).join(', ')}
                                {macro.suspicious_indicators.length > 3 && ` (+${macro.suspicious_indicators.length - 3} more)`}
                              </span>
                            </div>
                          )}
                          
                          {macro.obfuscation_indicators?.length > 0 && (
                            <div style={{ marginTop: 4 }}>
                              <span style={{ fontSize: "10px", color: "#4a5568", fontWeight: "600" }}>
                                Encoding: 
                              </span>
                              <span style={{ fontSize: "10px", marginLeft: 4 }}>
                                {macro.obfuscation_indicators.slice(0, 2).join(', ')}
                                {macro.obfuscation_indicators.length > 2 && ` (+${macro.obfuscation_indicators.length - 2} more)`}
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Code Preview */}
                      {macro.code_preview && (
                        <div style={{ marginTop: 8 }}>
                          <strong style={{ fontSize: "11px", color: "#4a5568" }}>Code Preview:</strong>
                          <pre style={{
                            marginTop: 4,
                            padding: 8,
                            backgroundColor: "#f7fafc",
                            borderRadius: 4,
                            fontSize: "10px",
                            fontFamily: "monospace",
                            maxHeight: "150px",
                            overflowY: "auto",
                            color: "#000000"
                          }}>
                            {macro.code_preview}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Extraction Errors */}
          {extractionResult.summary?.errors?.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <strong style={{ fontSize: "12px", color: "#e53e3e" }}>Extraction Warnings:</strong>
              <div style={{ 
                marginTop: 4,
                maxHeight: "120px",
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
  );
}