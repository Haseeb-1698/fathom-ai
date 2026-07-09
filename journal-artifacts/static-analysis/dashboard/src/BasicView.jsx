// BasicView.jsx - File identification, YARA hits, and detection reasoning
// Props: { record }

import { useState, useEffect } from 'react';

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

export default function BasicView({ record }) {
  const finalGuess = record?.final_guess || {};
  const heuristics = record?.heuristics || {};
  const yaraResults = heuristics?.yara || {};
  const yaraMatches = Array.isArray(yaraResults?.matches) ? yaraResults.matches : [];
  const signatures = record?.signatures || {};
  const counts = record?.counts || {};
  
  // File identification data
  const fileType = finalGuess?.type || 'unknown';
  const confidence = record?.confidence || 0;
  const confidenceLevel = record?.confidence_level || 'unknown';
  const fileSize = record?.size_bytes || 0;
  const sha256 = record?.sha256 || '';
  const filename = record?.filename || 'unknown';
  
  // Detection reasoning
  const detectionReasons = [];
  
  // Add signature-based reasons
  if (signatures?.magic_bytes) {
    detectionReasons.push(`Magic bytes: ${signatures.magic_bytes}`);
  }
  if (signatures?.file_header) {
    detectionReasons.push(`File header: ${signatures.file_header}`);
  }
  if (signatures?.pe_signature && fileType.includes('pe')) {
    detectionReasons.push('PE signature detected');
  }
  if (signatures?.pdf_signature && fileType === 'pdf') {
    detectionReasons.push('PDF signature detected');
  }
  if (signatures?.office_signature && fileType.includes('office')) {
    detectionReasons.push('Office document signature detected');
  }
  
  // Add heuristic reasons
  if (heuristics?.entropy && heuristics.entropy > 7.0) {
    detectionReasons.push(`High entropy (${heuristics.entropy.toFixed(2)}) suggests compressed/encrypted content`);
  }
  if (heuristics?.file_extension) {
    detectionReasons.push(`File extension: .${heuristics.file_extension}`);
  }
  
  // Format file size
  const formatFileSize = (bytes) => {
    if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(2)} KB`;
    }
    return `${bytes} bytes`;
  };
  
  // Get file type description
  const getFileTypeDescription = (type) => {
    switch (type.toLowerCase()) {
      case 'pe': return 'Windows Portable Executable';
      case 'dll': return 'Windows Dynamic Link Library';
      case 'pdf': return 'Portable Document Format';
      case 'office_ooxml': return 'Office Document (OOXML format)';
      case 'office_ole': return 'Office Document (OLE format)';
      default: return 'Unknown file type';
    }
  };
  
  // Get confidence color
  const getConfidenceColor = (conf) => {
    if (conf >= 90) return '#22543d'; // Green
    if (conf >= 70) return '#744210'; // Orange
    return '#742a2a'; // Red
  };

  return (
    <div style={{ display: 'grid', gap: 16 }}>
      {/* File Identification */}
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="badge">File Identification</div>
          <span style={{ 
            color: getConfidenceColor(confidence),
            fontWeight: '600',
            fontSize: '12px'
          }}>
            {confidence}% confidence
          </span>
        </div>
        
        <div className="grid" style={{ marginTop: 12, gap: 8 }}>
          <KV label="Filename" value={filename} />
          <KV label="File Type" value={getFileTypeDescription(fileType)} />
          <KV label="Type Code" value={fileType.toUpperCase()} />
          <KV label="File Size" value={formatFileSize(fileSize)} />
          <KV label="Confidence Level" value={confidenceLevel} />
          <KV label="SHA256" value={sha256} />
        </div>
      </div>

      {/* Detection Reasoning */}
      <div className="card">
        <div className="badge">Detection Reasoning</div>
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: '13px', color: 'var(--ink-3)' }}>
            Why we identified this as {getFileTypeDescription(fileType)}:
          </strong>
          
          {detectionReasons.length > 0 ? (
            <ul style={{ marginTop: 8, paddingLeft: 18, fontSize: '13px', color: 'var(--ink-4)' }}>
              {detectionReasons.map((reason, i) => (
                <li key={i} style={{ marginBottom: 4 }}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p style={{ marginTop: 8, fontSize: '13px', color: 'var(--ink-4)', fontStyle: 'italic' }}>
              Detection based on basic file analysis
            </p>
          )}
        </div>
      </div>

      {/* YARA Rule Matches */}
      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="badge">YARA Rule Matches</div>
          <span className={`pill ${yaraMatches.length > 0 ? 'pill-strong' : 'pill-muted'}`}>
            {yaraMatches.length} matches
          </span>
        </div>
        
{yaraMatches.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <div className="y-list" style={{
              maxHeight: "300px",
              overflowY: "auto"
            }}>
              {yaraMatches.map((match, i) => {
                const ruleName = match?.rule || 'Unknown Rule';
                const meta = match?.meta || {};
                const description = meta.description || meta.notes || meta.behavior || 'No description available';
                const category = meta.category || meta.type || 'General';
                
                return (
                  <div key={i} className="y-item">
                    <div className="y-line">
                      <span className="y-rule">{ruleName}</span>
                      <span className="pill pill-hint">{category}</span>
                    </div>
                    <div className="y-meta">
                      <span className="y-val">{description}</span>
                    </div>
                    {meta.severity && (
                      <div className="y-meta">
                        <span className="y-cap">Severity:</span>
                        <span className="y-val">{meta.severity}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>



      {/* Analysis Summary */}
      <div className="card" style={{ backgroundColor: '#f7fafc', border: '1px solid #e2e8f0' }}>
        <div className="badge" style={{ backgroundColor: '#4a5568', color: 'white' }}>
          Analysis Summary
        </div>
        <div style={{ marginTop: 12, fontSize: '13px', color: 'var(--ink-4)' }}>
          <div className="grid" style={{ gap: 6 }}>
            <KV label="Detection Status" value={confidence >= 70 ? 'Identified' : 'Uncertain'} />
            <KV label="YARA Matches" value={yaraMatches.length} />
            <KV label="Analysis Engine" value="Fathom Static Analysis" />
            <KV label="Scan Time" value={new Date().toLocaleString()} />
          </div>
          
          <div style={{ marginTop: 12, padding: 8, backgroundColor: 'white', borderRadius: 4, fontSize: '12px', color: '#000000' }}>
            <strong style={{ color: '#000000' }}>Next Steps:</strong> Use the Static Analysis tab to examine detailed file structure, 
            behavior patterns, and security indicators specific to this file type.
          </div>
        </div>
      </div>
    </div>
  );
}