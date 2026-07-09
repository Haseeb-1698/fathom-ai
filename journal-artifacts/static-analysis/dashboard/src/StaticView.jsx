// StaticView.jsx - Dynamic PDF + Office static analysis (only shows sections with content)
// Props: { record } from /api/upload or /api/static/*/{sha}

import { useState, useEffect } from 'react';
import ExtractedContent from './ExtractedContent';
import OfficeExtractor from './OfficeExtractor';
import InteractiveVisualizations from './InteractiveVisualizations';

// Helper components
function Section({ title, subtitle, children, show = true }) {
  if (!show) return null;
  
  return (
    <div style={{ marginTop: 12 }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <span className="badge">{title}</span>
      </div>
      {subtitle && (
        <div style={{ marginTop: 4, color: 'var(--ink-4)', fontSize: 12 }}>{subtitle}</div>
      )}
      <div style={{ marginTop: 8 }}>{children}</div>
    </div>
  );
}

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

// Helper function to check if data exists and has meaningful content
function hasContent(data) {
  if (!data) return false;
  if (Array.isArray(data)) return data.length > 0;
  if (typeof data === 'object') return Object.keys(data).length > 0;
  if (typeof data === 'string') return data.trim().length > 0;
  if (typeof data === 'number') return data > 0;
  return Boolean(data);
}

export default function StaticView({ record }) {
  if (!record) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <div className="badge" style={{ marginBottom: 16 }}>Static Analysis</div>
        <h3 style={{ color: 'var(--ink-4)', margin: '0 0 8px 0' }}>
          No Record Data
        </h3>
        <p style={{ color: 'var(--ink-4)', margin: 0 }}>
          No analysis record provided to StaticView component.
        </p>
      </div>
    );
  }

  const counts = record?.counts || {};
  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isPdf = finalType === 'pdf';
  const isOffice = finalType === 'office_ooxml' || finalType === 'office_ole' || !!record?.static?.office;
  const isPe = finalType === 'pe' || finalType === 'dll' || !!record?.static?.pe;
  
  // If no specific file type is detected, show a message
  if (!isPdf && !isOffice && !isPe) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <div className="badge" style={{ marginBottom: 16 }}>Static Analysis</div>
        <h3 style={{ color: 'var(--ink-4)', margin: '0 0 8px 0' }}>
          No Static Analysis Available
        </h3>
        <p style={{ color: 'var(--ink-4)', margin: 0 }}>
          Static analysis is only available for PE/DLL, PDF, and Office files.
          <br />
          Detected file type: <strong>{finalType || 'unknown'}</strong>
        </p>
      </div>
    );
  }

  // Utils
  const formatPdfDate = (s) => {
    if (typeof s !== 'string') return null;
    const m = s.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/);
    if (!m) return s;
    const [_, Y, Mo='01', D='01', H='00', Mi='00', S='00'] = m;
    return `${Y}-${Mo}-${D} ${H}:${Mi}:${S}`;
  };

  const formatIsoLike = (s) => {
    if (typeof s !== 'string') return null;
    try {
      const d = new Date(s);
      if (!isNaN(d.getTime())) return d.toISOString().replace('T',' ').substring(0,19);
    } catch {}
    return s;
  };

  try {
    if (isPdf) {
      return <PDFAnalysisView record={record} counts={counts} />;
    }

    if (isPe) {
      return <PEAnalysisView record={record} counts={counts} />;
    }

    if (isOffice) {
      return <OfficeAnalysisView record={record} counts={counts} />;
    }

    return null;
  } catch (error) {
    console.error('StaticView rendering error:', error);
    return (
      <div className="card" style={{ textAlign: 'center', padding: 32 }}>
        <div className="badge" style={{ marginBottom: 16, backgroundColor: '#e53e3e', color: 'white' }}>
          Static Analysis Error
        </div>
        <h3 style={{ color: 'var(--ink-4)', margin: '0 0 8px 0' }}>
          Rendering Error
        </h3>
        <p style={{ color: 'var(--ink-4)', margin: 0 }}>
          An error occurred while rendering the static analysis.
        </p>
      </div>
    );
  }
}

// PDF Analysis Component
function PDFAnalysisView({ record, counts }) {
  const pdf = record?.static?.pdf || {};
  const anomalies = Array.isArray(pdf?.anomalies) ? pdf.anomalies : [];
  const actions = Array.isArray(pdf?.actions) ? pdf.actions : [];
  const embedded = Array.isArray(pdf?.embedded_files) ? pdf.embedded_files : [];
  const jsPresent = (counts?.js_objects_total ?? 0) > 0;
  const autoActions = (counts?.auto_actions_total ?? 0) > 0;
  const embeddedPresent = (counts?.embedded_files_total ?? 0) > 0;
  const urlsFound = (counts?.ioc_urls_total ?? 0) > 0 || (pdf?.strings?.ioc_urls?.length ?? 0) > 0;
  const suspiciousKeywords = pdf?.strings?.suspicious_keywords?.length > 0;
  const highEntropy = (record?.counts?.high_entropy_stream_count ?? 0) > 0;
  const hasMetadata = pdf?.metadata?.Producer || pdf?.metadata?.Creator || pdf?.metadata?.CreationDate;
  const isEncrypted = pdf?.encryption?.Filter || pdf?.encryption;

  // Only show sections that have content
  const sectionsToShow = [];

  if (hasMetadata) sectionsToShow.push('metadata');
  if (isEncrypted) sectionsToShow.push('encryption');
  if (jsPresent) sectionsToShow.push('javascript');
  if (embeddedPresent) sectionsToShow.push('embedded');
  if (urlsFound) sectionsToShow.push('urls');
  if (suspiciousKeywords) sectionsToShow.push('keywords');
  if (highEntropy) sectionsToShow.push('entropy');
  if (anomalies.length > 0) sectionsToShow.push('anomalies');

  // If no significant content found, document appears standard
  const isClean = sectionsToShow.length === 0 || (sectionsToShow.length === 1 && sectionsToShow[0] === 'metadata');

  return (
    <div className="card" style={{ display: 'grid', gap: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="row" style={{ gap: 10 }}>
          <span className="badge">PDF Static Analysis</span>
          <span className="pill pill-muted">Document Analysis</span>
        </div>
      </div>

      <AnalysisEngineStatus record={record} fileType="PDF" />

      <div className="card">
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <span className="badge">Document Analysis</span>
        </div>
        
        {/* Document Metadata */}
        {hasMetadata && (
          <div className="card" style={{ marginTop: 10 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Document Metadata</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              {pdf?.metadata?.Producer && <KV label="Producer" value={pdf.metadata.Producer} />}
              {pdf?.metadata?.Creator && <KV label="Creator" value={pdf.metadata.Creator} />}
              {pdf?.metadata?.CreationDate && <KV label="Creation Date" value={formatPdfDate(pdf.metadata.CreationDate)} />}
              {pdf?.metadata?.ModDate && <KV label="Modified" value={formatPdfDate(pdf.metadata.ModDate)} />}
              {pdf?.metadata?.Title && <KV label="Title" value={pdf.metadata.Title} />}
              {pdf?.metadata?.Author && <KV label="Author" value={pdf.metadata.Author} />}
            </div>
          </div>
        )}

        {/* Encryption */}
        {isEncrypted && (
          <div className="card" style={{ marginTop: 10 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Encryption Detected</span>
              <span className="pill pill-strong">Security Feature</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Encrypted" value="YES" />
              {pdf?.encryption?.Filter && <KV label="Method" value={pdf.encryption.Filter} />}
              {pdf?.encryption?.P && <KV label="Permissions" value={String(pdf.encryption.P)} />}
              {pdf?.encryption?.V && <KV label="Version" value={String(pdf.encryption.V)} />}
            </div>
          </div>
        )}

        {/* JavaScript Detection */}
        {jsPresent && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">JavaScript Content</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="JS Objects" value={String(counts?.js_objects_total ?? 0)} />
              {autoActions && <KV label="Auto-execution" value="YES" />}
            </div>
          </div>
        )}

        {/* Embedded Files */}
        {embeddedPresent && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Embedded Files Detected</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="File Count" value={String(counts?.embedded_files_total ?? 0)} />
              {embedded.length > 0 && (
                <KV label="File Names" value={embedded.map(f => f.name).join(', ')} />
              )}
            </div>
          </div>
        )}

        {/* Network IOCs */}
        {urlsFound && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Network Indicators</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="URLs Found" value={String(counts?.ioc_urls_total ?? (pdf?.strings?.ioc_urls?.length ?? 0))} />
            </div>
            {Array.isArray(pdf?.strings?.ioc_urls) && pdf.strings.ioc_urls.length > 0 && (
              <div className="y-list" style={{ 
                marginTop: 6,
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {pdf.strings.ioc_urls.map((u, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">🌐 Network Target</span></div>
                    <div className="y-meta"><span className="y-val">{u}</span></div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Keywords */}
        {suspiciousKeywords && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Keywords</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Keywords Found" value={String(pdf.strings.suspicious_keywords.length)} />
            </div>
            <div className="y-list" style={{ marginTop: 6, maxHeight: "150px", overflowY: "auto" }}>
              {pdf.strings.suspicious_keywords.map((kw, i) => (
                <div key={i} className="y-item">
                  <div className="y-line"><span className="y-rule">Keyword</span></div>
                  <div className="y-meta"><span className="y-val">{kw}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* High Entropy Content */}
        {highEntropy && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">High Entropy Content</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="High-entropy streams" value={String(record.counts.high_entropy_stream_count)} />
              <KV label="Total strings" value={String(counts?.strings_total ?? 0)} />
            </div>
            <div style={{ marginTop: 6 }}>
              <span className="pill pill-muted">Possible encrypted or packed content detected</span>
            </div>
          </div>
        )}

        {/* Structural Anomalies */}
        {anomalies.length > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Structural Anomalies</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Anomalies Found" value={String(anomalies.length)} />
            </div>
            <ul style={{ 
              marginTop: 8, 
              paddingLeft: 18,
              maxHeight: "150px",
              overflowY: "auto"
            }}>
              {anomalies.map((a, i) => (
                <li key={i} style={{ color: 'var(--ink-4)', marginBottom: 4 }}>{a}</li>
              ))}
            </ul>
          </div>
        )}


      </div>

      <InteractiveVisualizations 
        key={record?.sha256 || record?.filename || 'pdf-analysis'}
        analysisData={{
          entropy: record?.static?.pdf?.entropy_data,
          structure: record?.static?.pdf?.structure,
          yara: record?.heuristics?.yara,
          timeline: record?.analysis_timeline,
          size: record?.size_bytes,
          fileType: 'pdf',
          filename: record?.filename
        }} 
      />

      <ExtractedContent record={record} />
    </div>
  );
}

// Office Analysis Component
function OfficeAnalysisView({ record, counts }) {
  const office = record?.static?.office || {};
  const meta = office?.metadata || {};
  const strings = office?.strings || {};
  const flags = office?.flags || {};
  const anomalies = Array.isArray(office?.anomalies) ? office.anomalies : [];
  
  const hasMetadata = meta?.Application || meta?.Creator || meta?.LastModifiedBy || meta?.Created || meta?.Modified || meta?.Company;
  const hasMacros = flags?.macro_present;
  const hasShellUsage = flags?.suspicious_shell_usage;
  const hasExternalRefs = (counts?.external_references_total ?? 0) > 0;
  const hasEmbeddedPayloads = (counts?.embedded_payloads_total ?? 0) > 0;
  const hasUrls = Array.isArray(strings?.ioc_urls) && strings.ioc_urls.length > 0;
  const hasSuspiciousKeywords = Array.isArray(strings?.suspicious_keywords) && strings.suspicious_keywords.length > 0;
  const hasHighEntropy = (counts?.high_entropy_embed_count ?? 0) > 0;
  const hasAnomalies = anomalies.length > 0;

  const isClean = !hasMacros && !hasShellUsage && !hasExternalRefs && !hasEmbeddedPayloads && 
                  !hasUrls && !hasSuspiciousKeywords && !hasHighEntropy && !hasAnomalies;

  return (
    <div className="card" style={{ display: 'grid', gap: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="row" style={{ gap: 10 }}>
          <span className="badge">Office Document Static Analysis</span>
          <span className="pill pill-muted">Document Analysis</span>
        </div>
      </div>
      
      <AnalysisEngineStatus record={record} fileType="Office" />
      
      <div className="card">
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <span className="badge">Document Analysis</span>
        </div>
        
        {/* Document Metadata */}
        {hasMetadata && (
          <div className="card" style={{ marginTop: 10 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Document Metadata</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              {meta?.Application && <KV label="Application" value={meta.Application} />}
              {meta?.Creator && <KV label="Creator" value={meta.Creator} />}
              {meta?.LastModifiedBy && <KV label="Last Modified By" value={meta.LastModifiedBy} />}
              {meta?.Created && <KV label="Created" value={formatIsoLike(meta.Created)} />}
              {meta?.Modified && <KV label="Modified" value={formatIsoLike(meta.Modified)} />}
              {meta?.Company && <KV label="Company" value={meta.Company} />}
            </div>
          </div>
        )}

        {/* Macros */}
        {hasMacros && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Macros</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Macro Modules" value={String(counts?.macros_total ?? 0)} />
              {flags?.suspicious_auto_exec && <KV label="Auto-execution" value="YES" />}
              {counts?.autoexec_macros_total > 0 && <KV label="Auto-exec Modules" value={String(counts.autoexec_macros_total)} />}
            </div>
          </div>
        )}

        {/* OS Command Usage */}
        {hasShellUsage && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">OS Command Usage</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Shell Usage" value="YES" />
            </div>
          </div>
        )}

        {/* External References */}
        {hasExternalRefs && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">External References</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="External Links" value={String(counts.external_references_total)} />
            </div>
          </div>
        )}

        {/* Embedded Payloads */}
        {hasEmbeddedPayloads && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Embedded Payloads</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Payloads Found" value={String(counts.embedded_payloads_total)} />
              {(counts?.high_entropy_embed_count ?? 0) > 0 && <KV label="High-entropy" value={String(counts.high_entropy_embed_count)} />}
            </div>
          </div>
        )}

        {/* Network Indicators */}
        {hasUrls && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Network Indicators</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="URLs Found" value={String(strings.ioc_urls.length)} />
            </div>
            <div className="y-list" style={{ marginTop: 6, maxHeight: "150px", overflowY: "auto" }}>
              {strings.ioc_urls.map((u, i) => (
                <div key={i} className="y-item">
                  <div className="y-line"><span className="y-rule">URL</span></div>
                  <div className="y-meta"><span className="y-val">{u}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Keywords */}
        {hasSuspiciousKeywords && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Keywords</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Keywords Found" value={String(strings.suspicious_keywords.length)} />
            </div>
            <div className="y-list" style={{ marginTop: 6, maxHeight: "150px", overflowY: "auto" }}>
              {strings.suspicious_keywords.map((k, i) => (
                <div key={i} className="y-item">
                  <div className="y-line"><span className="y-rule">Keyword</span></div>
                  <div className="y-meta"><span className="y-val">{k}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* High Entropy Content */}
        {hasHighEntropy && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">High Entropy Content</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="High-entropy embeds" value={String(counts.high_entropy_embed_count)} />
            </div>
            <div style={{ marginTop: 8, padding: 8, backgroundColor: '#fff5f5', borderRadius: 4, fontSize: '12px' }}>
              High-entropy embedded content detected - possible encrypted or compressed payloads
            </div>
          </div>
        )}

        {/* Structural Anomalies */}
        {hasAnomalies && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Structural Anomalies</span>
              <span className="pill pill-hint">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Anomalies Found" value={String(anomalies.length)} />
            </div>
            <ul style={{ marginTop: 8, paddingLeft: 18, maxHeight: "150px", overflowY: "auto" }}>
              {anomalies.map((a, i) => (
                <li key={i} style={{ color: 'var(--ink-4)', marginBottom: 4 }}>{a}</li>
              ))}
            </ul>
          </div>
        )}


      </div>

      <InteractiveVisualizations 
        key={record?.sha256 || record?.filename || 'office-analysis'}
        analysisData={{
          entropy: record?.static?.office?.entropy_data,
          structure: record?.static?.office?.structure,
          yara: record?.heuristics?.yara,
          timeline: record?.analysis_timeline,
          size: record?.size_bytes,
          fileType: (record?.final_guess?.type || 'office_ooxml').toLowerCase(),
          filename: record?.filename
        }} 
      />

      {/* Office Macro Extraction - Integrated automatically */}
      <OfficeExtractor record={record} />
    </div>
  );
}

// PE Analysis Component (simplified for now)
function PEAnalysisView({ record, counts }) {
  return (
    <div className="card" style={{ display: 'grid', gap: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <div className="row" style={{ gap: 10 }}>
          <span className="badge">PE/DLL Static Analysis</span>
          <span className="pill pill-muted">Executable Analysis</span>
        </div>
      </div>
      
      <AnalysisEngineStatus record={record} fileType="PE" />
      
      <InteractiveVisualizations 
        key={record?.sha256 || record?.filename || 'pe-analysis'}
        analysisData={{
          entropy: record?.static?.pe?.entropy_data,
          structure: record?.static?.pe?.structure,
          yara: record?.heuristics?.yara,
          timeline: record?.analysis_timeline,
          size: record?.size_bytes,
          fileType: (record?.final_guess?.type || 'pe').toLowerCase(),
          filename: record?.filename
        }} 
      />
      
      <div className="card">
        <div style={{ padding: 16, textAlign: 'center', color: 'var(--ink-4)' }}>
          PE analysis view - implementation in progress
        </div>
      </div>
    </div>
  );
}

// Analysis Engine Status Component
function AnalysisEngineStatus({ record, fileType }) {
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSystemStatus = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/status');
        const data = await response.json();
        setSystemStatus(data);
      } catch (error) {
        console.error('Failed to fetch system status:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchSystemStatus();
  }, []);

  if (loading) {
    return (
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="badge">{fileType} Analysis Engine</div>
        <p style={{ margin: "8px 0", color: "var(--ink-4)" }}>Loading engine status...</p>
      </div>
    );
  }

  const getStatusIcon = (available) => available ? "✅" : "❌";
  
  // Get file-type specific information
  const getEngineInfo = () => {
    switch (fileType) {
      case 'PDF':
        return {
          enhanced: systemStatus?.pdf_analysis?.enhanced_available,
          libraries: systemStatus?.pdf_analysis?.libraries || {},
          analysisData: record?.static?.pdf,
          counts: {
            'Objects': record?.counts?.objects_total || 0,
            'Streams': record?.counts?.streams_total || 0,
            'JavaScript': record?.counts?.js_objects_total || 0,
            'Embedded Files': record?.counts?.embedded_files_total || 0,
          }
        };
      case 'PE':
        return {
          enhanced: true,
          libraries: { 'pefile': true, 'yara': systemStatus?.system?.yara_available },
          analysisData: record?.static?.pe,
          counts: {
            'Sections': record?.static?.pe?.sections?.length || 0,
            'Imports': record?.static?.pe?.imports?.length || 0,
            'Suspicious APIs': record?.counts?.suspicious_imports_total || 0,
            'YARA Matches': record?.counts?.yara_matches_total || 0,
          }
        };
      case 'Office':
        return {
          enhanced: systemStatus?.office_analysis?.enhanced_available,
          libraries: systemStatus?.office_analysis?.libraries || {},
          analysisData: record?.static?.office,
          counts: {
            'Macros': record?.counts?.macros_total || 0,
            'Auto-exec Macros': record?.counts?.autoexec_macros_total || 0,
            'Suspicious Macros': record?.counts?.suspicious_macros_total || 0,
            'Embedded Objects': record?.counts?.embedded_objects_total || 0,
            'External Refs': record?.counts?.external_references_total || 0,
          }
        };
      default:
        return { enhanced: false, libraries: {}, analysisData: null, counts: {} };
    }
  };

  const engineInfo = getEngineInfo();
  const engineErrors = record?.errors?.filter(e => 
    e.toLowerCase().includes(fileType.toLowerCase()) || 
    e.includes('analysis') || 
    e.includes('error')
  ) || [];

  return (
    <div className="card" style={{ marginBottom: 16, border: "1px solid #e2e8f0" }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div className="badge">{fileType} Analysis Engine Status</div>
        <span style={{ 
          color: engineInfo.enhanced ? "#22543d" : "#744210",
          fontSize: "12px",
          fontWeight: "600"
        }}>
          {engineInfo.enhanced ? "🚀 Enhanced Mode" : "⚡ Basic Mode"}
        </span>
      </div>

      <div className="grid" style={{ marginTop: 12, gap: 8, fontSize: "13px" }}>
        <div className="kv">
          <label>Analysis Engine</label>
          <code>{engineInfo.enhanced ? `${fileType} Enhanced Parser` : `${fileType} Basic Parser`}</code>
        </div>
        <div className="kv">
          <label>Detection Confidence</label>
          <code>{record?.confidence || 0}% ({record?.confidence_level || 'unknown'})</code>
        </div>
        <div className="kv">
          <label>Analysis Status</label>
          <code style={{ color: engineErrors.length > 0 ? "#e53e3e" : "#22543d" }}>
            {engineErrors.length > 0 ? `${engineErrors.length} warnings` : "Clean"}
          </code>
        </div>
      </div>

      {/* Available Libraries - only show if we have libraries */}
      {Object.keys(engineInfo.libraries).length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Engine Libraries:</strong>
          <div className="row" style={{ marginTop: 6, gap: 8, flexWrap: "wrap" }}>
            {Object.entries(engineInfo.libraries).map(([lib, available]) => (
              <span 
                key={lib}
                className="pill"
                style={{ 
                  fontSize: "11px",
                  backgroundColor: available ? "#c6f6d5" : "#fed7d7",
                  color: available ? "#22543d" : "#742a2a",
                  border: `1px solid ${available ? "#68d391" : "#fc8181"}`
                }}
              >
                {getStatusIcon(available)} {lib}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Analysis Results Summary - only show if we have meaningful counts */}
      {Object.values(engineInfo.counts).some(count => count > 0) && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Analysis Results:</strong>
          <div className="grid" style={{ marginTop: 6, gap: 4, fontSize: "12px" }}>
            {Object.entries(engineInfo.counts).map(([label, count]) => {
              if (count === 0) return null; // Only show non-zero counts
              return (
                <div key={label} className="kv">
                  <label>{label}</label>
                  <code style={{ 
                    color: (label.includes('JavaScript') || label.includes('Suspicious') || label.includes('YARA')) && count > 0 
                      ? "#e53e3e" : "inherit" 
                  }}>
                    {count}
                  </code>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Show any engine-specific errors - only if they exist */}
      {engineErrors.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "#e53e3e" }}>Analysis Warnings:</strong>
          <div style={{ 
            marginTop: 4,
            maxHeight: "120px",
            overflowY: "auto"
          }}>
            {engineErrors.map((error, i) => (
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
  );
}

// Helper function to format dates
function formatIsoLike(s) {
  if (typeof s !== 'string') return null;
  try {
    const d = new Date(s);
    if (!isNaN(d.getTime())) return d.toISOString().replace('T',' ').substring(0,19);
  } catch {}
  return s;
}

function formatPdfDate(s) {
  if (typeof s !== 'string') return null;
  const m = s.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/);
  if (!m) return s;
  const [_, Y, Mo='01', D='01', H='00', Mi='00', S='00'] = m;
  return `${Y}-${Mo}-${D} ${H}:${Mi}:${S}`;
}