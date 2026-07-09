// StaticView.jsx - PDF + Office static analysis (Basic + Advanced)
// Props: { record } from /api/upload or /api/static/*/{sha}

import { useState, useEffect } from 'react';
import ExtractedContent from './ExtractedContent';
import OfficeExtractor from './OfficeExtractor';

// Helper components defined first
function Section({ title, subtitle, children }) {
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

export default function StaticView({ record }) {
  // Add error boundary and debugging
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
  // Remove truncation functions - show full content with scrollable containers
  const formatPdfDate = (s) => {
    if (typeof s !== 'string') return '—';
    const m = s.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/);
    if (!m) return s;
    const [_, Y, Mo='01', D='01', H='00', Mi='00', S='00'] = m;
    return `${Y}-${Mo}-${D} ${H}:${Mi}:${S}`;
  };
  const formatIsoLike = (s) => {
    if (typeof s !== 'string') return '—';
    try {
      const d = new Date(s);
      if (!isNaN(d.getTime())) return d.toISOString().replace('T',' ').substring(0,19);
    } catch {}
    return s;
  };
  const FALLBACK = "—";

  function safeText(v, fallback = FALLBACK) {
    if (v === null || v === undefined) return fallback;
    if (typeof v === "number") return v.toString();
    if (typeof v === "string") {
      const cleaned = v
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
        .replace(/[^\x20-\x7E\u00A0-\u024F]/g, "");
      if (!cleaned.trim()) return fallback;
      return cleaned;
    }
    return fallback;
  }

  function formatHex(num, fallback = FALLBACK) {
    if (num === null || num === undefined) return fallback;
    if (typeof num !== "number" || !Number.isFinite(num)) return fallback;
    return "0x" + num.toString(16).toUpperCase();
  }

  function yesNo(val) {
    if (val === true) return "YES";
    if (val === false) return "NO";
    return FALLBACK;
  }

  function truncate(str, maxLen = 120) {
    const s = safeText(str, FALLBACK);
    if (s === FALLBACK) return FALLBACK;
    return s.length > maxLen ? s.slice(0, maxLen) + "…" : s;
  }

  function prettySize(bytes) {
    if (bytes === null || bytes === undefined) return FALLBACK;
    if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return FALLBACK;
    if (bytes >= 1024 * 1024) {
      const mb = (bytes / (1024 * 1024)).toFixed(2);
      return `${mb} MB`;
    }
    if (bytes >= 1024) {
      const kb = (bytes / 1024).toFixed(2);
      return `${kb} KB`;
    }
    return `${Math.round(bytes)} B`;
  }

  function computeRisk(pe, counts) {
    const suspicious = (counts?.suspicious_imports_total || 0) > 0;
    const packed = (counts?.high_entropy_section_count || 0) > 0;
    const overlay = pe?.overlay?.present === true;
    const anomaliesCount = Array.isArray(pe?.anomalies) ? pe.anomalies.length : 0;
    if (suspicious && packed && overlay) return "High";
    if (suspicious || packed || overlay || anomaliesCount >= 3) return "Medium";
    return "Low";
  }

  function isUserFacingError(e) {
    if (!e) return false;
    const lower = String(e).toLowerCase();
    if (lower.includes("traceback")) return false;
    if (lower.includes("attributeerror")) return false;
    if (lower.includes("lief_signature_error")) return false;
    return true;
  }

  // PDF data
  const pdf = record?.static?.pdf || {};
  const anomaliesPdf = Array.isArray(pdf?.anomalies) ? pdf.anomalies : [];
  const actions = Array.isArray(pdf?.actions) ? pdf.actions : [];
  const embeddedPdf = Array.isArray(pdf?.embedded_files) ? pdf.embedded_files : [];
  const jsPresent = (counts?.js_objects_total ?? 0) > 0;
  const autoActions = (counts?.auto_actions_total ?? 0) > 0;
  const embeddedPresent = (counts?.embedded_files_total ?? 0) > 0;
  const urlRegex = /https?:\/\/[\w\-\.\/?#%&=:+,@~]+/gi;
  const previews = Array.isArray(pdf?.objects) ? pdf.objects.map((o) => o?.stream?.decoded_preview).filter((s) => typeof s === 'string') : [];
  const urlsSet = new Set();
  for (const p of previews) {
    const m = p.match(urlRegex) || [];
    for (const u of m) { if (urlsSet.size >= 20) break; urlsSet.add(u); }
    if (urlsSet.size >= 20) break;
  }
  const urlSample = Array.from(urlsSet);

  // Office data
  const office = record?.static?.office || {};
  const structure = office?.structure || {};
  const anomaliesOffice = Array.isArray(office?.anomalies) ? office.anomalies : [];
  const macros = Array.isArray(office?.macros) ? office.macros : [];
  const embeds = Array.isArray(office?.embedded_payloads) ? office.embedded_payloads : [];
  const meta = office?.metadata || {};
  const strings = office?.strings || {};
  const entropy = office?.entropy || {};
  const flags = office?.flags || {};

  // Add error handling for rendering
  try {
    if (isPdf) {
      return (
      <div className="card" style={{ display: 'grid', gap: 16 }}>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <div className="row" style={{ gap: 10 }}>
            <span className="badge">PDF Static Analysis</span>
            <span className="pill pill-muted">Document Analysis</span>
          </div>
        </div>

        {/* PDF Analysis Engine Status */}
        <AnalysisEngineStatus record={record} fileType="PDF" />

        <div className="card">
          <div className="row" style={{ gap: 10, alignItems: 'center' }}>
            <span className="badge">Document Analysis</span>
          </div>
          
          {/* Document Metadata - Only show if we have meaningful data */}
          {(pdf?.metadata?.Producer || pdf?.metadata?.Creator || pdf?.metadata?.CreationDate || pdf?.metadata?.ModDate) && (
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

          {/* Encryption - Only show if encrypted */}
          {(pdf?.encryption?.Filter || pdf?.encryption) && (
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

          {/* JavaScript Detection - Only show if JavaScript is present */}
          {jsPresent && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">JavaScript Detected</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="JS Objects" value={String(counts?.js_objects_total ?? 0)} />
                {autoActions && <KV label="Auto-execution" value="YES" />}
                {pdf?.javascript?.objects?.length > 0 && (
                  <KV label="Script Types" value={pdf.javascript.objects.map(js => js.type).join(', ')} />
                )}
              </div>
            </div>
          )}

          {/* Embedded Files - Only show if files are present */}
          {embeddedPresent && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Embedded Files Detected</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="File Count" value={String(counts?.embedded_files_total ?? 0)} />
                {embeddedPdf.length > 0 && (
                  <KV label="File Names" value={embeddedPdf.map(f => f.name).join(', ')} />
                )}
              </div>
            </div>
          )}

          {/* Network IOCs - Only show if URLs are found */}
          {(counts?.ioc_urls_total > 0 || (pdf?.strings?.ioc_urls?.length ?? 0) > 0) && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Network Indicators</span>
                <span className="pill pill-muted">Found</span>
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

          {/* Suspicious Keywords - Only show if found */}
          {(pdf?.strings?.suspicious_keywords?.length > 0) && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Keywords Detected</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Keywords Found" value={String(pdf.strings.suspicious_keywords.length)} />
              </div>
              <div className="y-list" style={{ marginTop: 6 }}>
                <div style={{ 
                  maxHeight: "150px",
                  overflowY: "auto"
                }}>
                  {pdf.strings.suspicious_keywords.map((kw, i) => (
                    <div key={i} className="y-item">
                      <div className="y-line"><span className="y-rule">🚨 Keyword</span></div>
                      <div className="y-meta"><span className="y-val">{kw}</span></div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* High Entropy Content - Only show if detected */}
          {(record?.counts?.high_entropy_stream_count ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">High Entropy Content</span>
                <span className="pill pill-muted">Found</span>
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
          {/* Structural Anomalies - Only show if found */}
          {Array.isArray(anomaliesPdf) && anomaliesPdf.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Structural Anomalies</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Anomalies Found" value={String(anomaliesPdf.length)} />
              </div>
              <ul style={{ 
                marginTop: 8, 
                paddingLeft: 18,
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {anomaliesPdf.map((a, i) => (
                  <li key={i} style={{ color: 'var(--ink-4)', marginBottom: 4 }}>{a}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Clean Status - Show if no threats detected */}
          {!jsPresent && !embeddedPresent && (counts?.ioc_urls_total ?? 0) === 0 && 
           (!pdf?.strings?.suspicious_keywords || pdf.strings.suspicious_keywords.length === 0) &&
           (record?.counts?.high_entropy_stream_count ?? 0) === 0 && 
           (!anomaliesPdf || anomaliesPdf.length === 0) && (
            <div className="card" style={{ marginTop: 12, backgroundColor: '#f0fff4', border: '1px solid #68d391' }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge" style={{ backgroundColor: '#38a169', color: 'white' }}>Clean Analysis</span>
                <span className="pill pill-green">No Threats Detected</span>
              </div>
              <div style={{ marginTop: 8, color: '#22543d' }}>
                ✅ No JavaScript, embedded files, suspicious keywords, or structural anomalies detected.
                This appears to be a legitimate PDF document.
              </div>
            </div>
          )}
        </div>

        {/* Advanced Analysis - Only show sections with actual data */}
        <div className="card">
          <div className="row" style={{ gap: 10, alignItems: 'center' }}>
            <span className="badge">Technical Details</span>
          </div>
          
          {/* PDF Structure - Only show if we have trailers */}
          {Array.isArray(pdf?.trailers) && pdf.trailers.length > 0 && (
            <Section title="PDF Structure">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Trailers Found" value={String(pdf.trailers.length)} />
                {pdf.trailers[0]?.startxref && <KV label="Start XRef" value={String(pdf.trailers[0].startxref)} />}
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--ink-3)' }}>View Raw Structure</summary>
                <pre className="jsonbox" style={{ marginTop: 8 }}>{JSON.stringify(pdf.trailers, null, 2)}</pre>
              </details>
            </Section>
          )}

          {/* Macros - Only show if present (for Office files embedded in PDF) */}
          {Array.isArray(macros) && macros.length > 0 && (
            <Section title="Embedded Macros">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Macro Modules" value={String(macros.length)} />
              </div>
              <div style={{ 
                maxHeight: "250px",
                overflowY: "auto"
              }}>
                {macros.map((m, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">{m.module_name || 'Module'}</span></div>
                    <div className="y-meta">
                      <span className="y-cap">autoexec:</span><span className="y-val">{(m.autoexec_indicators || []).join(', ') || '—'}</span>
                    </div>
                    <div className="y-meta">
                      <span className="y-cap">suspicious:</span><span className="y-val">{(m.suspicious_indicators || []).join(', ') || '—'}</span>
                    </div>
                    {m.preview && (
                      <div className="y-meta"><span className="y-cap">preview:</span><span className="y-val">{m.preview}</span></div>
                    )}
                  </div>
                ))}
              </div>
            </Section>
          )}
          {/* Actions - Only show if found */}
          {Array.isArray(actions) && actions.length > 0 && (
            <Section title="Automatic Actions">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Actions Found" value={String(actions.length)} />
                <KV label="Auto-execution" value={actions.some(a => a.notes?.includes('auto-exec')) ? 'YES' : 'NO'} />
              </div>
              <div style={{ 
                maxHeight: "200px",
                overflowY: "auto"
              }}>
                {actions.map((a, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line">
                      <span className="y-rule">{a.action_type}</span>
                      {a.uri && <span className="pill pill-hint">URI</span>}
                      {a.js_preview && <span className="pill pill-strong">JavaScript</span>}
                    </div>
                    <div className="y-meta">
                      <span className="y-cap">source:</span><span className="y-val">{a.source_obj}</span>
                      {a.target_obj && (<><span className="y-sep">•</span><span className="y-cap">target:</span><span className="y-val">{a.target_obj}</span></>)}
                      {a.uri && (<><span className="y-sep">•</span><span className="y-cap">uri:</span><span className="y-val">{a.uri}</span></>)}
                      {a.js_preview && (<><span className="y-sep">•</span><span className="y-cap">js:</span><span className="y-val">{a.js_preview}</span></>)}
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}
          {/* Embedded Files Details - Only show if files exist */}
          {Array.isArray(embeddedPdf) && embeddedPdf.length > 0 && (
            <Section title="Embedded Files Details">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Files Count" value={String(embeddedPdf.length)} />
              </div>
              <div style={{ 
                maxHeight: "200px",
                overflowY: "auto"
              }}>
                {embeddedPdf.map((e, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line">
                      <span className="y-rule">{e.name || e.obj_ref}</span>
                      {e.file_type && <span className="pill pill-hint">{e.file_type}</span>}
                    </div>
                    <div className="y-meta">
                      {e.size_hint && (<><span className="y-cap">size:</span><span className="y-val">{e.size_hint}</span></>)}
                      {e.sha256_raw && (<><span className="y-sep">•</span><span className="y-cap">sha256:</span><span className="y-val">{e.sha256_raw}</span></>)}
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}
          {/* Named Objects - Only show if found */}
          {Array.isArray(pdf?.names) && pdf.names.length > 0 && (
            <Section title="Named Objects">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Named Objects" value={String(pdf.names.length)} />
              </div>
              <div style={{ 
                maxHeight: "200px",
                overflowY: "auto"
              }}>
                {pdf.names.map((name, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line">
                      <span className="y-rule">{name.name || 'Unnamed'}</span>
                      <span className="pill pill-hint">{name.category || 'Unknown'}</span>
                    </div>
                    <div className="y-meta">
                      <span className="y-cap">ref:</span><span className="y-val">{name.obj_ref}</span>
                    </div>
                  </div>
                ))}
              </div>
            </Section>
          )}

          {/* Object Structure - Only show if we have meaningful data */}
          {pdf?.object_offsets && Object.keys(pdf.object_offsets).length > 0 && (
            <Section title="Object Structure">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Objects Mapped" value={String(pdf.object_offsets.total || Object.keys(pdf.object_offsets).length)} />
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--ink-3)' }}>View Object Map</summary>
                <pre className="jsonbox" style={{ marginTop: 8 }}>{JSON.stringify(pdf.object_offsets, null, 2)}</pre>
              </details>
            </Section>
          )}

          {/* Not Found Summary - Show what wasn't detected */}
          {(!jsPresent || !embeddedPresent || (counts?.ioc_urls_total ?? 0) === 0 || 
            !pdf?.strings?.suspicious_keywords || pdf.strings.suspicious_keywords.length === 0) && (
            <Section title="Not Detected">
              <div style={{ 
                padding: 12, 
                backgroundColor: '#f7fafc', 
                borderRadius: 4,
                fontSize: '13px',
                color: '#4a5568'
              }}>
                <strong>The following elements were not found in this PDF:</strong>
                <ul style={{ marginTop: 8, paddingLeft: 18 }}>
                  {!jsPresent && <li>❌ JavaScript or executable scripts</li>}
                  {!embeddedPresent && <li>❌ Embedded files or payloads</li>}
                  {(counts?.ioc_urls_total ?? 0) === 0 && <li>❌ Network communication URLs</li>}
                  {(!pdf?.strings?.suspicious_keywords || pdf.strings.suspicious_keywords.length === 0) && 
                    <li>❌ Suspicious keywords or malware indicators</li>}
                  {(record?.counts?.high_entropy_stream_count ?? 0) === 0 && 
                    <li>❌ Obfuscated or encrypted content</li>}
                  {(!anomaliesPdf || anomaliesPdf.length === 0) && 
                    <li>❌ Structural anomalies or format violations</li>}
                </ul>
              </div>
            </Section>
          )}

          {/* Engine Warnings - Only show if there are errors */}
          {Array.isArray(record?.errors) && record.errors.length > 0 && (
            <Section title="Analysis Warnings">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Warnings" value={String(record.errors.length)} />
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', color: 'var(--ink-3)' }}>View Warning Details</summary>
                <pre className="jsonbox" style={{ marginTop: 8 }}>{JSON.stringify(record.errors, null, 2)}</pre>
              </details>
            </Section>
          )}
        </div>

        {/* Extracted Content Display */}
        <ExtractedContent record={record} />
      </div>
    );
  }

  if (isPe) {
    return (
      <div className="card" style={{ display: 'grid', gap: 16 }}>
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <div className="row" style={{ gap: 10 }}>
            <span className="badge">PE/DLL Static Analysis</span>
            <span className="pill pill-muted">Executable Analysis</span>
          </div>
        </div>
        
        <AnalysisEngineStatus record={record} fileType="PE" />
        <StaticPEView record={record} counts={counts} />
      </div>
    );
  }

  if (isOffice) {
    const urls = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls : [];
    const suspicious = Array.isArray(strings?.suspicious_keywords) ? strings.suspicious_keywords : [];
    // Macro-derived suspicious indicators (union across modules)
    const macroIndicatorsSet = new Set();
    for (const m of (macros || [])) {
      const arr = Array.isArray(m?.suspicious_indicators) ? m.suspicious_indicators : [];
      for (const t of arr) { macroIndicatorsSet.add(String(t)); }
    }
    const macroIndicators = Array.from(macroIndicatorsSet);
    const hasCmd = (flags?.suspicious_shell_usage === true) || suspicious.some((s) => /powershell|cmd\.exe|rundll32|wscript\.shell|createobject|adodb\.stream/i.test(String(s)));
    const anomalies = anomaliesOffice || [];
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
          
          {/* Document Metadata - Only show if we have meaningful data */}
          {(meta?.Application || meta?.Creator || meta?.LastModifiedBy || meta?.Created || meta?.Modified || meta?.Company) && (
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
          {/* Macros - Only show if present */}
          {flags?.macro_present && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Macros Detected</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Macro Modules" value={String(counts?.macros_total ?? 0)} />
                {flags?.suspicious_auto_exec && <KV label="Auto-execution" value="YES" />}
                {counts?.autoexec_macros_total > 0 && <KV label="Auto-exec Modules" value={String(counts.autoexec_macros_total)} />}
              </div>
            </div>
          )}

          {/* OS Command Indicators - Only show if detected */}
          {(flags?.suspicious_shell_usage || hasCmd) && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">OS Command Indicators</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Shell Usage" value="YES" />
                {suspicious.length > 0 && <KV label="Suspicious Keywords" value={String(suspicious.length)} />}
              </div>
            </div>
          )}

          {/* External References - Only show if found */}
          {(counts?.external_references_total ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">External References</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="External Links" value={String(counts.external_references_total)} />
                {urls.length > 0 && <KV label="URLs Found" value={String(urls.length)} />}
              </div>
            </div>
          )}

          {/* Embedded Payloads - Only show if found */}
          {(counts?.embedded_payloads_total ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Embedded Payloads</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Payloads Found" value={String(counts.embedded_payloads_total)} />
                {(counts?.high_entropy_embed_count ?? 0) > 0 && <KV label="High-entropy" value={String(counts.high_entropy_embed_count)} />}
              </div>
            </div>
          )}
          {/* Network Indicators - Only show if URLs found */}
          {urls.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Network Indicators</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="URLs Found" value={String(urls.length)} />
              </div>
              <div className="y-list" style={{ 
                marginTop: 6,
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {urls.map((u, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">URL</span></div>
                    <div className="y-meta"><span className="y-val">{u}</span></div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Suspicious Keywords - Only show if found */}
          {suspicious.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Suspicious Keywords</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Keywords Found" value={String(suspicious.length)} />
              </div>
              <div className="y-list" style={{ 
                marginTop: 6,
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {suspicious.map((k, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">Keyword</span></div>
                    <div className="y-meta"><span className="y-val">{k}</span></div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Macro Indicators - Only show if found */}
          {macroIndicators.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Macro Indicators</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Indicators Found" value={String(macroIndicators.length)} />
              </div>
              <div className="y-list" style={{ 
                marginTop: 6,
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {macroIndicators.map((k, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">Macro Indicator</span></div>
                    <div className="y-meta"><span className="y-val">{k}</span></div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {/* High Entropy Content - Only show if detected */}
          {(counts?.high_entropy_embed_count ?? 0) > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">High Entropy Content</span>
                <span className="pill pill-muted">Found</span>
              </div>
              <div className="grid" style={{ marginTop: 8 }}>
                {typeof entropy?.overall === 'number' && <KV label="Overall entropy" value={entropy.overall.toFixed(2)} />}
                <KV label="High-entropy embeds" value={String(counts.high_entropy_embed_count)} />
              </div>
              <div style={{ marginTop: 8, padding: 8, backgroundColor: '#fff5f5', borderRadius: 4, fontSize: '12px' }}>
                High-entropy embedded content detected - possible encrypted or compressed payloads
              </div>
            </div>
          )}
          {/* Structural Anomalies - Only show if found */}
          {Array.isArray(anomalies) && anomalies.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Structural Anomalies</span>
                <span className="pill pill-muted">Found</span>
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

          {/* Not Found Summary - Show what wasn't detected */}
          {!flags?.macro_present && !flags?.suspicious_shell_usage && urls.length === 0 && suspicious.length === 0 && (counts?.high_entropy_embed_count ?? 0) === 0 && (!Array.isArray(anomalies) || anomalies.length === 0) && (
            <div className="card" style={{ marginTop: 12, backgroundColor: '#f7fafc', border: '1px solid #e2e8f0' }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge">Not Detected</span>
                <span className="pill pill-muted">Clean Analysis</span>
              </div>
              <div style={{ marginTop: 8, fontSize: '13px', color: 'var(--ink-4)' }}>
                <strong>No threats detected in this analysis:</strong>
                <ul style={{ marginTop: 6, paddingLeft: 18 }}>
                  <li>❌ No macros or executable scripts</li>
                  <li>❌ No OS command indicators</li>
                  <li>❌ No network communication URLs</li>
                  <li>❌ No suspicious keywords</li>
                  <li>❌ No high-entropy embedded content</li>
                  <li>❌ No structural anomalies</li>
                </ul>
              </div>
            </div>
          )}

          {/* Clean Analysis Status */}
          {!flags?.macro_present && !flags?.suspicious_shell_usage && urls.length === 0 && suspicious.length === 0 && (counts?.high_entropy_embed_count ?? 0) === 0 && (!Array.isArray(anomalies) || anomalies.length === 0) && (
            <div className="card" style={{ marginTop: 12, backgroundColor: '#f0fff4', border: '1px solid #68d391' }}>
              <div className="row" style={{ gap: 8, alignItems: 'center' }}>
                <span className="badge" style={{ backgroundColor: '#38a169', color: 'white' }}>Clean Analysis</span>
                <span className="pill pill-green">✓ No Threats</span>
              </div>
              <div style={{ marginTop: 8, fontSize: '13px', color: '#22543d' }}>
                <strong>✅ Clean Document Analysis</strong>
                <p style={{ marginTop: 4, marginBottom: 0 }}>
                  No threats detected. This appears to be a legitimate Office document with standard content and structure.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Office Macro Extraction - Integrated automatically */}
        <OfficeExtractor record={record} />

        {/* Technical Details - Collapsible sections */}
        <div className="card">
          <div className="row" style={{ gap: 10, alignItems: 'center' }}>
            <span className="badge">Technical Details</span>
          </div>
          
          {/* Document Parts - Only show if meaningful data */}
          {Array.isArray(structure?.parts) && structure.parts.length > 0 && (
            <Section title="Document Structure">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Parts Found" value={String(structure.parts.length)} />
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', fontSize: '12px', color: 'var(--ink-4)' }}>
                  View Raw Structure Data
                </summary>
                <pre className="jsonbox" style={{ 
                  marginTop: 8,
                  maxHeight: "300px",
                  overflowY: "auto"
                }}>
                  {JSON.stringify(structure.parts, null, 2)}
                </pre>
              </details>
            </Section>
          )}

          {/* External References - Only show if found */}
          {Array.isArray(structure?.external_references) && structure.external_references.length > 0 && (
            <Section title="External References">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="References Found" value={String(structure.external_references.length)} />
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ cursor: 'pointer', fontSize: '12px', color: 'var(--ink-4)' }}>
                  View External References
                </summary>
                <pre className="jsonbox" style={{ 
                  marginTop: 8,
                  maxHeight: "300px",
                  overflowY: "auto"
                }}>
                  {JSON.stringify(structure.external_references, null, 2)}
                </pre>
              </details>
            </Section>
          )}

          {/* Embedded Macros - Only show if present */}
          {macros.length > 0 && (
            <Section title="Embedded Macros">
              <div className="grid" style={{ marginTop: 8 }}>
                <KV label="Macro Modules" value={String(macros.length)} />
                <KV label="Auto-execution" value={macros.some(m => m.autoexec_indicators?.length > 0) ? 'YES' : 'NO'} />
              </div>
              <div className="y-list" style={{ 
                marginTop: 8,
                maxHeight: "250px",
                overflowY: "auto"
              }}>
                {macros.map((m, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line">
                      <span className="y-rule">{m.module_name || 'Module'}</span>
                      {m.autoexec_indicators?.length > 0 && <span className="pill pill-hint">Auto-exec</span>}
                    </div>
                    <div className="y-meta">
                      <span className="y-cap">autoexec:</span><span className="y-val">{(m.autoexec_indicators || []).join(', ') || '—'}</span>
                    </div>
                    {m.preview && (
                      <div className="y-meta"><span className="y-cap">preview:</span><span className="y-val">{m.preview}</span></div>
                    )}
                  </div>
                ))}
              </div>
            </Section>
          )}
          <Section title="Embedded Payloads">
            {embeds.length === 0 ? (
              <pre className="jsonbox">{'// No embedded payloads extracted'}</pre>
            ) : (
              <div style={{ 
                maxHeight: "250px",
                overflowY: "auto"
              }}>
                {embeds.map((e, i) => (
                  <div key={i} className="y-item">
                    <div className="y-line"><span className="y-rule">{e.name || e.path}</span></div>
                    <div className="y-meta">
                      <span className="y-cap">size:</span><span className="y-val">{e.size_hint ?? '—'}</span>
                      <span className="y-sep">•</span><span className="y-cap">sha256:</span><span className="y-val">{e.sha256_raw || '—'}</span>
                      <span className="y-sep">•</span><span className="y-cap">type:</span><span className="y-val">{e.type_hint || '—'}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Section>
          <Section title="Strings (samples)">
            {Array.isArray(strings?.sample_strings) && strings.sample_strings.length > 0 ? (
              <pre className="jsonbox" style={{ 
                maxHeight: "200px",
                overflowY: "auto"
              }}>
                {JSON.stringify(strings.sample_strings, null, 2)}
              </pre>
            ) : (
              <pre className="jsonbox">{'// No string samples'}</pre>
            )}
          </Section>
          <Section title="Entropy hotspots">
            <pre className="jsonbox">{JSON.stringify(entropy?.suspicious_embeds || [], null, 2)}</pre>
          </Section>
          {Array.isArray(record?.errors) && record.errors.length > 0 && (
            <Section title="Engine Warnings">
              <pre className="jsonbox">{JSON.stringify(record.errors, null, 2)}</pre>
            </Section>
          )}
        </div>
      </div>
    );
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
          <br />
          Check the browser console for details.
        </p>
        <details style={{ marginTop: 16, textAlign: 'left' }}>
          <summary style={{ cursor: 'pointer' }}>Error Details</summary>
          <pre style={{ 
            marginTop: 8, 
            padding: 8, 
            backgroundColor: '#f5f5f5', 
            borderRadius: 4,
            fontSize: '12px',
            overflow: 'auto'
          }}>
            {error.toString()}
          </pre>
        </details>
      </div>
    );
  }
}

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
          enhanced: true, // PE analysis is always available
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

      {/* Available Libraries */}
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

      {/* Analysis Results Summary */}
      <div style={{ marginTop: 12 }}>
        <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Analysis Results:</strong>
        <div className="grid" style={{ marginTop: 6, gap: 4, fontSize: "12px" }}>
          {Object.entries(engineInfo.counts).map(([label, count]) => (
            <div key={label} className="kv">
              <label>{label}</label>
              <code style={{ 
                color: (label.includes('JavaScript') || label.includes('Suspicious') || label.includes('YARA')) && count > 0 
                  ? "#e53e3e" : "inherit" 
              }}>
                {count}
              </code>
            </div>
          ))}
        </div>
      </div>

      {/* Show any engine-specific errors */}
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

      {/* File-specific recommendations */}
      {!engineInfo.enhanced && fileType === 'PDF' && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Recommendations:</strong>
          <ul style={{ marginTop: 4, paddingLeft: 16, fontSize: "11px", color: "var(--ink-4)" }}>
            <li>Install enhanced PDF libraries for better metadata extraction</li>
            <li>Run: install_pdf_libs.ps1 for professional analysis capabilities</li>
          </ul>
        </div>
      )}
    </div>
  );
}

function PDFAnalysisStatus({ record }) {
  const [libraryStatus, setLibraryStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLibraryStatus = async () => {
      try {
        const response = await fetch('http://127.0.0.1:8000/api/status/pdf');
        const data = await response.json();
        setLibraryStatus(data);
      } catch (error) {
        console.error('Failed to fetch library status:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchLibraryStatus();
  }, []);

  if (loading) {
    return (
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="badge">PDF Analysis Engine</div>
        <p style={{ margin: "8px 0", color: "var(--ink-4)" }}>Loading engine status...</p>
      </div>
    );
  }

  const getStatusIcon = (available) => available ? "✅" : "❌";
  const getStatusColor = (available) => available ? "#22543d" : "#742a2a";

  // Check if enhanced analysis was used for this PDF
  const usedEnhancedAnalysis = record?.static?.pdf?.analysis_engine || 
                              (libraryStatus?.enhanced_analysis && "Enhanced");
  
  // Extract analysis metadata from the PDF record
  const analysisMetadata = record?.static?.pdf?.analysis_metadata || {};
  const engineErrors = record?.errors?.filter(e => e.includes('pdf') || e.includes('enhanced')) || [];

  return (
    <div className="card" style={{ marginBottom: 16, border: "1px solid #e2e8f0" }}>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div className="badge">PDF Analysis Engine Status</div>
        <span style={{ 
          color: libraryStatus?.enhanced_analysis ? "#22543d" : "#744210",
          fontSize: "12px",
          fontWeight: "600"
        }}>
          {libraryStatus?.enhanced_analysis ? "🚀 Enhanced Mode" : "⚡ Basic Mode"}
        </span>
      </div>

      <div className="grid" style={{ marginTop: 12, gap: 8, fontSize: "13px" }}>
        <div className="kv">
          <label>Analysis Engine</label>
          <code>{usedEnhancedAnalysis || "Basic PDF Parser"}</code>
        </div>
        <div className="kv">
          <label>Library Count</label>
          <code>{libraryStatus?.library_count || "1/4 (basic)"}</code>
        </div>
        {analysisMetadata.extraction_method && (
          <div className="kv">
            <label>Metadata Method</label>
            <code>{analysisMetadata.extraction_method}</code>
          </div>
        )}
      </div>

      {libraryStatus?.libraries && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Available Libraries:</strong>
          <div className="row" style={{ marginTop: 6, gap: 8, flexWrap: "wrap" }}>
            {Object.entries(libraryStatus.libraries).map(([lib, available]) => (
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

      {/* Show analysis output/results */}
      {record?.static?.pdf && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Analysis Results:</strong>
          <div className="grid" style={{ marginTop: 6, gap: 4, fontSize: "12px" }}>
            <div className="kv">
              <label>Objects Parsed</label>
              <code>{record.counts?.objects_total || 0}</code>
            </div>
            <div className="kv">
              <label>Streams Analyzed</label>
              <code>{record.counts?.streams_total || 0}</code>
            </div>
            <div className="kv">
              <label>JavaScript Objects</label>
              <code style={{ color: record.counts?.js_objects_total > 0 ? "#e53e3e" : "inherit" }}>
                {record.counts?.js_objects_total || 0}
              </code>
            </div>
            <div className="kv">
              <label>Embedded Files</label>
              <code>{record.counts?.embedded_files_total || 0}</code>
            </div>
          </div>
        </div>
      )}

      {/* Show any engine-specific errors */}
      {engineErrors.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "#e53e3e" }}>Engine Warnings:</strong>
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

      {/* Recommendations */}
      {libraryStatus?.recommendations && libraryStatus.recommendations.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <strong style={{ fontSize: "12px", color: "var(--ink-3)" }}>Recommendations:</strong>
          <ul style={{ 
            marginTop: 4, 
            paddingLeft: 16, 
            fontSize: "11px", 
            color: "var(--ink-4)",
            maxHeight: "100px",
            overflowY: "auto"
          }}>
            {libraryStatus.recommendations.map((rec, i) => (
              <li key={i}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function StaticPEView({ record, counts }) {
  const FALLBACK = "—";

  function safeText(v, fallback = FALLBACK) {
    if (v === null || v === undefined) return fallback;
    if (typeof v === "number") return v.toString();
    if (typeof v === "string") {
      const cleaned = v
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "")
        .replace(/[^\x20-\x7E\u00A0-\u024F]/g, "");
      if (!cleaned.trim()) return fallback;
      return cleaned;
    }
    return fallback;
  }

  function formatHex(num, fallback = FALLBACK) {
    if (num === null || num === undefined) return fallback;
    if (typeof num !== "number" || !Number.isFinite(num)) return fallback;
    return "0x" + num.toString(16).toUpperCase();
  }

  function yesNo(val) {
    if (val === true) return "YES";
    if (val === false) return "NO";
    return FALLBACK;
  }

  function truncate(str, maxLen = 120) {
    const s = safeText(str, FALLBACK);
    if (s === FALLBACK) return FALLBACK;
    return s.length > maxLen ? s.slice(0, maxLen) + "…" : s;
  }

  function prettySize(bytes) {
    if (bytes === null || bytes === undefined) return FALLBACK;
    if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return FALLBACK;
    if (bytes >= 1024 * 1024) {
      const mb = (bytes / (1024 * 1024)).toFixed(2);
      return `${mb} MB`;
    }
    if (bytes >= 1024) {
      const kb = (bytes / 1024).toFixed(2);
      return `${kb} KB`;
    }
    return `${Math.round(bytes)} B`;
  }

  function computeRisk(pe, counts) {
    const suspicious = (counts?.suspicious_imports_total || 0) > 0;
    const packed = (counts?.high_entropy_section_count || 0) > 0;
    const overlay = pe?.overlay?.present === true;
    const anomaliesCount = Array.isArray(pe?.anomalies) ? pe.anomalies.length : 0;
    if (suspicious && packed && overlay) return "High";
    if (suspicious || packed || overlay || anomaliesCount >= 3) return "Medium";
    return "Low";
  }

  function isUserFacingError(e) {
    if (!e) return false;
    const lower = String(e).toLowerCase();
    if (lower.includes("traceback")) return false;
    if (lower.includes("attributeerror")) return false;
    if (lower.includes("lief_signature_error")) return false;
    return true;
  }

  const pe = record?.static?.pe || {};
  const fileInfo = pe?.file_info || {};
  const signature = (pe?.signatures || {}).authenticode || {};
  const overlay = pe?.overlay || {};
  const sections = Array.isArray(pe?.sections) ? pe.sections : [];
  const imports = Array.isArray(pe?.imports) ? pe.imports : [];
  const exportsList = Array.isArray(pe?.exports) ? pe.exports : [];
  const resources = Array.isArray(pe?.resources) ? pe.resources : [];
  const suspiciousImports = Array.isArray(pe?.suspicious_imports) ? pe.suspicious_imports : [];
  const yaraMatches = Array.isArray(pe?.yara_matches) ? pe.yara_matches : [];
  const anomalies = Array.isArray(pe?.anomalies) ? pe.anomalies : [];
  const strings = pe?.strings || {};
  const disasm = Array.isArray(pe?.disasm) ? pe.disasm : [];

  const totalSuspiciousImports = counts?.suspicious_imports_total ?? suspiciousImports.length;
  const totalHighEntropy = counts?.high_entropy_section_count ?? 0;
  const totalStrings = counts?.strings_total ?? (typeof strings.total === "number" ? strings.total : 0);
  const yaraTotal = counts?.yara_matches_total ?? yaraMatches.length;
  const iocUrls = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls : [];
  const suspiciousKeywords = Array.isArray(strings?.suspicious_keywords) ? strings.suspicious_keywords : [];
  // Remove truncation - show all data with scrollable containers

  const overlayPresent = overlay?.present === true;
  const overlaySize = overlayPresent ? prettySize(overlay?.size) : "";
  const overlayExtra = overlayPresent && overlaySize && overlaySize !== FALLBACK ? ` (${overlaySize})` : "";
  const fileBadge = fileInfo?.is_dll ? "PE / DLL" : "PE";

  const fileTypeCpu = (() => {
    const type = safeText(fileInfo?.file_type);
    const machine = safeText(fileInfo?.machine);
    if (type === FALLBACK && machine === FALLBACK) return FALLBACK;
    if (type === FALLBACK) return machine;
    if (machine === FALLBACK) return type;
    return `${type} / ${machine}`;
  })();

  const signerText = signature?.present ? safeText(signature?.signer, "unknown") : "unknown";
  const canRunOtherPrograms = totalSuspiciousImports > 0;
  const osCmdIndicators = topKeywords.some((kw) => /powershell|cmd\.exe|rundll32|regsvr32|wscript|mshta/i.test(String(kw || "")));

  const normalizeNote = (val) => {
    if (val === null || val === undefined) return null;
    const raw = typeof val === "string" ? val : String(val);
    const cleaned = safeText(raw, FALLBACK);
    if (cleaned === FALLBACK) return null;
    if (cleaned.toLowerCase() === "undefined") return null;
    return cleaned.replace(/_/g, " ");
  };

  const yaraMeaning = (match) => {
    const meta = match?.meta || {};
    return safeText(meta.notes || meta.behavior || meta.subtype || meta.purpose || FALLBACK);
  };

  const userFacingErrors = [
    ...(Array.isArray(record?.errors) ? record.errors : []),
    ...(Array.isArray(pe?.errors) ? pe.errors : []),
  ].filter(isUserFacingError);

  const notes = Array.from(new Set([
    ...anomalies.map(normalizeNote),
    ...userFacingErrors.map(normalizeNote),
  ].filter(Boolean)));

  return (
    <div className="card" style={{ display: 'grid', gap: 16 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div className="row" style={{ gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span className="badge">Static Analysis</span>
          <span className="pill pill-muted">{fileBadge}</span>
        </div>
      </div>

      <div className="card">
        <div className="row" style={{ gap: 10, alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
          <span className="badge">Basic Analysis</span>
        </div>
        <div className="card" style={{ marginTop: 10 }}>
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <span className="badge">File Details</span>
          </div>
          <dl style={{ margin: 0, display: 'grid', gap: 12 }}>
            <div>
              <dt style={{ fontWeight: 600 }}>File Type / CPU</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{fileTypeCpu}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>This tells us if it's 32-bit or 64-bit and what CPU it was built for.</small>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Build Time</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{safeText(fileInfo?.compile_time)}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>When the program says it was compiled.</small>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Where it starts running (Entry Point)</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{formatHex(fileInfo?.entrypoint_rva)}</dd>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Base Address in Memory</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{formatHex(fileInfo?.image_base)}</dd>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Tries to run code early (TLS callbacks)</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{yesNo(fileInfo?.has_tls_callbacks)}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>Malware sometimes hides startup code here.</small>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Is it digitally signed?</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{yesNo(signature?.present)}</dd>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Signer (if known)</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{safeText(signerText, 'unknown')}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>Legit software is often signed by a company.</small>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>Extra data bundled</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{`${yesNo(overlayPresent)}${overlayExtra}`}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>Big extra data at the end can mean an installer or hidden payload.</small>
            </div>
            <div>
              <dt style={{ fontWeight: 600 }}>High-entropy code regions</dt>
              <dd style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', color: 'var(--ink-5)' }}>{totalHighEntropy}</dd>
              <small style={{ display: 'block', marginTop: 2, color: 'var(--ink-4)' }}>High entropy can mean encrypted/packed code.</small>
            </div>
          </dl>
        </div>

        {/* Suspicious Imports - Only show if found */}
        {suspiciousImports.length > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Suspicious API Imports</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Suspicious APIs" value={String(suspiciousImports.length)} />
            </div>
            <div style={{ marginTop: 8 }}>
              <small style={{ color: 'var(--ink-4)' }}>These Windows functions can launch other apps, download data, or load code in memory.</small>
              <ul style={{ 
                marginTop: 6, 
                paddingLeft: 18, 
                color: 'var(--ink-5)',
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {suspiciousImports.map((imp, idx) => (
                  <li key={idx} style={{ marginBottom: 4 }}>{imp}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* YARA Matches - Only show if found */}
        {yaraMatches.length > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">YARA Rule Matches</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Rules Matched" value={String(yaraMatches.length)} />
            </div>
            <div style={{ marginTop: 8 }}>
              <small style={{ color: 'var(--ink-4)' }}>These are behavior signatures that identify specific patterns or techniques.</small>
              <ul style={{ 
                marginTop: 6, 
                paddingLeft: 18, 
                color: 'var(--ink-5)',
                maxHeight: "200px",
                overflowY: "auto"
              }}>
                {yaraMatches.map((match, idx) => (
                  <li key={idx} style={{ marginBottom: 8 }}>
                    <div><strong>{match?.rule}</strong></div>
                    <div style={{ color: 'var(--ink-4)', fontSize: '12px' }}>{yaraMeaning(match)}</div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Network Indicators - Only show if URLs found */}
        {iocUrls.length > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Network Indicators</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="URLs Found" value={String(iocUrls.length)} />
            </div>
            <div style={{ marginTop: 8 }}>
              <small style={{ color: 'var(--ink-4)' }}>Website or server links found inside the executable.</small>
              <ul style={{ 
                marginTop: 6, 
                paddingLeft: 18, 
                color: 'var(--ink-5)',
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {iocUrls.map((url, idx) => (
                  <li key={idx} style={{ marginBottom: 4 }}>Possible contact: {url}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* Suspicious Keywords - Only show if found */}
        {suspiciousKeywords.length > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Suspicious Keywords</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="Keywords Found" value={String(suspiciousKeywords.length)} />
            </div>
            <div style={{ marginTop: 8 }}>
              <small style={{ color: 'var(--ink-4)' }}>Suspicious text strings that may indicate malicious behavior.</small>
              <ul style={{ 
                marginTop: 6, 
                paddingLeft: 18, 
                color: 'var(--ink-5)',
                maxHeight: "150px",
                overflowY: "auto"
              }}>
                {suspiciousKeywords.map((kw, idx) => (
                  <li key={idx} style={{ marginBottom: 4 }}>{kw}</li>
                ))}
              </ul>
            </div>
          </div>
        )}

        {/* High Entropy Sections - Only show if detected */}
        {totalHighEntropy > 0 && (
          <div className="card" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">High Entropy Content</span>
              <span className="pill pill-muted">Found</span>
            </div>
            <div className="grid" style={{ marginTop: 8 }}>
              <KV label="High-entropy sections" value={String(totalHighEntropy)} />
            </div>
            <div style={{ marginTop: 8, padding: 8, backgroundColor: '#fff5f5', borderRadius: 4, fontSize: '12px' }}>
              High entropy can indicate encrypted, packed, or compressed code sections.
            </div>
          </div>
        )}

        {/* Not Found Summary - Show what wasn't detected */}
        {suspiciousImports.length === 0 && yaraMatches.length === 0 && iocUrls.length === 0 && suspiciousKeywords.length === 0 && totalHighEntropy === 0 && anomalies.length === 0 && (
          <div className="card" style={{ marginTop: 12, backgroundColor: '#f7fafc', border: '1px solid #e2e8f0' }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge">Not Detected</span>
              <span className="pill pill-muted">Clean Analysis</span>
            </div>
            <div style={{ marginTop: 8, fontSize: '13px', color: 'var(--ink-4)' }}>
              <strong>No threats detected in this analysis:</strong>
              <ul style={{ marginTop: 6, paddingLeft: 18 }}>
                <li>❌ No suspicious API imports</li>
                <li>❌ No YARA rule matches</li>
                <li>❌ No network communication URLs</li>
                <li>❌ No suspicious keywords</li>
                <li>❌ No high-entropy (packed/encrypted) sections</li>
                <li>❌ No structural anomalies</li>
              </ul>
            </div>
          </div>
        )}

        {/* Clean Analysis Status */}
        {suspiciousImports.length === 0 && yaraMatches.length === 0 && iocUrls.length === 0 && suspiciousKeywords.length === 0 && totalHighEntropy === 0 && anomalies.length === 0 && (
          <div className="card" style={{ marginTop: 12, backgroundColor: '#f0fff4', border: '1px solid #68d391' }}>
            <div className="row" style={{ gap: 8, alignItems: 'center' }}>
              <span className="badge" style={{ backgroundColor: '#38a169', color: 'white' }}>Clean Analysis</span>
              <span className="pill pill-green">✓ No Threats</span>
            </div>
            <div style={{ marginTop: 8, fontSize: '13px', color: '#22543d' }}>
              <strong>✅ Clean Executable Analysis</strong>
              <p style={{ marginTop: 4, marginBottom: 0 }}>
                No threats detected. This appears to be a legitimate executable with standard behavior patterns.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <span className="badge">Advanced Analysis</span>
        </div>
        <Section
          title="Program Sections (Technical View)"
          subtitle="Shows how the program is divided and whether any parts look encrypted or packed."
        >
          {sections.length === 0 ? (
            <div>No program sections were parsed.</div>
          ) : (
            <div className="y-list" style={{
              maxHeight: "400px",
              overflowY: "auto"
            }}>
              {sections.map((section, idx) => {
                const name = safeText(section?.name);
                const virtualAddress = formatHex(section?.virtual_address);
                const rawSize = typeof section?.raw_size === 'number' ? `${section.raw_size} bytes` : FALLBACK;
                const entropy = typeof section?.entropy === 'number' ? section.entropy.toFixed(2) : FALLBACK;
                const looksPacked = section?.suspect === true || (typeof section?.entropy === 'number' && section.entropy >= 7.5);
                const characteristics = Array.isArray(section?.characteristics) ? section.characteristics.map((c) => safeText(c)).filter((c) => c !== FALLBACK) : [];
                return (
                  <div key={idx} className="y-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                    <div className="y-line">
                      <span className="y-rule">{name}</span>
                      {looksPacked && <span className="pill pill-strong">looks encrypted/packed</span>}
                    </div>
                    <div className="y-meta">
                      <span className="y-cap">Virtual Address:</span><span className="y-val">{virtualAddress}</span>
                      <span className="y-sep">|</span><span className="y-cap">Raw Size:</span><span className="y-val">{rawSize}</span>
                      <span className="y-sep">|</span><span className="y-cap">Entropy:</span><span className="y-val">{entropy}</span>
                      <span className="y-sep">|</span><span className="y-cap">Looks encrypted/packed:</span><span className="y-val">{yesNo(looksPacked)}</span>
                    </div>
                    {characteristics.length > 0 && (
                      <div className="y-meta">
                        <span className="y-cap">Flags:</span><span className="y-val">{characteristics.join(', ')}</span>
                      </div>
                    )}
                  </div>
                );
              })}

            </div>
          )}
        </Section>
        <Section
          title="Functions This Program Calls (Windows APIs)"
          subtitle="These are Windows features the program is asking to use."
        >
          {imports.length === 0 ? (
            <div>No Windows API imports were parsed.</div>
          ) : (
            <div className="y-list">
              <div style={{ 
                maxHeight: "300px",
                overflowY: "auto"
              }}>
                {imports.map((dll, idx) => {
                const dllName = safeText(dll?.dll);
                const funcs = Array.isArray(dll?.functions) ? dll.functions : [];
                const shown = funcs.map((fn) => safeText(fn)).filter((fn) => fn !== FALLBACK);

                return (
                  <div key={idx} className="y-item">
                    <div className="y-line"><span className="y-rule">{dllName}</span></div>
                    <div className="y-meta">
                      <span className="y-val">{shown.length > 0 ? shown.join(', ') : 'No specific functions listed.'}</span>
                    </div>

                  </div>
                );
              })}
              </div>
            </div>
          )}
        </Section>
        <Section title="Exports">
          {exportsList.length === 0 ? (
            <div>No exports were parsed.</div>
          ) : (
            <div className="y-list">
              <div style={{ 
                maxHeight: "300px",
                overflowY: "auto"
              }}>
                {exportsList.map((ex, idx) => (
                <div key={idx} className="y-item">
                  <div className="y-line"><span className="y-rule">{ex?.name || `(ordinal ${ex?.ordinal})`}</span></div>
                  <div className="y-meta">
                    <span className="y-cap">RVA:</span><span className="y-val">{formatHex(ex?.rva)}</span>
                  </div>
                </div>
              ))}
              </div>
            </div>
          )}
        </Section>
        <Section title="Embedded Resources">
          {resources.length === 0 ? (
            <div>No embedded resources were parsed.</div>
          ) : (
            <div className="y-list">
              <div style={{ 
                maxHeight: "250px",
                overflowY: "auto"
              }}>
                {resources.map((res, idx) => {
                const type = safeText(res?.type);
                const lang = safeText(res?.lang);
                const size = typeof res?.size === 'number' ? prettySize(res.size) : FALLBACK;
                return (
                  <div key={idx} className="y-item">
                    <div className="y-line"><span className="y-rule">{type}</span></div>
                    <div className="y-meta">
                      <span className="y-cap">Language:</span><span className="y-val">{lang}</span>
                      <span className="y-sep">|</span><span className="y-cap">Size:</span><span className="y-val">{size}</span>
                    </div>
                  </div>
                );
              })}
              </div>
            </div>
          )}
        </Section>
        <Section
          title="Behavior Signatures"
          subtitle="Rules that match known behaviors like downloading data or anti-debug tricks."
        >
          {yaraMatches.length === 0 ? (
            <div>No behavior signatures were triggered.</div>
          ) : (
            <div className="y-list">
              <div style={{ 
                maxHeight: "300px",
                overflowY: "auto"
              }}>
                {yaraMatches.map((match, idx) => (
                <div key={idx} className="y-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                  <div className="y-line"><span className="y-rule">{match?.rule}</span></div>
                  <div className="y-meta">
                    <span className="y-cap">Meaning:</span><span className="y-val">{yaraMeaning(match)}</span>
                  </div>
                  {match?.meta?.confidence && (
                    <div className="y-meta">
                      <span className="y-cap">Confidence:</span><span className="y-val">{safeText(match.meta.confidence)}</span>
                    </div>
                  )}
                </div>
              ))}
              </div>
            </div>
          )}
          <small style={{ display: 'block', marginTop: 6, color: 'var(--ink-4)' }}>These are pattern hits that may indicate known behavior (for example: packed file, .NET code, anti-debug tricks).</small>
        </Section>
        <Section
          title="First Instructions the Program Runs"
          subtitle="A short technical preview of the code at the program's start point."
        >
          {disasm.length === 0 ? (
            <div>No disassembly preview available.</div>
          ) : (
            <div className="y-list">
              <div style={{ 
                maxHeight: "400px",
                overflowY: "auto"
              }}>
                {disasm.map((entry, idx) => (
                <div key={idx} className="y-item">
                  <div className="y-line"><span className="y-rule">RVA {formatHex(entry?.rva)}</span></div>
                  <div className="y-meta">
                    <span className="y-val">{entry?.mnemonics || entry?.bytes}</span>
                  </div>
                </div>
              ))}
              </div>
            </div>
          )}
        </Section>
        <Section title="Analysis Notes / Warnings">
          {notes.length === 0 ? (
            <div>No additional warnings.</div>
          ) : (
            <ul style={{ marginTop: 6, paddingLeft: 18, color: 'var(--ink-5)' }}>
              {notes.map((note, idx) => (
                <li key={idx}>{note}</li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  );
}