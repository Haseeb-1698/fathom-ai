// StaticMiniSummary.jsx — compact static overview (PDF + Office) for the Basic tab
// Props: { record }

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

export default function StaticMiniSummary({ record }) {
  const counts = record?.counts || {};
  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isPdf = finalType === 'pdf';
  const isOffice = finalType === 'office_ooxml' || finalType === 'office_ole' || !!record?.static?.office;
  const isPe = finalType === 'pe' || finalType === 'dll' || !!record?.static?.pe;
  
  if (!isPdf && !isOffice && !isPe) return null;

  // URLs sample
  let urls = [];
  if (isPdf) {
    const pdf = record?.static?.pdf || {};
    const urlRegex = /https?:\/\/[\w\-\.\/?#%&=:+,@~]+/gi;
    const previews = Array.isArray(pdf?.objects) ? pdf.objects
      .map((o) => o?.stream?.decoded_preview)
      .filter((s) => typeof s === 'string') : [];
    const urlsSet = new Set();
    for (const p of previews) {
      const m = p.match(urlRegex) || [];
      for (const u of m) { if (urlsSet.size >= 5) break; urlsSet.add(u); }
      if (urlsSet.size >= 5) break;
    }
    urls = Array.from(urlsSet);
  } else if (isOffice) {
    const strings = record?.static?.office?.strings || {};
    urls = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls : [];
  }

  // Remove truncation - show full content

  if (isPdf) {
    const pdf = record?.static?.pdf || {};
    const anomalies = Array.isArray(pdf?.anomalies) ? pdf.anomalies : [];
    
    return (
      <div className="card" style={{ marginTop: 12, display: 'grid', gap: 8 }}>
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="badge">Static Indicators</span>
          {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
        </div>
        <div className="grid">
          <KV label="Producer" value={pdf?.metadata?.Producer || '—'} />
          <KV label="Encrypted" value={pdf?.encryption?.Filter ? 'YES' : 'NO'} />
          <KV label="URLs" value={String(counts?.urls_total ?? 0)} />
          <KV label="Embedded" value={String(counts?.embedded_files_total ?? 0)} />
          <KV label="JS" value={(counts?.js_objects_total ?? 0) > 0 ? 'YES' : 'NO'} />
          <KV label="Auto actions" value={(counts?.auto_actions_total ?? 0) > 0 ? 'YES' : 'NO'} />
        </div>
        {urls.length > 0 && (
          <div>
            <strong>URLs</strong>
            <div className="y-list" style={{ 
              marginTop: 6,
              maxHeight: "120px",
              overflowY: "auto"
            }}>
              {urls.map((u, i) => (
                <div key={i} className="y-item">
                  <div className="y-meta"><span className="y-val">{u}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  if (isPe) {
    const DASH = "—";
    const pe = record?.static?.pe || {};
    const signature = (pe?.signatures || {}).authenticode || {};
    const anomalies = Array.isArray(pe?.anomalies) ? pe.anomalies : [];
    const overlay = pe?.overlay || {};
    const strings = pe?.strings || {};
    const suspiciousImports = Array.isArray(pe?.suspicious_imports) ? pe.suspicious_imports : [];
    const urlsPe = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls : [];
    const suspiciousImportsTotal = counts?.suspicious_imports_total ?? 0;
    const highEntropySections = counts?.high_entropy_section_count ?? 0;
    const yaraTotal = counts?.yara_matches_total ?? 0;
    const overlayPresent = overlay?.present === true;
    const linkCount = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls.length : 0;

    const yesNo = (value) => (value === true ? 'YES' : value === false ? 'NO' : DASH);
    const countValue = (value) => (Number.isFinite(value) ? String(value) : DASH);
    const listValue = (value) => {
      const text = typeof value === 'string' ? value : String(value ?? '');
      return text.trim() ? text : DASH;
    };

    return (
      <div className="card" style={{ marginTop: 12, display: 'grid', gap: 8 }}>
        <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
          <span className="badge">Static Indicators</span>
          {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
        </div>
        <div className="grid">
          <KV label="Digitally signed" value={yesNo(signature?.present === true)} />
          <KV label="Can launch or load other programs" value={yesNo(suspiciousImportsTotal > 0)} />
          <KV label="Possible packed/encrypted parts" value={yesNo(highEntropySections > 0)} />
          <KV label="Contains extra hidden data" value={yesNo(overlayPresent)} />
          <KV label="Behavior signatures (rules hit)" value={countValue(yaraTotal)} />
          <KV label="Links found inside" value={countValue(linkCount)} />
        </div>
        {(suspiciousImports.length > 0 || urlsPe.length > 0) && (
          <div>
            {suspiciousImports.length > 0 && (
              <>
                <strong>Windows APIs it may use</strong>
                <div className="y-list" style={{ 
                  marginTop: 6,
                  maxHeight: "120px",
                  overflowY: "auto"
                }}>
                  {suspiciousImports.map((imp, i) => (
                    <div key={i} className="y-item">
                      <div className="y-meta"><span className="y-val">{listValue(imp)}</span></div>
                    </div>
                  ))}
                </div>
              </>
            )}
            {urlsPe.length > 0 && (
              <>
                <strong style={{ marginTop: 8, display: 'block' }}>Possible network links</strong>
                <div className="y-list" style={{ 
                  marginTop: 6,
                  maxHeight: "120px",
                  overflowY: "auto"
                }}>
                  {urlsPe.map((u, i) => (
                    <div key={i} className="y-item">
                      <div className="y-meta"><span className="y-val">{listValue(u)}</span></div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    );
  }

  // Office
  const office = record?.static?.office || {};
  const anomalies = Array.isArray(office?.anomalies) ? office.anomalies : [];
  const flags = office?.flags || {};
  
  return (
    <div className="card" style={{ marginTop: 12, display: 'grid', gap: 8 }}>
      <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="badge">Static Indicators</span>
        {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
      </div>
      <div className="grid">
        <KV label="Application" value={office?.metadata?.Application || '—'} />
        <KV label="Macros" value={(flags?.macro_present ? 'YES' : 'NO')} />
        <KV label="Auto-exec" value={(flags?.suspicious_auto_exec ? 'YES' : 'NO')} />
        <KV label="OS Cmd Indicators" value={(flags?.suspicious_shell_usage ? 'YES' : 'NO')} />
        <KV label="External links" value={String(counts?.external_references_total ?? 0)} />
        <KV label="Embedded" value={String(counts?.embedded_payloads_total ?? 0)} />
        <KV label="IOC URLs" value={String(counts?.ioc_urls_total ?? 0)} />
        <KV label="High-entropy embeds" value={String(counts?.high_entropy_embed_count ?? 0)} />
      </div>
      {urls.length > 0 && (
        <div>
          <strong>URLs</strong>
          <div className="y-list" style={{ 
            marginTop: 6,
            maxHeight: "120px",
            overflowY: "auto"
          }}>
            {urls.map((u, i) => (
              <div key={i} className="y-item">
                <div className="y-meta"><span className="y-val">{u}</span></div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}