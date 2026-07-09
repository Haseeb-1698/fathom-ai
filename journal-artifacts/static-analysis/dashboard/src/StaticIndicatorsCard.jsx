// StaticIndicatorsCard.jsx — mini card for Basic tab (when final_guess === 'pdf')
// Props: { record }

function KV({ label, value }) {
  return (
    <div className="kv">
      <label>{label}</label>
      <code>{value}</code>
    </div>
  );
}

export default function StaticIndicatorsCard({ record }) {
  const counts = record?.counts || {};
  const finalType = (record?.final_guess?.type || '').toLowerCase();
  const isPdf = finalType === 'pdf';
  const isOffice = finalType === 'office_ooxml' || finalType === 'office_ole' || !!record?.static?.office;
  const isPe = finalType === 'pe' || finalType === 'dll' || !!record?.static?.pe;
  
  if (!isPdf && !isOffice && !isPe) return null;

  if (isPdf) {
    const pdf = record?.static?.pdf || {};
    const anomalies = Array.isArray(pdf?.anomalies) ? pdf.anomalies : [];
    return (
      <div className="card" style={{ marginTop: 12 }}>
        <div className="row" style={{ gap: 8, alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="badge">Static Indicators</span>
          {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
        </div>
        <div className="grid" style={{ marginTop: 8 }}>
          <KV label="JS" value={(counts?.js_objects_total ?? 0) > 0 ? 'YES' : 'NO'} />
          <KV label="Auto actions" value={(counts?.auto_actions_total ?? 0) > 0 ? 'YES' : 'NO'} />
          <KV label="URLs" value={String(counts?.urls_total ?? 0)} />
          <KV label="Embedded files" value={String(counts?.embedded_files_total ?? 0)} />
          <KV label="IOC URLs" value={String(counts?.ioc_urls_total ?? 0)} />
          <KV label="High-entropy streams" value={String(counts?.high_entropy_stream_count ?? 0)} />
        </div>
      </div>
    );
  }

  if (isPe) {
    const DASH = "—";
    const pe = record?.static?.pe || {};
    const anomalies = Array.isArray(pe?.anomalies) ? pe.anomalies : [];
    const signature = (pe?.signatures || {}).authenticode || {};
    const overlay = pe?.overlay || {};
    const strings = pe?.strings || {};
    const suspiciousImportsTotal = counts?.suspicious_imports_total ?? 0;
    const highEntropySections = counts?.high_entropy_section_count ?? 0;
    const yaraTotal = counts?.yara_matches_total ?? 0;
    const overlayPresent = overlay?.present === true;
    const iocCount = Array.isArray(strings?.ioc_urls) ? strings.ioc_urls.length : 0;

    const yesNo = (value) => (value === true ? 'YES' : value === false ? 'NO' : DASH);
    const countValue = (value) => (Number.isFinite(value) ? String(value) : DASH);

    return (
      <div className="card" style={{ marginTop: 12 }}>
        <div className="row" style={{ gap: 8, alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="badge">Static Indicators</span>
          {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
        </div>
        <div className="grid" style={{ marginTop: 8 }}>
          <KV label="Digitally signed" value={yesNo(signature?.present === true)} />
          <KV label="Can launch or load other programs" value={yesNo(suspiciousImportsTotal > 0)} />
          <KV label="Possible packed/encrypted parts" value={yesNo(highEntropySections > 0)} />
          <KV label="Contains extra hidden data" value={yesNo(overlayPresent)} />
          <KV label="Behavior signatures (rules hit)" value={countValue(yaraTotal)} />
          <KV label="Links found inside" value={countValue(iocCount)} />
        </div>
      </div>
    );
  }

  // Office
  const office = record?.static?.office || {};
  const anomalies = Array.isArray(office?.anomalies) ? office.anomalies : [];
  const flags = office?.flags || {};
  
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <div className="row" style={{ gap: 8, alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="badge">Static Indicators</span>
        {anomalies.length > 0 && <span className="pill pill-strong">anomalies</span>}
      </div>
      <div className="grid" style={{ marginTop: 8 }}>
        <KV label="Macros" value={(flags?.macro_present ? 'YES' : 'NO')} />
        <KV label="Auto-exec" value={(flags?.suspicious_auto_exec ? 'YES' : 'NO')} />
        <KV label="OS Cmd Indicators" value={(flags?.suspicious_shell_usage ? 'YES' : 'NO')} />
        <KV label="External links" value={String(counts?.external_references_total ?? 0)} />
        <KV label="Embedded payloads" value={String(counts?.embedded_payloads_total ?? 0)} />
        <KV label="IOC URLs" value={String(counts?.ioc_urls_total ?? 0)} />
        <KV label="High-entropy embeds" value={String(counts?.high_entropy_embed_count ?? 0)} />
      </div>
    </div>
  );
}