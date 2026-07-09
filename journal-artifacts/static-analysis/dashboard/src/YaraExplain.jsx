// src/YaraExplain.jsx
const RULE_EXPLANATIONS = {
  // PDF
  PDF_Basic_Robust:
    "Identifies a PDF file by locating the %PDF- header within the first kilobyte, allowing for minor leading bytes.",
  PDF_Structure_OK:
    "Confirms typical PDF structure: a %PDF- header plus tail markers like startxref and %%EOF.",
  PDF_With_JavaScript_Strict:
    "Flags PDFs that contain embedded JavaScript (tokens /JavaScript or /JS).",
  PDF_With_AutoAction_Soft:
    "Hints that a PDF may auto-run actions (OpenAction/AA) such as Launch/URI/EmbeddedFile; often benign but worth review.",

  // Office / OLE / OOXML
  OLE_CFB_Header:
    "Detects legacy Office Compound File Binary (OLE/CFB) format by its header signature at the file start.",
  Office_VBA_Project:
    "Indicates presence of a VBA macro project (vbaProject.bin).",
  OOXML_Package_Basic:
    "Detects modern Office OOXML packages (docx/xlsx/pptx) via ZIP header and Office folder layout.",
  OOXML_VBA_Present:
    "OOXML package that contains a VBA macro project (vbaProject.bin).",

  // PE
  PE_File_Basic:
    "Matches Windows PE files (EXE/DLL/SYS) by DOS MZ header and a valid PE signature.",
  PE_EXE:
    "Specifically identifies a Windows executable where the DLL flag is not set.",
  PE_DLL:
    "Specifically identifies a Windows DLL by the IMAGE_FILE_DLL flag.",
  PE_UPX_Packed:
    "Heuristic for UPX-packed PE: typical section names, high entropy sections, or UPX marker present.",
};

function explainSentence(rule, meta = {}, tags = []) {
  // Prefer curated text when known
  if (RULE_EXPLANATIONS[rule]) return RULE_EXPLANATIONS[rule];

  // Build a friendly sentence from meta
  const parts = [];
  if (meta.purpose) parts.push(meta.purpose);
  if (meta.description && meta.description !== meta.purpose) parts.push(meta.description);
  if (meta.behavior) parts.push(`behavior: ${meta.behavior}`);
  if (meta.subtype) parts.push(`subtype: ${meta.subtype}`);
  if (meta.packer) parts.push(`packer: ${meta.packer}`);
  const joined = parts.join(" — ");
  if (joined) return `Detects ${joined}.`;
  // Fallback to a generic message
  const family = meta.family ? `${meta.family} ` : "";
  const tone = tags?.includes("hint") ? "Provides a hint that" : "Indicates that";
  return `${tone} this file matches a ${family}rule named ${rule}.`;
}

export default function YaraExplain({ matches = [] }) {
  if (!matches || matches.length === 0) {
    return (
      <div className="card">
        <span className="badge">No YARA matches</span>
        <p style={{ marginTop: 8, color: "var(--ink-3)" }}>
          When rules match, this tab explains what each rule is looking for and
          why it might matter.
        </p>
      </div>
    );
  }

  const explainLine = (m) => explainSentence(m.rule, m.meta, m.tags);

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <div className="row" style={{ gap: 10 }}>
          <span className="badge">YARA</span>
          <span className="pill pill-muted">{matches.length} explanation{matches.length>1?"s":""}</span>
        </div>
      </div>

      <div className="hr" />

      <p className="explain-intro">
        YARA rules are pattern-based signatures. They do not execute the file —
        they match byte sequences, strings, or structural attributes. High-confidence
        rules are strong indicators; “hint” tags mean informational context.
      </p>

      <div className="y-list" style={{ marginTop: 10 }}>
        {matches.map((m, i) => {
          const strong = m.tags?.includes("strong");
          const hint = m.tags?.includes("hint");
          const meta = m.meta || {};
          const summary = explainLine(m);
          return (
            <div key={i} className="y-item">
              <div className="y-line">
                <span className="y-dot" />
                <span className="y-rule">{m.rule}</span>
                {strong && <span className="pill pill-strong">strong</span>}
                {hint && <span className="pill pill-hint">hint</span>}
                {meta.family && (
                  <span className="pill pill-muted">{meta.family}</span>
                )}
              </div>
              {summary && (
                <div className="y-meta" style={{ marginLeft: "1.05rem" }}>
                  <span className="y-val">{summary}</span>
                </div>
              )}
              <div className="y-meta" style={{ marginLeft: "1.05rem" }}>
                <span className="y-cap">confidence:</span>
                <span className="y-val">{meta.confidence || "—"}</span>
                {m.tags?.length ? (
                  <>
                    <span className="y-sep">•</span>
                    <span className="y-cap">tags:</span>
                    <span className="y-val">{m.tags.join(", ")}</span>
                  </>
                ) : null}
                {meta.notes ? (
                  <>
                    <span className="y-sep">•</span>
                    <span className="y-cap">notes:</span>
                    <span className="y-val">{meta.notes}</span>
                  </>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
