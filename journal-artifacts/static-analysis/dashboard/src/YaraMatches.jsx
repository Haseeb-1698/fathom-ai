// src/YaraMatches.jsx
export default function YaraMatches({ matches = [] }) {
  if (!matches || matches.length === 0) return null;

  return (
    <section className="section">
      <div className="y-head">
        <span className="pill pill-green">YARA</span>
        <span className="pill pill-muted">
          {matches.length} match{matches.length > 1 ? "es" : ""}
        </span>
      </div>

      <div className="y-list">
        {matches.map((m, i) => {
          const strong = m.tags?.includes("strong");
          const hint = m.tags?.includes("hint");
          return (
            <div key={i} className="y-item">
              <div className="y-line">
                <span className="y-dot" />
                <span className="y-rule">{m.rule}</span>
                {strong && <span className="pill pill-strong">strong</span>}
                {hint && <span className="pill pill-hint">hint</span>}
                {m.meta?.behavior && (
                  <span className="pill pill-muted">{m.meta.behavior}</span>
                )}
              </div>
              <div className="y-meta">
                <span className="y-cap">confidence:</span>{" "}
                <span className="y-val">
                  {m.meta?.confidence || "—"}
                </span>
                {m.meta?.family && (
                  <>
                    <span className="y-sep">•</span>
                    <span className="y-cap">family:</span>{" "}
                    <span className="y-val">{m.meta.family}</span>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
