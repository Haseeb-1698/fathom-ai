import { useState } from "react";
import UploadPanel from "./UploadPanel";
import InteractiveEnhancer from "./InteractiveEnhancer";
import "./styles.css";
import fathomLogo from "./fathom.jpg";

export default function App() {
  const [lastResult, setLastResult] = useState(null);

  return (
    <InteractiveEnhancer>
      <div className="container">
        <h1 className="app-title interactive-element">
          <img src={fathomLogo} alt="Fathom Logo" className="fathom-logo interactive-element" />
          Fathom Dashboard
        </h1>
        <p className="subtitle">Advanced file analysis and threat detection platform</p>

        <UploadPanel onResult={setLastResult} />

        {/* Optional: a tiny footer with route suggestion if present */}
        {lastResult?.route && (
          <>
            <div className="hr interactive-element" />
            <div className="row">
              <span className="badge interactive-element">Suggested route: {lastResult.route}</span>
            </div>
          </>
        )}
      </div>
    </InteractiveEnhancer>
  );
}
