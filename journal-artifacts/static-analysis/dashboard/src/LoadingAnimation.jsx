import React, { useState, useEffect } from 'react';
import fathomLogo from './fathom.jpg';

const LoadingAnimation = ({ isVisible, onComplete }) => {
  const [progress, setProgress] = useState(0);
  const [currentPhase, setCurrentPhase] = useState(0);
  
  const phases = [
    "Initializing analysis engine...",
    "Scanning file headers...",
    "Detecting file signatures...",
    "Running YARA rules...",
    "Analyzing structure...",
    "Extracting metadata...",
    "Computing entropy...",
    "Checking for threats...",
    "Generating report...",
    "Analysis complete!"
  ];

  useEffect(() => {
    if (!isVisible) {
      setProgress(0);
      setCurrentPhase(0);
      return;
    }

    const duration = 20000; // 20 seconds
    const interval = 100; // Update every 100ms
    const totalSteps = duration / interval;
    const phaseSteps = totalSteps / phases.length;
    
    let currentStep = 0;
    
    const timer = setInterval(() => {
      currentStep++;
      const newProgress = (currentStep / totalSteps) * 100;
      const newPhase = Math.floor(currentStep / phaseSteps);
      
      setProgress(Math.min(newProgress, 100));
      setCurrentPhase(Math.min(newPhase, phases.length - 1));
      
      if (currentStep >= totalSteps) {
        clearInterval(timer);
        setTimeout(() => {
          onComplete?.();
        }, 500);
      }
    }, interval);

    return () => clearInterval(timer);
  }, [isVisible, onComplete]);

  if (!isVisible) return null;

  return (
    <div className="loading-overlay">
      <div className="loading-container">
        {/* Animated Logo */}
        <div className="loading-logo-container">
          <img src={fathomLogo} alt="Fathom" className="loading-logo" />
          <div className="loading-logo-glow"></div>
          <div className="loading-logo-ring"></div>
        </div>
        
        {/* Main Title */}
        <h2 className="loading-title">Fathom Analysis Engine</h2>
        
        {/* Current Phase */}
        <div className="loading-phase">
          <span className="loading-phase-text">{phases[currentPhase]}</span>
        </div>
        
        {/* Progress Bar */}
        <div className="loading-progress-container">
          <div className="loading-progress-bar">
            <div 
              className="loading-progress-fill" 
              style={{ width: `${progress}%` }}
            ></div>
            <div className="loading-progress-glow"></div>
          </div>
          <span className="loading-percentage">{Math.round(progress)}%</span>
        </div>
        
        {/* Animated Particles */}
        <div className="loading-particles">
          {[...Array(12)].map((_, i) => (
            <div key={i} className={`loading-particle loading-particle-${i + 1}`}></div>
          ))}
        </div>
        
        {/* Status Indicators */}
        <div className="loading-indicators">
          <div className="loading-indicator active">
            <div className="loading-indicator-dot"></div>
            <span>Security Scan</span>
          </div>
          <div className="loading-indicator active">
            <div className="loading-indicator-dot"></div>
            <span>Deep Analysis</span>
          </div>
          <div className="loading-indicator active">
            <div className="loading-indicator-dot"></div>
            <span>Threat Detection</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoadingAnimation;