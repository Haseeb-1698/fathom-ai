import React, { useState, useEffect } from 'react';

const BugCompanion = ({ fileType, isVisible = true }) => {
  const [currentFact, setCurrentFact] = useState('');
  const [isAnimating, setIsAnimating] = useState(false);
  const [bugPosition, setBugPosition] = useState('right');
  const [showBubble, setShowBubble] = useState(false);

  // Fun facts database for different file types
  const funFacts = {
    pdf: [
      "🐛 Did you know? PDF stands for Portable Document Format and was created by Adobe in 1993!",
      "🕷️ Fun fact: The first PDF viewer was called 'Carousel' and ran on NeXT computers!",
      "🐞 Buzz buzz! PDFs can contain JavaScript - that's why I help scan them for safety!",
      "🦗 Chirp! The PDF format can embed 3D models, videos, and interactive forms!",
      "🐛 Psst! PDF files use compression to stay small - like how I squeeze into tiny spaces!"
    ],
    office_ooxml: [
      "🕷️ Web fact! OOXML files are actually ZIP archives in disguise - I love hidden things!",
      "🐞 Buzz! Microsoft Office documents can contain VBA macros - that's my specialty to detect!",
      "🦗 Did you know? OOXML was standardized as ISO/IEC 29500 in 2008!",
      "🐛 Fun fact: Word documents can embed other files inside them - like nesting dolls!",
      "🕸️ Spider sense! OOXML uses XML markup language - it's like a web of data!"
    ],
    office_ole: [
      "🐞 Vintage vibes! OLE files use the old Compound Document format from the 90s!",
      "🦗 Chirp chirp! OLE stands for Object Linking and Embedding - fancy tech talk!",
      "🐛 Fun fact: These files store data in 'streams' - like how I navigate through code!",
      "🕷️ Web wisdom: OLE files can contain multiple embedded objects in one file!",
      "🐞 Buzz! The OLE format inspired modern container formats - evolution in action!"
    ],
    pe: [
      "🐛 Executable excitement! PE files are Windows programs - I scan them for safety!",
      "🕷️ Did you know? PE stands for Portable Executable - they're quite portable indeed!",
      "🦗 Fun fact: PE files have a DOS header for backward compatibility - vintage tech!",
      "🐞 Buzz buzz! These files contain machine code that CPUs can understand directly!",
      "🕸️ Spider fact: PE files have sections like .text, .data, and .rsrc - organized like my web!"
    ],
    dll: [
      "🐞 Library love! DLL stands for Dynamic Link Library - shared code for programs!",
      "🦗 Chirp! DLLs help programs share functionality - like how bugs share pheromones!",
      "🐛 Fun fact: Windows loads DLLs on demand to save memory - efficient like my web!",
      "🕷️ Did you know? DLL Hell was a real problem in early Windows - glad that's fixed!",
      "🐞 Buzz! DLLs can be loaded at runtime - dynamic like my movements!"
    ],
    zip: [
      "🐛 Compression magic! ZIP files squeeze data smaller - like how I fit in tight spaces!",
      "🕷️ Fun fact: The ZIP format was created by Phil Katz in 1989 - thanks Phil!",
      "🦗 Did you know? ZIP files use the DEFLATE algorithm for compression!",
      "🐞 Buzz! You can password-protect ZIP files - security is important!",
      "🕸️ Spider sense! ZIP files can contain other ZIP files - inception!"
    ],
    unknown: [
      "🐛 Mystery file! I love a good puzzle - let me investigate this unknown format!",
      "🕷️ Unknown doesn't mean unsafe - but I'll keep my eight eyes on it!",
      "🦗 Chirp! Every file has a story - this one's just being shy about its format!",
      "🐞 Buzz buzz! Sometimes files disguise themselves - good thing I'm a detective!",
      "🕸️ Web wisdom: Unknown files are opportunities to learn something new!"
    ]
  };

  // Get appropriate bug emoji based on file type
  const getBugEmoji = (type) => {
    const bugTypes = {
      pdf: '🐞',        // Ladybug for PDFs
      office_ooxml: '🕷️', // Spider for Office files
      office_ole: '🦗',    // Cricket for old Office
      pe: '🐛',         // Bug for executables
      dll: '🐞',        // Ladybug for DLLs
      zip: '🕸️',        // Spider web for archives
      unknown: '🦋'     // Butterfly for unknown
    };
    return bugTypes[type] || '🐛';
  };

  // Get random fact for current file type
  const getRandomFact = (type) => {
    const facts = funFacts[type] || funFacts.unknown;
    return facts[Math.floor(Math.random() * facts.length)];
  };

  // Show new fact
  const showNewFact = () => {
    if (!fileType) return;
    
    setIsAnimating(true);
    setShowBubble(false);
    
    setTimeout(() => {
      setCurrentFact(getRandomFact(fileType));
      setShowBubble(true);
      setIsAnimating(false);
    }, 300);
  };

  // Switch sides randomly
  const switchSides = () => {
    setBugPosition(bugPosition === 'right' ? 'left' : 'right');
  };

  // Initialize with first fact
  useEffect(() => {
    if (fileType && isVisible) {
      setTimeout(() => {
        showNewFact();
      }, 2000); // Show first fact after 2 seconds
    }
  }, [fileType, isVisible]);

  // Auto-rotate facts every 15 seconds
  useEffect(() => {
    if (!isVisible || !fileType) return;

    const factInterval = setInterval(() => {
      showNewFact();
    }, 15000);

    const positionInterval = setInterval(() => {
      switchSides();
    }, 30000);

    return () => {
      clearInterval(factInterval);
      clearInterval(positionInterval);
    };
  }, [isVisible, fileType, bugPosition]);

  if (!isVisible || !fileType) return null;

  return (
    <>
      {/* Bug Character */}
      <div 
        className={`bug-companion ${bugPosition} ${isAnimating ? 'animating' : ''}`}
        onClick={showNewFact}
        title="Click me for a fun fact!"
      >
        <div className="bug-body">
          <span className="bug-emoji">{getBugEmoji(fileType)}</span>
          <div className="bug-eyes">
            <div className="eye left-eye"></div>
            <div className="eye right-eye"></div>
          </div>
        </div>
        
        {/* Cute little legs */}
        <div className="bug-legs">
          <div className="leg leg-1"></div>
          <div className="leg leg-2"></div>
          <div className="leg leg-3"></div>
        </div>
      </div>

      {/* Speech Bubble */}
      {showBubble && currentFact && (
        <div className={`bug-speech-bubble ${bugPosition}`}>
          <div className="bubble-content">
            <p>{currentFact}</p>
            <button 
              className="bubble-close"
              onClick={() => setShowBubble(false)}
              title="Close"
            >
              ×
            </button>
          </div>
          <div className="bubble-tail"></div>
        </div>
      )}

      {/* Bug Trail Effect */}
      <div className={`bug-trail ${bugPosition}`}>
        <div className="trail-dot trail-dot-1"></div>
        <div className="trail-dot trail-dot-2"></div>
        <div className="trail-dot trail-dot-3"></div>
      </div>
    </>
  );
};

export default BugCompanion;