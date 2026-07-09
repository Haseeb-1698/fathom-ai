import React, { useEffect, useRef } from 'react';

const InteractiveEnhancer = ({ children }) => {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Add interactive classes to elements
    const addInteractiveClasses = () => {
      // Cards
      const cards = container.querySelectorAll('.card');
      cards.forEach(card => {
        card.classList.add('interactive-element', 'ripple', 'hover-zone');
      });

      // Buttons
      const buttons = container.querySelectorAll('.btn');
      buttons.forEach(btn => {
        btn.classList.add('interactive-element', 'ripple', 'glow-on-hover');
      });

      // Pills
      const pills = container.querySelectorAll('.pill');
      pills.forEach(pill => {
        pill.classList.add('interactive-element', 'micro-bounce');
      });

      // Badges
      const badges = container.querySelectorAll('.badge');
      badges.forEach(badge => {
        badge.classList.add('interactive-element', 'scale-on-hover');
      });

      // Code blocks
      const codes = container.querySelectorAll('code');
      codes.forEach(code => {
        code.classList.add('interactive-element', 'glow-on-hover');
      });

      // YARA items
      const yaraItems = container.querySelectorAll('.y-item');
      yaraItems.forEach(item => {
        item.classList.add('interactive-element', 'hover-zone');
      });

      // Sections
      const sections = container.querySelectorAll('.section');
      sections.forEach(section => {
        section.classList.add('slide-on-hover');
      });

      // Key-value pairs
      const kvs = container.querySelectorAll('.kv');
      kvs.forEach(kv => {
        kv.classList.add('interactive-element');
      });

      // Reason boxes
      const reasons = container.querySelectorAll('.reason');
      reasons.forEach(reason => {
        reason.classList.add('interactive-element', 'hover-zone');
      });
    };

    // Mouse tracking for simple hover effects (no tilt)
    const handleMouseMove = (e) => {
      const cards = container.querySelectorAll('.card');
      cards.forEach(card => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        if (x >= 0 && x <= rect.width && y >= 0 && y <= rect.height) {
          card.style.transform = `
            translateY(-3px) 
            scale(1.01)
          `;
        }
      });
    };

    const handleMouseLeave = () => {
      const cards = container.querySelectorAll('.card');
      cards.forEach(card => {
        card.style.transform = '';
      });
    };

    // Click effects
    const handleClick = (e) => {
      const element = e.target.closest('.ripple');
      if (!element) return;

      // Create ripple effect
      const ripple = document.createElement('span');
      const rect = element.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;

      ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${x}px;
        top: ${y}px;
        background: radial-gradient(circle, rgba(57, 255, 20, 0.6) 0%, transparent 70%);
        border-radius: 50%;
        transform: scale(0);
        animation: rippleEffect 0.6s ease-out;
        pointer-events: none;
        z-index: 1000;
      `;

      element.style.position = 'relative';
      element.appendChild(ripple);

      setTimeout(() => {
        ripple.remove();
      }, 600);
    };

    // Copy to clipboard functionality
    const handleCodeClick = (e) => {
      const code = e.target.closest('code');
      if (!code) return;

      const text = code.textContent;
      navigator.clipboard.writeText(text).then(() => {
        // Show feedback
        const feedback = document.createElement('div');
        feedback.textContent = 'Copied!';
        feedback.style.cssText = `
          position: absolute;
          top: -30px;
          left: 50%;
          transform: translateX(-50%);
          background: var(--accent-neon);
          color: #000000;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 12px;
          font-weight: 600;
          z-index: 1000;
          animation: fadeInOut 2s ease-in-out;
        `;

        code.style.position = 'relative';
        code.appendChild(feedback);

        setTimeout(() => {
          feedback.remove();
        }, 2000);
      }).catch(() => {
        // Fallback for older browsers
        console.log('Copy failed');
      });
    };

    // Keyboard interactions
    const handleKeyDown = (e) => {
      // Add keyboard shortcuts
      if (e.ctrlKey || e.metaKey) {
        switch (e.key) {
          case 'c':
            if (e.target.tagName === 'CODE') {
              e.preventDefault();
              handleCodeClick({ target: e.target });
            }
            break;
          case 'r':
            e.preventDefault();
            // Refresh animation
            const elements = container.querySelectorAll('.interactive-element');
            elements.forEach(el => {
              el.style.animation = 'none';
              el.offsetHeight; // Trigger reflow
              el.style.animation = null;
            });
            break;
        }
      }
    };

    // Intersection Observer for scroll animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.animation = 'fadeInUp 0.6s ease-out';
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
        }
      });
    }, observerOptions);

    // Initialize
    addInteractiveClasses();

    // Observe elements for scroll animations
    const animatedElements = container.querySelectorAll('.card, .section, .y-item');
    animatedElements.forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(20px)';
      observer.observe(el);
    });

    // Add event listeners
    container.addEventListener('mousemove', handleMouseMove);
    container.addEventListener('mouseleave', handleMouseLeave);
    container.addEventListener('click', handleClick);
    container.addEventListener('click', handleCodeClick);
    document.addEventListener('keydown', handleKeyDown);

    // Cleanup
    return () => {
      container.removeEventListener('mousemove', handleMouseMove);
      container.removeEventListener('mouseleave', handleMouseLeave);
      container.removeEventListener('click', handleClick);
      container.removeEventListener('click', handleCodeClick);
      document.removeEventListener('keydown', handleKeyDown);
      observer.disconnect();
    };
  }, []);

  return (
    <div ref={containerRef} className="interactive-container">
      {children}
    </div>
  );
};

export default InteractiveEnhancer;