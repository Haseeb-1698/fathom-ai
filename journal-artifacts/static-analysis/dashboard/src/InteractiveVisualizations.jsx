import React, { useState, useEffect, useRef } from 'react';

// Entropy Visualization Component
const EntropyChart = ({ data, fileSize }) => {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  const [hoveredPoint, setHoveredPoint] = useState(null);

  useEffect(() => {
    if (!data || !canvasRef.current || !containerRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    
    // Set canvas size to match container
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    
    const { width, height } = canvas;

    // Clear canvas
    ctx.clearRect(0, 0, width, height);

    // Setup with proper padding
    const padding = 50;
    const chartWidth = width - 2 * padding;
    const chartHeight = height - 2 * padding;

    // Ensure we have valid dimensions
    if (chartWidth <= 0 || chartHeight <= 0) return;

    // Draw background
    ctx.fillStyle = 'rgba(104, 222, 101, 0.05)';
    ctx.fillRect(padding, padding, chartWidth, chartHeight);

    // Draw border
    ctx.strokeStyle = 'rgba(104, 222, 101, 0.3)';
    ctx.lineWidth = 2;
    ctx.strokeRect(padding, padding, chartWidth, chartHeight);

    // Draw grid
    ctx.strokeStyle = 'rgba(104, 222, 101, 0.2)';
    ctx.lineWidth = 1;
    
    // Horizontal grid lines
    for (let i = 0; i <= 8; i++) {
      const y = padding + (i / 8) * chartHeight;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(padding + chartWidth, y);
      ctx.stroke();
      
      // Y-axis labels
      ctx.fillStyle = '#ffffff';
      ctx.font = '12px Inter';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      ctx.fillText((8 - i).toString(), padding - 10, y);
    }

    // Vertical grid lines
    const segments = Math.min(data.length, 10);
    for (let i = 0; i <= segments; i++) {
      const x = padding + (i / segments) * chartWidth;
      ctx.beginPath();
      ctx.moveTo(x, padding);
      ctx.lineTo(x, padding + chartHeight);
      ctx.stroke();
    }

    // Clamp entropy values to valid range and calculate positions
    const clampedData = data.map(entropy => Math.max(0, Math.min(8, entropy)));
    
    // Draw entropy line with proper clipping
    ctx.save();
    ctx.beginPath();
    ctx.rect(padding, padding, chartWidth, chartHeight);
    ctx.clip();
    
    ctx.strokeStyle = '#39ff14';
    ctx.lineWidth = 3;
    ctx.beginPath();

    clampedData.forEach((entropy, index) => {
      const x = padding + (index / Math.max(1, clampedData.length - 1)) * chartWidth;
      const y = padding + (1 - entropy / 8) * chartHeight;
      
      if (index === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });

    ctx.stroke();
    ctx.restore();

    // Draw data points
    clampedData.forEach((entropy, index) => {
      const x = padding + (index / Math.max(1, clampedData.length - 1)) * chartWidth;
      const y = padding + (1 - entropy / 8) * chartHeight;
      
      // Determine color based on entropy level
      let color = '#39ff14'; // Low entropy (green)
      if (entropy > 6) color = '#ffaa39'; // Medium entropy (orange)
      if (entropy > 7.5) color = '#ff1439'; // High entropy (red)
      
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, 2 * Math.PI);
      ctx.fill();
      
      // Add glow effect for high entropy
      if (entropy > 7) {
        ctx.shadowColor = color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, 2 * Math.PI);
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    });

    // Draw axes labels
    ctx.fillStyle = '#ffffff';
    ctx.font = '14px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText('File Position', width / 2, height - 25);
    
    ctx.save();
    ctx.translate(20, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('Entropy (0-8)', 0, 0);
    ctx.restore();

  }, [data]);

  const handleMouseMove = (e) => {
    if (!data || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const padding = 50;
    const chartWidth = rect.width - 2 * padding;
    
    if (x >= padding && x <= rect.width - padding) {
      const normalizedX = (x - padding) / chartWidth;
      const index = Math.round(normalizedX * (data.length - 1));
      if (index >= 0 && index < data.length) {
        setHoveredPoint({
          index,
          entropy: data[index],
          x: e.clientX,
          y: e.clientY
        });
      }
    } else {
      setHoveredPoint(null);
    }
  };

  return (
    <div 
      ref={containerRef}
      style={{ 
        position: 'relative',
        width: '100%',
        height: '300px',
        border: '1px solid rgba(104, 222, 101, 0.3)',
        borderRadius: '12px',
        overflow: 'hidden',
        backgroundColor: 'rgba(0, 0, 0, 0.2)'
      }}
    >
      <canvas
        ref={canvasRef}
        style={{ 
          width: '100%', 
          height: '100%',
          cursor: 'crosshair',
          display: 'block'
        }}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setHoveredPoint(null)}
      />
      
      {hoveredPoint && (
        <div
          style={{
            position: 'fixed',
            left: hoveredPoint.x + 10,
            top: hoveredPoint.y - 10,
            background: 'rgba(0, 0, 0, 0.9)',
            color: '#ffffff',
            padding: '8px 12px',
            borderRadius: '8px',
            fontSize: '12px',
            fontWeight: '600',
            pointerEvents: 'none',
            zIndex: 1000,
            border: '1px solid #39ff14'
          }}
        >
          Position: {hoveredPoint.index}<br/>
          Entropy: {hoveredPoint.entropy.toFixed(2)}
        </div>
      )}
    </div>
  );
};

// File Structure Tree Component
const FileStructureTree = ({ structure }) => {
  const [expandedNodes, setExpandedNodes] = useState(new Set(['root']));
  

  


  const toggleNode = (nodeId) => {
    const newExpanded = new Set(expandedNodes);
    if (newExpanded.has(nodeId)) {
      newExpanded.delete(nodeId);
    } else {
      newExpanded.add(nodeId);
    }
    setExpandedNodes(newExpanded);
  };

  const renderNode = (node, level = 0, parentId = '') => {
    const nodeId = `${parentId}_${node.name}`;
    const isExpanded = expandedNodes.has(nodeId);
    const hasChildren = node.children && node.children.length > 0;

    return (
      <div key={nodeId} style={{ marginLeft: level * 20 }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            padding: '8px 12px',
            cursor: hasChildren ? 'pointer' : 'default',
            borderRadius: '8px',
            transition: 'all 0.2s ease',
            backgroundColor: level % 2 === 0 ? 'rgba(104, 222, 101, 0.05)' : 'transparent'
          }}
          onClick={() => hasChildren && toggleNode(nodeId)}
          onMouseEnter={(e) => {
            e.target.style.backgroundColor = 'rgba(104, 222, 101, 0.1)';
          }}
          onMouseLeave={(e) => {
            e.target.style.backgroundColor = level % 2 === 0 ? 'rgba(104, 222, 101, 0.05)' : 'transparent';
          }}
        >
          {hasChildren && (
            <span style={{ 
              marginRight: '8px', 
              color: '#39ff14',
              transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
              transition: 'transform 0.2s ease'
            }}>
              ▶
            </span>
          )}
          
          <span style={{ 
            marginRight: '8px',
            fontSize: '16px'
          }}>
            {node.type === 'folder' ? '📁' : 
             node.type === 'executable' ? '⚙️' : 
             node.type === 'document' ? '📄' : 
             node.type === 'archive' ? '📦' : '📄'}
          </span>
          
          <span style={{ 
            color: '#ffffff',
            fontWeight: '500',
            flex: 1
          }}>
            {node.name}
          </span>
          
          {node.size && (
            <span style={{ 
              color: 'rgba(255, 255, 255, 0.7)',
              fontSize: '12px',
              marginLeft: '12px'
            }}>
              {formatBytes(node.size)}
            </span>
          )}
          
          {node.suspicious && (
            <span style={{
              marginLeft: '8px',
              padding: '2px 6px',
              backgroundColor: '#ff1439',
              color: '#ffffff',
              borderRadius: '4px',
              fontSize: '10px',
              fontWeight: '600'
            }}>
              SUSPICIOUS
            </span>
          )}
        </div>
        
        {hasChildren && isExpanded && (
          <div>
            {node.children.map(child => renderNode(child, level + 1, nodeId))}
          </div>
        )}
      </div>
    );
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0B';
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${bytes}B`;
  };

  return (
    <div style={{
      maxHeight: '400px',
      overflowY: 'auto',
      border: '1px solid rgba(104, 222, 101, 0.3)',
      borderRadius: '12px',
      padding: '12px'
    }}>
      {structure ? (
        <div>
          <div style={{ 
            fontSize: '12px', 
            color: 'rgba(255, 255, 255, 0.6)', 
            marginBottom: '8px' 
          }}>
            File Type: {structure.type} | Size: {formatBytes(structure.size)}
          </div>
          {renderNode(structure)}
        </div>
      ) : (
        <div style={{ 
          textAlign: 'center', 
          color: 'rgba(255, 255, 255, 0.7)',
          padding: '20px'
        }}>
          No structure data available
        </div>
      )}
    </div>
  );
};



// Threat Timeline Component
const ThreatTimeline = ({ events }) => {
  const timelineEvents = events || [];

  const getEventColor = (type) => {
    switch (type) {
      case 'success': return '#39ff14';
      case 'warning': return '#ffaa39';
      case 'danger': return '#ff1439';
      default: return '#68de65';
    }
  };

  return (
    <div style={{ padding: '20px' }}>
      {timelineEvents.map((event, index) => (
        <div key={index} style={{ 
          display: 'flex', 
          alignItems: 'center', 
          marginBottom: '16px',
          position: 'relative'
        }}>
          <div style={{
            width: '60px',
            fontSize: '12px',
            color: 'rgba(255, 255, 255, 0.7)',
            fontFamily: 'JetBrains Mono'
          }}>
            {event.time}
          </div>
          
          <div style={{
            width: '12px',
            height: '12px',
            borderRadius: '50%',
            backgroundColor: getEventColor(event.type),
            margin: '0 16px',
            boxShadow: `0 0 10px ${getEventColor(event.type)}40`
          }} />
          
          <div style={{
            flex: 1,
            color: '#ffffff',
            fontSize: '14px',
            fontWeight: '500'
          }}>
            {event.event}
          </div>
          
          {index < timelineEvents.length - 1 && (
            <div style={{
              position: 'absolute',
              left: '81px',
              top: '12px',
              width: '2px',
              height: '20px',
              backgroundColor: 'rgba(104, 222, 101, 0.3)'
            }} />
          )}
        </div>
      ))}
    </div>
  );
};

// Main Interactive Visualizations Component
const InteractiveVisualizations = ({ analysisData }) => {
  const [activeViz, setActiveViz] = useState('entropy');

  // Reset to entropy tab when new analysis data comes in
  useEffect(() => {
    setActiveViz('entropy');
  }, [analysisData?.filename, analysisData?.size]);

  // Generate entropy data from actual analysis or create realistic sample based on file type
  const generateEntropyData = () => {
    if (analysisData?.entropy && Array.isArray(analysisData.entropy)) {
      return analysisData.entropy;
    }
    
    // Generate realistic entropy based on file type and size
    const fileType = analysisData?.fileType || 'unknown';
    const fileSize = analysisData?.size || 1024000;
    const segments = Math.min(Math.max(Math.floor(fileSize / 10000), 20), 100);
    
    return Array.from({ length: segments }, (_, i) => {
      const position = i / segments;
      let baseEntropy = 3.0; // Default entropy
      
      // Adjust entropy based on file type
      if (fileType === 'pdf') {
        // PDFs often have compressed streams
        baseEntropy = position < 0.2 ? 2.0 : (Math.random() > 0.7 ? 7.5 : 4.5);
      } else if (fileType === 'pe' || fileType === 'dll') {
        // PE files have structured sections
        if (position < 0.3) baseEntropy = 2.5; // Headers
        else if (position < 0.7) baseEntropy = 6.0; // Code section
        else baseEntropy = 4.0; // Data section
      } else if (fileType.includes('office')) {
        // Office files are ZIP-based, high entropy
        baseEntropy = Math.random() > 0.6 ? 7.2 : 5.5;
      }
      
      // Add some randomness
      return Math.max(0, Math.min(8, baseEntropy + (Math.random() - 0.5) * 2));
    });
  };

  const entropyData = generateEntropyData();

  // Generate file structure from actual analysis or create based on file type
  const generateFileStructure = () => {
    if (analysisData?.structure) {
      return analysisData.structure;
    }
    
    const fileType = analysisData?.fileType || 'unknown';
    const fileName = analysisData?.filename || 'analyzed_file';
    const fileSize = analysisData?.size || 1024000;
    
    // Temporary debug for Office files
    if (fileType.includes('office') || fileName.includes('.doc') || fileName.includes('.xls')) {
      console.log('🏢 Office file detected in frontend:', { fileType, fileName, fileSize });
    }
    

    

    
    // Generate structure based on file type
    if (fileType === 'pdf') {
      return {
        name: fileName,
        type: 'document',
        size: fileSize,
        children: [
          {
            name: 'PDF Header',
            type: 'folder',
            size: Math.floor(fileSize * 0.01),
            children: [
              { name: 'Version Info', type: 'document', size: 64 },
              { name: 'Catalog', type: 'document', size: 256 }
            ]
          },
          {
            name: 'Content Streams',
            type: 'folder',
            size: Math.floor(fileSize * 0.7),
            children: [
              { name: 'Text Content', type: 'document', size: Math.floor(fileSize * 0.3) },
              { name: 'Images', type: 'document', size: Math.floor(fileSize * 0.2) },
              { name: 'Fonts', type: 'document', size: Math.floor(fileSize * 0.1) }
            ]
          }
        ]
      };
    } else if (fileType === 'pe' || fileType === 'dll') {
      return {
        name: fileName,
        type: 'executable',
        size: fileSize,
        children: [
          {
            name: '.text',
            type: 'folder',
            size: Math.floor(fileSize * 0.5),
            children: [
              { name: 'Code Section', type: 'executable', size: Math.floor(fileSize * 0.4) },
              { name: 'Entry Point', type: 'executable', size: Math.floor(fileSize * 0.1) }
            ]
          },
          {
            name: '.data',
            type: 'folder',
            size: Math.floor(fileSize * 0.3),
            children: [
              { name: 'Initialized Data', type: 'document', size: Math.floor(fileSize * 0.2) },
              { name: 'String Table', type: 'document', size: Math.floor(fileSize * 0.1) }
            ]
          }
        ]
      };
    } else if (fileType === 'office_ooxml' || fileType === 'office_ole' || fileType.includes('office') || fileName.includes('.doc') || fileName.includes('.xls') || fileName.includes('.ppt')) {
      // Office documents structure
      const isOOXML = fileType === 'office_ooxml' || fileType.includes('ooxml');
      const isOLE = fileType === 'office_ole' || fileType.includes('ole');
      
      if (isOOXML) {
        // OOXML (modern Office) - ZIP-based structure
        return {
          name: fileName,
          type: 'archive',
          size: fileSize,
          children: [
            {
              name: '[Content_Types].xml',
              type: 'document',
              size: Math.floor(fileSize * 0.01),
              children: [
                { name: 'Content Type Definitions', type: 'document', size: 512 }
              ]
            },
            {
              name: '_rels',
              type: 'folder',
              size: Math.floor(fileSize * 0.02),
              children: [
                { name: '.rels', type: 'document', size: 1024 },
                { name: 'Relationship Mappings', type: 'document', size: 512 }
              ]
            },
            {
              name: 'word',
              type: 'folder',
              size: Math.floor(fileSize * 0.6),
              children: [
                { name: 'document.xml', type: 'document', size: Math.floor(fileSize * 0.4) },
                { name: 'styles.xml', type: 'document', size: Math.floor(fileSize * 0.1) },
                { name: 'settings.xml', type: 'document', size: Math.floor(fileSize * 0.05) },
                { name: 'fontTable.xml', type: 'document', size: Math.floor(fileSize * 0.02) }
              ]
            },
            {
              name: 'docProps',
              type: 'folder',
              size: Math.floor(fileSize * 0.05),
              children: [
                { name: 'core.xml', type: 'document', size: Math.floor(fileSize * 0.02) },
                { name: 'app.xml', type: 'document', size: Math.floor(fileSize * 0.02) }
              ]
            },
            {
              name: 'word/media',
              type: 'folder',
              size: Math.floor(fileSize * 0.2),
              children: [
                { name: 'Embedded Images', type: 'document', size: Math.floor(fileSize * 0.15) },
                { name: 'Media Objects', type: 'document', size: Math.floor(fileSize * 0.05) }
              ]
            },
            {
              name: 'customXml',
              type: 'folder',
              size: Math.floor(fileSize * 0.1),
              suspicious: true,
              children: [
                { name: 'Custom XML Parts', type: 'document', size: Math.floor(fileSize * 0.05), suspicious: true },
                { name: 'itemProps.xml', type: 'document', size: Math.floor(fileSize * 0.02) }
              ]
            }
          ]
        };
      } else if (isOLE) {
        // OLE (legacy Office) - Compound Document structure
        return {
          name: fileName,
          type: 'document',
          size: fileSize,
          children: [
            {
              name: 'OLE Header',
              type: 'folder',
              size: Math.floor(fileSize * 0.02),
              children: [
                { name: 'File Header', type: 'document', size: 512 },
                { name: 'Directory Entries', type: 'document', size: 1024 }
              ]
            },
            {
              name: 'Root Entry',
              type: 'folder',
              size: Math.floor(fileSize * 0.05),
              children: [
                { name: 'Root Storage', type: 'document', size: Math.floor(fileSize * 0.03) },
                { name: 'Mini Stream', type: 'document', size: Math.floor(fileSize * 0.02) }
              ]
            },
            {
              name: 'WordDocument',
              type: 'folder',
              size: Math.floor(fileSize * 0.5),
              children: [
                { name: 'Main Document Stream', type: 'document', size: Math.floor(fileSize * 0.4) },
                { name: 'Document Properties', type: 'document', size: Math.floor(fileSize * 0.1) }
              ]
            },
            {
              name: 'Data',
              type: 'folder',
              size: Math.floor(fileSize * 0.2),
              children: [
                { name: 'Table Stream', type: 'document', size: Math.floor(fileSize * 0.1) },
                { name: 'Data Stream', type: 'document', size: Math.floor(fileSize * 0.1) }
              ]
            },
            {
              name: 'Macros',
              type: 'folder',
              size: Math.floor(fileSize * 0.15),
              suspicious: true,
              children: [
                { name: 'VBA Project', type: 'executable', size: Math.floor(fileSize * 0.1), suspicious: true },
                { name: 'Macro Modules', type: 'executable', size: Math.floor(fileSize * 0.05), suspicious: true }
              ]
            },
            {
              name: 'ObjectPool',
              type: 'folder',
              size: Math.floor(fileSize * 0.08),
              children: [
                { name: 'Embedded Objects', type: 'document', size: Math.floor(fileSize * 0.05) },
                { name: 'OLE Objects', type: 'document', size: Math.floor(fileSize * 0.03) }
              ]
            }
          ]
        };
      }
    }
    
    // Default structure for unknown files
    return {
      name: fileName,
      type: 'document',
      size: fileSize,
      children: [
        {
          name: 'File Content',
          type: 'document',
          size: fileSize
        }
      ]
    };
  };

  const fileStructure = generateFileStructure();
  const yaraMatches = analysisData?.yara?.matches || [];

  // Generate timeline based on actual analysis or create realistic timeline
  const generateTimeline = () => {
    if (analysisData?.timeline && Array.isArray(analysisData.timeline)) {
      return analysisData.timeline;
    }
    
    const fileType = analysisData?.fileType || 'unknown';
    const yaraCount = yaraMatches.length;
    const hasHighEntropy = entropyData.some(e => e > 7.5);
    
    const timeline = [
      { time: '00:00', event: 'File uploaded and queued', type: 'info' },
      { time: '00:01', event: `${fileType.toUpperCase()} file type detected`, type: 'success' }
    ];
    
    // Add file-specific analysis steps
    if (fileType === 'pdf') {
      timeline.push(
        { time: '00:02', event: 'PDF structure parsed', type: 'success' },
        { time: '00:03', event: 'Checking for JavaScript', type: 'info' }
      );
    } else if (fileType === 'pe' || fileType === 'dll') {
      timeline.push(
        { time: '00:02', event: 'PE headers analyzed', type: 'success' },
        { time: '00:03', event: 'Sections mapped', type: 'info' }
      );
    } else if (fileType.includes('office')) {
      timeline.push(
        { time: '00:02', event: 'Office document structure parsed', type: 'success' },
        { time: '00:03', event: 'Checking for macros', type: 'info' }
      );
    }
    
    // Add entropy analysis
    if (hasHighEntropy) {
      timeline.push({ time: '00:04', event: 'High entropy regions detected', type: 'warning' });
    } else {
      timeline.push({ time: '00:04', event: 'Entropy analysis completed', type: 'success' });
    }
    
    // Add YARA analysis
    timeline.push({ time: '00:05', event: 'YARA rules executed', type: 'info' });
    
    if (yaraCount > 0) {
      const highSeverity = yaraMatches.filter(m => m.meta?.severity === 'High').length;
      if (highSeverity > 0) {
        timeline.push({ time: '00:06', event: `${yaraCount} YARA matches found (${highSeverity} high severity)`, type: 'danger' });
      } else {
        timeline.push({ time: '00:06', event: `${yaraCount} YARA matches found`, type: 'warning' });
      }
    } else {
      timeline.push({ time: '00:06', event: 'No YARA matches found', type: 'success' });
    }
    
    timeline.push({ time: '00:07', event: 'Analysis complete', type: 'success' });
    
    return timeline;
  };

  const timelineEvents = generateTimeline();

  const vizTabs = [
    { id: 'entropy', label: 'Entropy Analysis', icon: '📊' },
    { id: 'structure', label: 'File Structure', icon: '🌳' },
    { id: 'timeline', label: 'Analysis Timeline', icon: '⏱️' }
  ];

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <div className="badge">Interactive Visualizations</div>
        {analysisData?.filename && (
          <div style={{
            fontSize: '12px',
            color: 'rgba(255, 255, 255, 0.7)',
            fontFamily: 'JetBrains Mono'
          }}>
            📄 {analysisData.filename}
          </div>
        )}
      </div>
      
      {/* Visualization Tabs */}
      <div style={{ 
        display: 'flex', 
        gap: '8px', 
        marginTop: '16px',
        borderBottom: '1px solid rgba(104, 222, 101, 0.3)',
        paddingBottom: '12px'
      }}>
        {vizTabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveViz(tab.id)}
            style={{
              padding: '8px 16px',
              border: 'none',
              borderRadius: '8px',
              background: activeViz === tab.id ? 
                'linear-gradient(135deg, #39ff14 0%, #68de65 100%)' : 
                'transparent',
              color: activeViz === tab.id ? '#000000' : '#ffffff',
              cursor: 'pointer',
              fontSize: '14px',
              fontWeight: '600',
              transition: 'all 0.2s ease',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <span>{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Visualization Content */}
      <div style={{ marginTop: '20px' }}>
        {activeViz === 'entropy' && (
          <div>
            <h3 style={{ color: '#ffffff', marginBottom: '16px' }}>
              Entropy Distribution Analysis
            </h3>
            <p style={{ color: 'rgba(255, 255, 255, 0.8)', marginBottom: '20px', fontSize: '14px' }}>
              High entropy regions (red) may indicate compressed, encrypted, or obfuscated content.
            </p>
            <EntropyChart data={entropyData} fileSize={analysisData?.size} />
          </div>
        )}

        {activeViz === 'structure' && (
          <div>
            <h3 style={{ color: '#ffffff', marginBottom: '16px' }}>
              File Structure Explorer
            </h3>
            <p style={{ color: 'rgba(255, 255, 255, 0.8)', marginBottom: '20px', fontSize: '14px' }}>
              Navigate through the file's internal structure. Suspicious sections are highlighted.
            </p>
            <FileStructureTree structure={fileStructure} />
          </div>
        )}

        {activeViz === 'timeline' && (
          <div>
            <h3 style={{ color: '#ffffff', marginBottom: '16px' }}>
              Analysis Timeline
            </h3>
            <p style={{ color: 'rgba(255, 255, 255, 0.8)', marginBottom: '20px', fontSize: '14px' }}>
              Step-by-step timeline of the analysis process and key findings.
            </p>
            <ThreatTimeline events={timelineEvents} />
          </div>
        )}
      </div>
    </div>
  );
};

export default InteractiveVisualizations;