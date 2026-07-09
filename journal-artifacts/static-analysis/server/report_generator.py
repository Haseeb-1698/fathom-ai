"""
Professional Static Analysis Report Generator for Fathom
Generates industry-standard static analysis reports mimicking real-world malware analysis documentation.
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white, red, orange, green, blue
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import hashlib

class StaticAnalysisReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Setup custom paragraph styles for professional static analysis reports"""
        
        def safe_add_style(name, style):
            if name not in self.styles:
                self.styles.add(style)
        
        # Report title
        safe_add_style('ReportTitle', ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontSize=20,
            spaceAfter=6,
            textColor=HexColor('#1a202c'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Classification header
        safe_add_style('Classification', ParagraphStyle(
            name='Classification',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#e53e3e'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceBefore=0,
            spaceAfter=20
        ))
        
        # Section headers
        safe_add_style('SectionHeader', ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor('#2d3748'),
            fontName='Helvetica-Bold',
            borderWidth=1,
            borderColor=HexColor('#cbd5e0'),
            borderPadding=6,
            backColor=HexColor('#f7fafc')
        ))
        
        # Subsection headers
        safe_add_style('SubsectionHeader', ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading2'],
            fontSize=12,
            spaceBefore=12,
            spaceAfter=6,
            textColor=HexColor('#4a5568'),
            fontName='Helvetica-Bold'
        ))
        
        # Finding styles
        safe_add_style('CriticalFinding', ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6,
            leftIndent=15,
            borderWidth=2,
            borderColor=HexColor('#e53e3e'),
            borderPadding=8,
            backColor=HexColor('#fed7d7'),
            textColor=HexColor('#742a2a')
        ))
        
        safe_add_style('HighFinding', ParagraphStyle(
            name='HighFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6,
            leftIndent=15,
            borderWidth=1,
            borderColor=HexColor('#f56500'),
            borderPadding=8,
            backColor=HexColor('#feebc8'),
            textColor=HexColor('#7b341e')
        ))
        
        safe_add_style('MediumFinding', ParagraphStyle(
            name='MediumFinding',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6,
            leftIndent=15,
            borderWidth=1,
            borderColor=HexColor('#d69e2e'),
            borderPadding=8,
            backColor=HexColor('#faf089'),
            textColor=HexColor('#744210')
        ))
        
        # Technical details
        safe_add_style('TechnicalData', ParagraphStyle(
            name='TechnicalData',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            spaceBefore=4,
            spaceAfter=4,
            leftIndent=10,
            backColor=HexColor('#f7fafc'),
            borderWidth=1,
            borderColor=HexColor('#e2e8f0'),
            borderPadding=4
        ))
        
        # IOC style
        safe_add_style('IOC', ParagraphStyle(
            name='IOC',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier-Bold',
            spaceBefore=2,
            spaceAfter=2,
            leftIndent=20,
            textColor=HexColor('#c53030')
        ))
        
        # Metadata
        safe_add_style('Metadata', ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceBefore=2,
            spaceAfter=2,
            leftIndent=10
        ))

    def generate_report(self, record: Dict[str, Any], output_path: str) -> str:
        """Generate a professional static analysis report"""
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=80,
            bottomMargin=80
        )
        
        story = []
        
        # Classification and title
        story.extend(self._create_header(record))
        
        # Executive summary
        story.extend(self._create_executive_summary(record))
        
        # Sample information
        story.extend(self._create_sample_information(record))
        
        # Static analysis results
        final_type = (record.get("final_guess", {}).get("type", "unknown")).lower()
        
        if final_type in ["pe", "dll"]:
            story.extend(self._create_pe_static_analysis(record))
        elif final_type == "pdf":
            story.extend(self._create_pdf_static_analysis(record))
        elif final_type in ["office_ooxml", "office_ole"]:
            story.extend(self._create_office_static_analysis(record))
        
        # Behavioral indicators
        story.extend(self._create_behavioral_analysis(record))
        
        # IOC extraction
        story.extend(self._create_ioc_analysis(record))
        
        # Threat assessment
        story.extend(self._create_threat_assessment(record))
        
        # Technical appendix
        story.extend(self._create_technical_appendix(record))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_header_footer, onLaterPages=self._add_header_footer)
        
        return output_path

    def _create_header(self, record: Dict[str, Any]) -> List:
        """Create report header with classification and title"""
        story = []
        
        # Classification
        story.append(Paragraph("STATIC ANALYSIS REPORT", self.styles['Classification']))
        
        # Title
        final_type = (record.get("final_guess", {}).get("type", "unknown")).upper()
        story.append(Paragraph(f"{final_type} Static Analysis Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 20))
        
        return story

    def _create_executive_summary(self, record: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("1. EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        # Analysis overview
        final_type = (record.get("final_guess", {}).get("type", "unknown")).lower()
        confidence = record.get("confidence", 0)
        filename = record.get("filename", "Unknown")
        
        summary_text = f"This report presents the static analysis results for the sample '{filename}'. "
        summary_text += f"The file has been classified as {final_type.upper()} with {confidence}% confidence. "
        
        # Threat level assessment
        threat_level, threat_indicators = self._assess_threat_level(record, final_type)
        summary_text += f"Based on static analysis, the sample is assessed as {threat_level} threat level."
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Key findings table
        findings_data = [
            ["Category", "Finding", "Severity"],
            ["File Type", final_type.upper(), "INFO"],
            ["Detection Confidence", f"{confidence}%", "INFO" if confidence >= 80 else "LOW"],
        ]
        
        # Add threat indicators
        for indicator, severity in threat_indicators[:5]:  # Top 5 findings
            findings_data.append(["Static Analysis", indicator, severity])
        
        findings_table = Table(findings_data, colWidths=[1.5*inch, 3*inch, 1*inch])
        findings_table.setStyle(self._get_findings_table_style())
        story.append(findings_table)
        story.append(Spacer(1, 20))
        
        return story

    def _create_sample_information(self, record: Dict[str, Any]) -> List:
        """Create sample information section - includes ALL Basic tab content"""
        story = []
        
        story.append(Paragraph("2. SAMPLE INFORMATION", self.styles['SectionHeader']))
        
        # Basic sample data (from Basic tab)
        size_bytes = record.get("size_bytes", 0)
        size_human = self._format_bytes(size_bytes)
        confidence = record.get("confidence", 0)
        confidence_level = record.get("confidence_level", "unknown")
        final_type = record.get("final_guess", {}).get("type", "unknown")
        
        sample_data = [
            ["Attribute", "Value"],
            ["File Name", record.get("filename", "Unknown")],
            ["File Size", f"{size_human} ({size_bytes:,} bytes)"],
            ["File Type", final_type.upper()],
            ["Type Code", final_type.upper()],
            ["Detection Confidence", f"{confidence}% ({confidence_level})"],
            ["SHA-256", record.get("sha256", "N/A")],
            ["Analysis Date", record.get("scanned_at", datetime.now().isoformat())],
            ["Analysis Engine", "Fathom Static Analysis Engine"],
        ]
        
        sample_table = Table(sample_data, colWidths=[2*inch, 4*inch])
        sample_table.setStyle(self._get_standard_table_style())
        story.append(sample_table)
        story.append(Spacer(1, 15))
        
        # Detection Reasoning (from Basic tab)
        story.append(Paragraph("2.1 Detection Reasoning", self.styles['SubsectionHeader']))
        reasons = record.get("final_guess", {}).get("reasons", [])
        
        if reasons:
            story.append(Paragraph(f"Why we identified this as {final_type.upper()}:", self.styles['Metadata']))
            for reason in reasons:
                story.append(Paragraph(f"• {reason}", self.styles['Normal']))
        else:
            story.append(Paragraph("Detection based on basic file analysis", self.styles['Normal']))
        
        story.append(Spacer(1, 15))
        
        # File Signatures (from Basic tab)
        signatures = record.get("signatures", {})
        if signatures:
            story.append(Paragraph("2.2 File Signatures", self.styles['SubsectionHeader']))
            
            sig_data = [["Signature Type", "Value"]]
            
            # Add all signature data
            for sig_type in ["pe", "pdf", "office_ooxml", "office_ole"]:
                sig_info = signatures.get(sig_type, {})
                if sig_info:
                    # Add relevant signature information
                    if sig_type == "pe" and sig_info.get("is_pe"):
                        sig_data.append(["PE Signature", "Present"])
                        if sig_info.get("machine"):
                            sig_data.append(["Machine Type", sig_info["machine"]])
                    elif sig_type == "pdf" and sig_info.get("is_pdf"):
                        sig_data.append(["PDF Signature", "Present"])
                        if sig_info.get("version"):
                            sig_data.append(["PDF Version", sig_info["version"]])
                    elif sig_type == "office_ooxml" and sig_info.get("is_ooxml"):
                        sig_data.append(["OOXML Signature", "Present"])
                        families = sig_info.get("families", [])
                        if families:
                            sig_data.append(["Office Type", ", ".join(families)])
                    elif sig_type == "office_ole" and sig_info.get("is_ole"):
                        sig_data.append(["OLE Signature", "Present"])
            
            # Add entropy if available
            heuristics = record.get("heuristics", {})
            if "entropy" in heuristics and isinstance(heuristics["entropy"], dict):
                overall_entropy = heuristics["entropy"].get("overall")
                if overall_entropy is not None:
                    sig_data.append(["Overall Entropy", f"{overall_entropy:.2f} bits"])
            
            if len(sig_data) > 1:  # More than just header
                sig_table = Table(sig_data, colWidths=[2*inch, 4*inch])
                sig_table.setStyle(self._get_standard_table_style())
                story.append(sig_table)
        
        story.append(Spacer(1, 20))
        return story

    def _create_pe_static_analysis(self, record: Dict[str, Any]) -> List:
        """Create PE/DLL static analysis section"""
        story = []
        pe = record.get("static", {}).get("pe", {})
        counts = record.get("counts", {})
        
        story.append(Paragraph("3. STATIC ANALYSIS RESULTS", self.styles['SectionHeader']))
        
        # PE Header Analysis
        story.append(Paragraph("3.1 PE Header Analysis", self.styles['SubsectionHeader']))
        
        file_info = pe.get("file_info", {})
        if file_info:
            pe_data = [
                ["Field", "Value", "Analysis"],
                ["Machine Type", file_info.get("machine", "Unknown"), "Target architecture"],
                ["Compilation Time", file_info.get("compile_time", "Unknown"), "Build timestamp"],
                ["Entry Point", f"0x{file_info.get('entrypoint_rva', 0):08X}", "Code execution start"],
                ["Image Base", f"0x{file_info.get('image_base', 0):08X}", "Preferred load address"],
                ["File Type", "DLL" if file_info.get("is_dll") else "EXE", "Executable type"],
                ["TLS Callbacks", "Yes" if file_info.get("has_tls_callbacks") else "No", "Early execution hooks"],
            ]
            
            pe_table = Table(pe_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
            pe_table.setStyle(self._get_analysis_table_style())
            story.append(pe_table)
            story.append(Spacer(1, 15))
        
        # Digital Signature Analysis
        signature = pe.get("signatures", {}).get("authenticode", {})
        story.append(Paragraph("3.2 Digital Signature Analysis", self.styles['SubsectionHeader']))
        
        if signature.get("present"):
            signer = signature.get("signer", "Unknown")
            story.append(Paragraph(f"✓ File is digitally signed by: {signer}", self.styles['Normal']))
        else:
            story.append(Paragraph("⚠ File is NOT digitally signed", self.styles['MediumFinding']))
            story.append(Paragraph("Unsigned executables may indicate malicious software or development builds.", self.styles['Metadata']))
        
        story.append(Spacer(1, 15))
        
        # Section Analysis
        sections = pe.get("sections", [])
        if sections:
            story.append(Paragraph("3.3 Section Analysis", self.styles['SubsectionHeader']))
            
            high_entropy_sections = [s for s in sections if s.get("entropy", 0) >= 7.5]
            if high_entropy_sections:
                story.append(Paragraph(f"⚠ {len(high_entropy_sections)} high-entropy sections detected (possible packing/encryption)", self.styles['HighFinding']))
            
            # Section table
            section_data = [["Name", "Virtual Size", "Raw Size", "Entropy", "Characteristics"]]
            for section in sections[:10]:  # First 10 sections
                name = section.get("name", "Unknown")
                vsize = f"0x{section.get('virtual_size', 0):X}"
                rsize = self._format_bytes(section.get("raw_size", 0))
                entropy = f"{section.get('entropy', 0):.2f}"
                chars = ", ".join(section.get("characteristics", [])[:2])
                
                section_data.append([name, vsize, rsize, entropy, chars])
            
            section_table = Table(section_data, colWidths=[0.8*inch, 1*inch, 1*inch, 0.8*inch, 2.4*inch])
            section_table.setStyle(self._get_standard_table_style())
            story.append(section_table)
            story.append(Spacer(1, 15))
        
        # Import Analysis
        suspicious_imports = pe.get("suspicious_imports", [])
        if suspicious_imports:
            story.append(Paragraph("3.4 Suspicious Import Analysis", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {len(suspicious_imports)} suspicious API functions detected", self.styles['HighFinding']))
            
            # Categorize imports
            process_apis = [imp for imp in suspicious_imports if any(x in imp.lower() for x in ['createprocess', 'shellexecute', 'winexec'])]
            file_apis = [imp for imp in suspicious_imports if any(x in imp.lower() for x in ['createfile', 'writefile', 'deletefile'])]
            network_apis = [imp for imp in suspicious_imports if any(x in imp.lower() for x in ['internetopen', 'httpopen', 'socket'])]
            
            if process_apis:
                story.append(Paragraph("Process Creation APIs:", self.styles['Metadata']))
                for api in process_apis[:5]:
                    story.append(Paragraph(f"• {api}", self.styles['IOC']))
            
            if file_apis:
                story.append(Paragraph("File System APIs:", self.styles['Metadata']))
                for api in file_apis[:5]:
                    story.append(Paragraph(f"• {api}", self.styles['IOC']))
            
            if network_apis:
                story.append(Paragraph("Network APIs:", self.styles['Metadata']))
                for api in network_apis[:5]:
                    story.append(Paragraph(f"• {api}", self.styles['IOC']))
            
            story.append(Spacer(1, 15))
        
        return story

    def _create_pdf_static_analysis(self, record: Dict[str, Any]) -> List:
        """Create PDF static analysis section - includes ALL Static tab content"""
        story = []
        pdf = record.get("static", {}).get("pdf", {})
        counts = record.get("counts", {})
        
        story.append(Paragraph("3. STATIC ANALYSIS RESULTS", self.styles['SectionHeader']))
        
        # Analysis Engine Status
        story.append(Paragraph("3.1 Analysis Engine Status", self.styles['SubsectionHeader']))
        
        confidence = record.get("confidence", 0)
        confidence_level = record.get("confidence_level", "unknown")
        
        engine_data = [
            ["Parameter", "Value"],
            ["Analysis Engine", "PDF Enhanced Parser" if pdf else "PDF Basic Parser"],
            ["Detection Confidence", f"{confidence}% ({confidence_level})"],
            ["Objects Parsed", str(counts.get("objects_total", 0))],
            ["Streams Analyzed", str(counts.get("streams_total", 0))],
            ["JavaScript Objects", str(counts.get("js_objects_total", 0))],
            ["Embedded Files", str(counts.get("embedded_files_total", 0))],
        ]
        
        engine_table = Table(engine_data, colWidths=[2*inch, 4*inch])
        engine_table.setStyle(self._get_standard_table_style())
        story.append(engine_table)
        story.append(Spacer(1, 15))
        
        # Document Metadata (from Static tab)
        metadata = pdf.get("metadata", {})
        if metadata:
            story.append(Paragraph("3.2 Document Metadata", self.styles['SubsectionHeader']))
            
            meta_data = [["Property", "Value"]]
            for key, label in [("Producer", "Producer"), ("Creator", "Creator"), ("Title", "Title"), 
                              ("Author", "Author"), ("CreationDate", "Creation Date"), ("ModDate", "Modified Date")]:
                if metadata.get(key):
                    value = metadata[key]
                    # Format dates
                    if key in ["CreationDate", "ModDate"] and value.startswith("D:"):
                        try:
                            # Parse PDF date format
                            import re
                            m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", value)
                            if m:
                                year, month, day, hour, minute, second = m.groups()
                                value = f"{year}-{month or '01'}-{day or '01'} {hour or '00'}:{minute or '00'}:{second or '00'}"
                        except:
                            pass
                    meta_data.append([label, value])
            
            if len(meta_data) > 1:
                meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
                meta_table.setStyle(self._get_standard_table_style())
                story.append(meta_table)
                story.append(Spacer(1, 15))
        
        # Encryption Analysis (from Static tab)
        encryption = pdf.get("encryption", {})
        story.append(Paragraph("3.3 Security Features", self.styles['SubsectionHeader']))
        
        if encryption.get("Filter"):
            story.append(Paragraph(f"🔒 Document is encrypted with {encryption['Filter']}", self.styles['MediumFinding']))
            if encryption.get("P"):
                story.append(Paragraph(f"Permissions: {encryption['P']}", self.styles['Metadata']))
            if encryption.get("V"):
                story.append(Paragraph(f"Encryption Version: {encryption['V']}", self.styles['Metadata']))
        else:
            story.append(Paragraph("✓ Document is not encrypted", self.styles['Normal']))
        
        # JavaScript Content (from Static tab)
        js_objects = counts.get("js_objects_total", 0)
        auto_actions = counts.get("auto_actions_total", 0)
        
        if js_objects > 0:
            story.append(Paragraph("3.4 JavaScript Content", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {js_objects} JavaScript objects detected", self.styles['HighFinding']))
            
            if auto_actions > 0:
                story.append(Paragraph(f"⚠ {auto_actions} auto-execution actions detected", self.styles['HighFinding']))
                story.append(Paragraph("Auto-actions execute automatically when the document is opened.", self.styles['Metadata']))
            
            # JavaScript objects details
            javascript = pdf.get("javascript", {})
            if javascript.get("objects"):
                js_data = [["Object Type", "Count"]]
                for js_obj in javascript["objects"]:
                    js_data.append([js_obj.get("type", "Unknown"), "1"])
                
                js_table = Table(js_data, colWidths=[3*inch, 3*inch])
                js_table.setStyle(self._get_standard_table_style())
                story.append(js_table)
            
            story.append(Spacer(1, 15))
        
        # Embedded Files (from Static tab)
        embedded_files = counts.get("embedded_files_total", 0)
        if embedded_files > 0:
            story.append(Paragraph("3.5 Embedded Files", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"📎 {embedded_files} embedded files detected", self.styles['MediumFinding']))
            
            embedded_list = pdf.get("embedded_files", [])
            if embedded_list:
                embed_data = [["File Name", "Type", "Size"]]
                for embed in embedded_list[:10]:  # First 10 files
                    name = embed.get("name", "Unknown")
                    file_type = embed.get("file_type", "Unknown")
                    size_hint = embed.get("size_hint", "Unknown")
                    embed_data.append([name, file_type, size_hint])
                
                embed_table = Table(embed_data, colWidths=[2*inch, 2*inch, 2*inch])
                embed_table.setStyle(self._get_standard_table_style())
                story.append(embed_table)
            
            story.append(Spacer(1, 15))
        
        # Network Indicators (from Static tab)
        ioc_urls = pdf.get("strings", {}).get("ioc_urls", [])
        if ioc_urls:
            story.append(Paragraph("3.6 Network Indicators", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"🌐 {len(ioc_urls)} URLs found", self.styles['MediumFinding']))
            
            for url in ioc_urls[:10]:  # First 10 URLs
                story.append(Paragraph(f"• {url}", self.styles['IOC']))
            
            story.append(Spacer(1, 15))
        
        # Keywords (from Static tab)
        keywords = pdf.get("strings", {}).get("suspicious_keywords", [])
        if keywords:
            story.append(Paragraph("3.7 Keywords", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"🔍 {len(keywords)} keywords found", self.styles['MediumFinding']))
            
            for keyword in keywords[:15]:  # First 15 keywords
                story.append(Paragraph(f"• {keyword}", self.styles['TechnicalData']))
            
            story.append(Spacer(1, 15))
        
        # High Entropy Content (from Static tab)
        high_entropy_streams = counts.get("high_entropy_stream_count", 0)
        if high_entropy_streams > 0:
            story.append(Paragraph("3.8 High Entropy Content", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {high_entropy_streams} high-entropy streams detected", self.styles['HighFinding']))
            story.append(Paragraph("High-entropy content may indicate compressed or encrypted data.", self.styles['Metadata']))
            
            # Entropy details
            entropy_info = pdf.get("entropy", {})
            if entropy_info:
                entropy_data = [["Metric", "Value"]]
                if entropy_info.get("overall") is not None:
                    entropy_data.append(["Overall Entropy", f"{entropy_info['overall']:.2f} bits"])
                entropy_data.append(["High-entropy Streams", str(high_entropy_streams)])
                
                entropy_table = Table(entropy_data, colWidths=[3*inch, 3*inch])
                entropy_table.setStyle(self._get_standard_table_style())
                story.append(entropy_table)
            
            story.append(Spacer(1, 15))
        
        # Structural Anomalies (from Static tab)
        anomalies = pdf.get("anomalies", [])
        if anomalies:
            story.append(Paragraph("3.9 Structural Anomalies", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {len(anomalies)} structural anomalies detected", self.styles['MediumFinding']))
            
            for anomaly in anomalies[:10]:  # First 10 anomalies
                story.append(Paragraph(f"• {anomaly}", self.styles['TechnicalData']))
        
        story.append(Spacer(1, 20))
        return story

    def _create_office_static_analysis(self, record: Dict[str, Any]) -> List:
        """Create Office document static analysis section - includes ALL Static tab content"""
        story = []
        office = record.get("static", {}).get("office", {})
        counts = record.get("counts", {})
        
        story.append(Paragraph("3. STATIC ANALYSIS RESULTS", self.styles['SectionHeader']))
        
        # Analysis Engine Status
        story.append(Paragraph("3.1 Analysis Engine Status", self.styles['SubsectionHeader']))
        
        confidence = record.get("confidence", 0)
        confidence_level = record.get("confidence_level", "unknown")
        
        engine_data = [
            ["Parameter", "Value"],
            ["Analysis Engine", "Office Enhanced Parser" if office else "Office Basic Parser"],
            ["Detection Confidence", f"{confidence}% ({confidence_level})"],
            ["Macros Found", str(counts.get("macros_total", 0))],
            ["Auto-exec Macros", str(counts.get("autoexec_macros_total", 0))],
            ["Complex Macros", str(counts.get("suspicious_macros_total", 0))],
            ["Embedded Objects", str(counts.get("embedded_objects_total", 0))],
            ["External References", str(counts.get("external_references_total", 0))],
        ]
        
        engine_table = Table(engine_data, colWidths=[2*inch, 4*inch])
        engine_table.setStyle(self._get_standard_table_style())
        story.append(engine_table)
        story.append(Spacer(1, 15))
        
        # Document Metadata (from Static tab)
        metadata = office.get("metadata", {})
        if metadata:
            story.append(Paragraph("3.2 Document Metadata", self.styles['SubsectionHeader']))
            
            meta_data = [["Property", "Value"]]
            for key, label in [("Application", "Application"), ("Creator", "Creator"), 
                              ("LastModifiedBy", "Last Modified By"), ("Created", "Created"), 
                              ("Modified", "Modified"), ("Company", "Company")]:
                if metadata.get(key):
                    value = metadata[key]
                    # Format dates
                    if key in ["Created", "Modified"] and isinstance(value, str):
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                            value = dt.strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            pass
                    meta_data.append([label, value])
            
            if len(meta_data) > 1:
                meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
                meta_table.setStyle(self._get_standard_table_style())
                story.append(meta_table)
                story.append(Spacer(1, 15))
        
        # Macro Analysis (from Static tab + Office Extractor)
        flags = office.get("flags", {})
        macros = office.get("macros", [])
        
        story.append(Paragraph("3.3 VBA Macro Analysis", self.styles['SubsectionHeader']))
        
        if flags.get("macro_present"):
            macro_count = counts.get("macros_total", len(macros))
            autoexec_count = counts.get("autoexec_macros_total", 0)
            suspicious_count = counts.get("suspicious_macros_total", 0)
            obfuscated_count = counts.get("obfuscated_macros_total", 0)
            
            story.append(Paragraph(f"⚠ {macro_count} VBA macro modules detected", self.styles['HighFinding']))
            
            # Macro summary table
            macro_summary = [
                ["Metric", "Count", "Analysis"],
                ["Total Macros", str(macro_count), "VBA modules found"],
                ["Auto-execution", str(autoexec_count), "Macros that run automatically"],
                ["Complex Macros", str(suspicious_count), "Macros with advanced functionality"],
                ["Encoded Macros", str(obfuscated_count), "Macros with encoding/obfuscation"],
            ]
            
            macro_table = Table(macro_summary, colWidths=[2*inch, 1*inch, 3*inch])
            macro_table.setStyle(self._get_analysis_table_style())
            story.append(macro_table)
            story.append(Spacer(1, 10))
            
            if autoexec_count > 0:
                story.append(Paragraph(f"⚠ {autoexec_count} auto-execution macros detected", self.styles['CriticalFinding']))
                story.append(Paragraph("Auto-execution macros run automatically when the document is opened.", self.styles['Metadata']))
            
            if flags.get("suspicious_shell_usage"):
                story.append(Paragraph("⚠ Macros contain OS command execution capabilities", self.styles['CriticalFinding']))
                story.append(Paragraph("Shell command execution in macros indicates potential malicious activity.", self.styles['Metadata']))
            
            # Detailed macro analysis
            if macros:
                story.append(Paragraph("3.4 Detailed Macro Analysis", self.styles['SubsectionHeader']))
                
                for i, macro in enumerate(macros[:5]):  # First 5 macros
                    module_name = macro.get("module_name", f"Module_{i+1}")
                    story.append(Paragraph(f"Macro Module: {module_name}", self.styles['SubsectionHeader']))
                    
                    # Macro details table
                    macro_details = [["Attribute", "Value"]]
                    
                    if macro.get("size"):
                        macro_details.append(["Size", f"{macro['size']} bytes"])
                    
                    if macro.get("extraction_method"):
                        macro_details.append(["Extraction Method", macro["extraction_method"]])
                    
                    if macro.get("sha256"):
                        macro_details.append(["SHA256", macro["sha256"][:32] + "..."])
                    
                    # Analysis results
                    autoexec_indicators = macro.get("autoexec_indicators", [])
                    if autoexec_indicators:
                        macro_details.append(["Auto-execution", ", ".join(autoexec_indicators)])
                    
                    suspicious_indicators = macro.get("suspicious_indicators", [])
                    if suspicious_indicators:
                        macro_details.append(["API Calls", ", ".join(suspicious_indicators[:5])])
                    
                    obfuscation_indicators = macro.get("obfuscation_indicators", [])
                    if obfuscation_indicators:
                        macro_details.append(["Encoding", ", ".join(obfuscation_indicators[:3])])
                    
                    if len(macro_details) > 1:
                        detail_table = Table(macro_details, colWidths=[2*inch, 4*inch])
                        detail_table.setStyle(self._get_standard_table_style())
                        story.append(detail_table)
                    
                    # Code preview
                    if macro.get("code_preview"):
                        story.append(Paragraph("Code Preview:", self.styles['Metadata']))
                        code_preview = macro["code_preview"][:300] + "..." if len(macro["code_preview"]) > 300 else macro["code_preview"]
                        story.append(Paragraph(code_preview, self.styles['TechnicalData']))
                    
                    story.append(Spacer(1, 10))
        else:
            story.append(Paragraph("✓ No VBA macros detected", self.styles['Normal']))
        
        # OS Command Usage (from Static tab)
        if flags.get("suspicious_shell_usage"):
            story.append(Paragraph("3.5 OS Command Usage", self.styles['SubsectionHeader']))
            story.append(Paragraph("⚠ OS command execution capabilities detected", self.styles['HighFinding']))
            story.append(Paragraph("Document contains functionality to execute operating system commands.", self.styles['Metadata']))
            story.append(Spacer(1, 15))
        
        # External References (from Static tab)
        external_refs = counts.get("external_references_total", 0)
        if external_refs > 0:
            story.append(Paragraph("3.6 External References", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"🔗 {external_refs} external references detected", self.styles['MediumFinding']))
            story.append(Spacer(1, 15))
        
        # Embedded Payloads (from Static tab)
        embedded_payloads = counts.get("embedded_payloads_total", 0)
        if embedded_payloads > 0:
            story.append(Paragraph("3.7 Embedded Payloads", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"📦 {embedded_payloads} embedded payloads detected", self.styles['HighFinding']))
            
            high_entropy_embeds = counts.get("high_entropy_embed_count", 0)
            if high_entropy_embeds > 0:
                story.append(Paragraph(f"⚠ {high_entropy_embeds} high-entropy embedded objects", self.styles['HighFinding']))
            
            story.append(Spacer(1, 15))
        
        # Network Indicators (from Static tab)
        strings = office.get("strings", {})
        ioc_urls = strings.get("ioc_urls", [])
        if ioc_urls:
            story.append(Paragraph("3.8 Network Indicators", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"🌐 {len(ioc_urls)} URLs found", self.styles['MediumFinding']))
            
            for url in ioc_urls[:10]:  # First 10 URLs
                story.append(Paragraph(f"• {url}", self.styles['IOC']))
            
            story.append(Spacer(1, 15))
        
        # Keywords (from Static tab)
        keywords = strings.get("suspicious_keywords", [])
        if keywords:
            story.append(Paragraph("3.9 Keywords", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"🔍 {len(keywords)} keywords found", self.styles['MediumFinding']))
            
            for keyword in keywords[:15]:  # First 15 keywords
                story.append(Paragraph(f"• {keyword}", self.styles['TechnicalData']))
            
            story.append(Spacer(1, 15))
        
        # High Entropy Content (from Static tab)
        high_entropy_embeds = counts.get("high_entropy_embed_count", 0)
        if high_entropy_embeds > 0:
            story.append(Paragraph("3.10 High Entropy Content", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {high_entropy_embeds} high-entropy embedded objects detected", self.styles['HighFinding']))
            story.append(Paragraph("High-entropy content may indicate encrypted or compressed payloads.", self.styles['Metadata']))
            
            # Entropy details
            entropy_info = office.get("entropy", {})
            if entropy_info and entropy_info.get("overall"):
                story.append(Paragraph(f"Overall entropy: {entropy_info['overall']:.2f} bits", self.styles['TechnicalData']))
            
            story.append(Spacer(1, 15))
        
        # Structural Anomalies (from Static tab)
        anomalies = office.get("anomalies", [])
        if anomalies:
            story.append(Paragraph("3.11 Structural Anomalies", self.styles['SubsectionHeader']))
            story.append(Paragraph(f"⚠ {len(anomalies)} structural anomalies detected", self.styles['MediumFinding']))
            
            for anomaly in anomalies[:10]:  # First 10 anomalies
                story.append(Paragraph(f"• {anomaly}", self.styles['TechnicalData']))
        
        story.append(Spacer(1, 20))
        return story

    def _create_behavioral_analysis(self, record: Dict[str, Any]) -> List:
        """Create behavioral analysis section - includes ALL YARA matches from Basic tab"""
        story = []
        yara_data = record.get("heuristics", {}).get("yara", {})
        matches = yara_data.get("matches", [])
        yara_errors = yara_data.get("errors", [])
        
        story.append(Paragraph("4. BEHAVIORAL ANALYSIS", self.styles['SectionHeader']))
        
        if matches:
            story.append(Paragraph(f"4.1 YARA Rule Matches ({len(matches)} signatures triggered)", self.styles['SubsectionHeader']))
            
            # Show ALL matches with full details (from Basic tab)
            yara_table_data = [["Rule Name", "Category", "Description", "Tags"]]
            
            for match in matches:
                rule_name = match.get("rule", "Unknown Rule")
                meta = match.get("meta", {})
                description = (meta.get("description") or 
                             meta.get("notes") or 
                             meta.get("behavior") or 
                             "No description available")
                category = meta.get("category") or meta.get("type") or "General"
                tags = ", ".join(match.get("tags", []))
                
                # Truncate long descriptions for table
                if len(description) > 80:
                    description = description[:77] + "..."
                
                yara_table_data.append([rule_name, category, description, tags])
            
            yara_table = Table(yara_table_data, colWidths=[1.5*inch, 1*inch, 2.5*inch, 1*inch])
            yara_table.setStyle(self._get_standard_table_style())
            story.append(yara_table)
            story.append(Spacer(1, 15))
            
            # Categorize matches by severity for detailed analysis
            critical_matches = [m for m in matches if "critical" in (m.get("tags", []))]
            high_matches = [m for m in matches if "high" in (m.get("tags", [])) or "malware" in (m.get("tags", []))]
            medium_matches = [m for m in matches if m not in critical_matches and m not in high_matches]
            
            if critical_matches:
                story.append(Paragraph("Critical Behavioral Indicators:", self.styles['SubsectionHeader']))
                for match in critical_matches:
                    rule_name = match.get("rule", "Unknown")
                    description = self._get_yara_description(match)
                    story.append(Paragraph(f"• {rule_name}: {description}", self.styles['CriticalFinding']))
                    
                    # Add severity info if available
                    meta = match.get("meta", {})
                    if meta.get("severity"):
                        story.append(Paragraph(f"  Severity: {meta['severity']}", self.styles['Metadata']))
                story.append(Spacer(1, 10))
            
            if high_matches:
                story.append(Paragraph("High-Risk Behavioral Indicators:", self.styles['SubsectionHeader']))
                for match in high_matches:
                    rule_name = match.get("rule", "Unknown")
                    description = self._get_yara_description(match)
                    story.append(Paragraph(f"• {rule_name}: {description}", self.styles['HighFinding']))
                story.append(Spacer(1, 10))
            
            if medium_matches:
                story.append(Paragraph("Other Behavioral Indicators:", self.styles['SubsectionHeader']))
                for match in medium_matches:
                    rule_name = match.get("rule", "Unknown")
                    description = self._get_yara_description(match)
                    story.append(Paragraph(f"• {rule_name}: {description}", self.styles['MediumFinding']))
        else:
            story.append(Paragraph("4.1 YARA Rule Analysis", self.styles['SubsectionHeader']))
            story.append(Paragraph("No YARA behavioral signatures triggered.", self.styles['Normal']))
            story.append(Paragraph("This indicates the file does not match any known behavioral patterns in the current rule set.", self.styles['Metadata']))
        
        # Include YARA errors if any
        if yara_errors:
            story.append(Paragraph("4.2 YARA Analysis Warnings", self.styles['SubsectionHeader']))
            for error in yara_errors:
                story.append(Paragraph(f"• {error}", self.styles['TechnicalData']))
        
        story.append(Spacer(1, 20))
        return story

    def _create_ioc_analysis(self, record: Dict[str, Any]) -> List:
        """Create IOC analysis section"""
        story = []
        
        story.append(Paragraph("5. INDICATORS OF COMPROMISE (IOCs)", self.styles['SectionHeader']))
        
        # Extract IOCs based on file type
        final_type = (record.get("final_guess", {}).get("type", "unknown")).lower()
        iocs = []
        
        if final_type in ["pe", "dll"]:
            pe = record.get("static", {}).get("pe", {})
            strings = pe.get("strings", {})
            ioc_urls = strings.get("ioc_urls", [])
            suspicious_keywords = strings.get("suspicious_keywords", [])
            
            if ioc_urls:
                story.append(Paragraph("Network IOCs:", self.styles['SubsectionHeader']))
                for url in ioc_urls[:10]:
                    story.append(Paragraph(url, self.styles['IOC']))
                story.append(Spacer(1, 10))
            
            if suspicious_keywords:
                story.append(Paragraph("Suspicious Keywords:", self.styles['SubsectionHeader']))
                for keyword in suspicious_keywords[:15]:
                    story.append(Paragraph(keyword, self.styles['TechnicalData']))
                story.append(Spacer(1, 10))
        
        elif final_type == "pdf":
            pdf = record.get("static", {}).get("pdf", {})
            strings = pdf.get("strings", {})
            ioc_urls = strings.get("ioc_urls", [])
            
            if ioc_urls:
                story.append(Paragraph("Network IOCs:", self.styles['SubsectionHeader']))
                for url in ioc_urls:
                    story.append(Paragraph(url, self.styles['IOC']))
        
        elif final_type in ["office_ooxml", "office_ole"]:
            office = record.get("static", {}).get("office", {})
            strings = office.get("strings", {})
            ioc_urls = strings.get("ioc_urls", [])
            
            if ioc_urls:
                story.append(Paragraph("Network IOCs:", self.styles['SubsectionHeader']))
                for url in ioc_urls:
                    story.append(Paragraph(url, self.styles['IOC']))
        
        # File hash IOC
        story.append(Paragraph("File Hash IOCs:", self.styles['SubsectionHeader']))
        story.append(Paragraph(f"SHA-256: {record.get('sha256', 'N/A')}", self.styles['IOC']))
        
        story.append(Spacer(1, 20))
        return story

    def _create_threat_assessment(self, record: Dict[str, Any]) -> List:
        """Create threat assessment section"""
        story = []
        
        story.append(Paragraph("6. THREAT ASSESSMENT", self.styles['SectionHeader']))
        
        final_type = (record.get("final_guess", {}).get("type", "unknown")).lower()
        threat_level, threat_indicators = self._assess_threat_level(record, final_type)
        
        # Overall assessment
        story.append(Paragraph("6.1 Overall Threat Level", self.styles['SubsectionHeader']))
        
        threat_color = {
            "CRITICAL": self.styles['CriticalFinding'],
            "HIGH": self.styles['HighFinding'],
            "MEDIUM": self.styles['MediumFinding'],
            "LOW": self.styles['Normal']
        }
        
        story.append(Paragraph(f"Threat Level: {threat_level}", threat_color.get(threat_level, self.styles['Normal'])))
        
        # Threat indicators
        if threat_indicators:
            story.append(Paragraph("6.2 Threat Indicators", self.styles['SubsectionHeader']))
            
            for indicator, severity in threat_indicators:
                style = threat_color.get(severity, self.styles['Normal'])
                story.append(Paragraph(f"• {indicator} ({severity})", style))
        
        # Recommendations
        story.append(Paragraph("6.3 Recommendations", self.styles['SubsectionHeader']))
        recommendations = self._generate_recommendations(record, final_type, threat_level)
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            story.append(Spacer(1, 6))
        
        story.append(Spacer(1, 20))
        return story

    def _create_technical_appendix(self, record: Dict[str, Any]) -> List:
        """Create technical appendix"""
        story = []
        
        story.append(Paragraph("7. TECHNICAL APPENDIX", self.styles['SectionHeader']))
        
        # Analysis metadata
        story.append(Paragraph("7.1 Analysis Metadata", self.styles['SubsectionHeader']))
        
        tech_data = [
            ["Parameter", "Value"],
            ["Analysis Engine", "Fathom Static Analysis v1.0"],
            ["Analysis Date", record.get("scanned_at", datetime.now().isoformat())],
            ["Detection Confidence", f"{record.get('confidence', 0)}% ({record.get('confidence_level', 'unknown')})"],
            ["File Size Limit", "64 MB"],
            ["Timeout Settings", "1.5s per operation"],
        ]
        
        tech_table = Table(tech_data, colWidths=[2*inch, 4*inch])
        tech_table.setStyle(self._get_standard_table_style())
        story.append(tech_table)
        
        # Errors and warnings
        errors = record.get("errors", [])
        if errors:
            story.append(Paragraph("7.2 Analysis Warnings", self.styles['SubsectionHeader']))
            story.append(Paragraph("The following warnings were generated during analysis:", self.styles['Normal']))
            
            for error in errors[:10]:
                story.append(Paragraph(f"• {error}", self.styles['TechnicalData']))
        
        story.append(Spacer(1, 20))
        return story

    def _assess_threat_level(self, record: Dict[str, Any], final_type: str) -> tuple:
        """Assess overall threat level and return indicators"""
        threat_indicators = []
        
        # YARA matches
        yara_matches = record.get("heuristics", {}).get("yara", {}).get("matches", [])
        critical_yara = [m for m in yara_matches if "critical" in (m.get("tags", []))]
        high_yara = [m for m in yara_matches if "malware" in (m.get("tags", [])) or "high" in (m.get("tags", []))]
        
        if critical_yara:
            threat_indicators.append((f"{len(critical_yara)} critical YARA signatures", "CRITICAL"))
        if high_yara:
            threat_indicators.append((f"{len(high_yara)} high-risk YARA signatures", "HIGH"))
        
        # Type-specific indicators
        if final_type in ["pe", "dll"]:
            pe = record.get("static", {}).get("pe", {})
            
            # Unsigned executable
            signature = pe.get("signatures", {}).get("authenticode", {})
            if not signature.get("present"):
                threat_indicators.append(("Unsigned executable", "MEDIUM"))
            
            # Suspicious imports
            suspicious_imports = pe.get("suspicious_imports", [])
            if len(suspicious_imports) >= 10:
                threat_indicators.append((f"{len(suspicious_imports)} suspicious API imports", "HIGH"))
            elif len(suspicious_imports) >= 5:
                threat_indicators.append((f"{len(suspicious_imports)} suspicious API imports", "MEDIUM"))
            
            # High entropy sections
            sections = pe.get("sections", [])
            high_entropy_sections = [s for s in sections if s.get("entropy", 0) >= 7.5]
            if len(high_entropy_sections) >= 3:
                threat_indicators.append((f"{len(high_entropy_sections)} high-entropy sections (possible packing)", "HIGH"))
            elif len(high_entropy_sections) >= 1:
                threat_indicators.append((f"{len(high_entropy_sections)} high-entropy sections", "MEDIUM"))
        
        elif final_type == "pdf":
            counts = record.get("counts", {})
            
            # JavaScript
            js_objects = counts.get("js_objects_total", 0)
            if js_objects >= 5:
                threat_indicators.append((f"{js_objects} JavaScript objects", "HIGH"))
            elif js_objects >= 1:
                threat_indicators.append((f"{js_objects} JavaScript objects", "MEDIUM"))
            
            # Auto actions
            auto_actions = counts.get("auto_actions_total", 0)
            if auto_actions >= 1:
                threat_indicators.append((f"{auto_actions} auto-execution actions", "HIGH"))
        
        elif final_type in ["office_ooxml", "office_ole"]:
            office = record.get("static", {}).get("office", {})
            flags = office.get("flags", {})
            counts = record.get("counts", {})
            
            # Macros with shell usage
            if flags.get("suspicious_shell_usage"):
                threat_indicators.append(("Macros with OS command execution", "CRITICAL"))
            elif flags.get("suspicious_auto_exec"):
                threat_indicators.append(("Auto-execution macros", "HIGH"))
            elif flags.get("macro_present"):
                threat_indicators.append(("VBA macros present", "MEDIUM"))
        
        # Determine overall threat level
        if any(severity == "CRITICAL" for _, severity in threat_indicators):
            threat_level = "CRITICAL"
        elif any(severity == "HIGH" for _, severity in threat_indicators):
            threat_level = "HIGH"
        elif any(severity == "MEDIUM" for _, severity in threat_indicators):
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        return threat_level, threat_indicators

    def _generate_recommendations(self, record: Dict[str, Any], final_type: str, threat_level: str) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if threat_level in ["CRITICAL", "HIGH"]:
            recommendations.append("DO NOT execute this file in a production environment")
            recommendations.append("Isolate the file and analyze in a controlled sandbox environment")
            recommendations.append("Block file hash in security controls (firewalls, endpoint protection)")
        
        if final_type in ["pe", "dll"]:
            pe = record.get("static", {}).get("pe", {})
            
            if not pe.get("signatures", {}).get("authenticode", {}).get("present"):
                recommendations.append("Verify file source and integrity due to lack of digital signature")
            
            suspicious_imports = pe.get("suspicious_imports", [])
            if suspicious_imports:
                recommendations.append("Monitor for process creation, file system, and network activity if executed")
        
        elif final_type == "pdf":
            counts = record.get("counts", {})
            if counts.get("js_objects_total", 0) > 0:
                recommendations.append("Disable JavaScript in PDF viewers before opening")
                recommendations.append("Use PDF viewers with enhanced security features")
        
        elif final_type in ["office_ooxml", "office_ole"]:
            office = record.get("static", {}).get("office", {})
            flags = office.get("flags", {})
            
            if flags.get("macro_present"):
                recommendations.append("Disable macro execution in Office applications")
                recommendations.append("Review macro code manually before enabling execution")
        
        # General recommendations
        recommendations.extend([
            "Scan with multiple antivirus engines for additional detection",
            "Perform dynamic analysis in an isolated environment",
            "Update security controls with IOCs identified in this analysis",
            "Monitor network traffic for communication with identified URLs/IPs"
        ])
        
        return recommendations

    def _get_yara_description(self, match: Dict[str, Any]) -> str:
        """Get YARA rule description"""
        meta = match.get("meta", {})
        return (meta.get("description") or 
                meta.get("notes") or 
                meta.get("behavior") or 
                "Behavioral signature match")

    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColor(HexColor('#e53e3e'))
        canvas.drawString(50, doc.height + 50, "STATIC ANALYSIS REPORT")
        canvas.drawRightString(doc.width + 50, doc.height + 50, "FATHOM ANALYSIS ENGINE")
        
        # Header line
        canvas.setStrokeColor(HexColor('#e2e8f0'))
        canvas.line(50, doc.height + 40, doc.width + 50, doc.height + 40)
        
        # Footer
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(HexColor('#718096'))
        canvas.drawString(50, 30, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas.drawRightString(doc.width + 50, 30, f"Page {doc.page}")
        
        # Footer line
        canvas.line(50, 40, doc.width + 50, 40)
        
        canvas.restoreState()

    # Helper methods
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes into human readable format"""
        if bytes_val == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"

    def _get_standard_table_style(self):
        """Get standard table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2d3748')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 1), (-1, -1), white),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])

    def _get_analysis_table_style(self):
        """Get analysis table style"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])

    def _get_findings_table_style(self):
        """Get findings table style with severity colors"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a202c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('BACKGROUND', (0, 1), (-1, -1), white),
            ('TEXTCOLOR', (0, 1), (-1, -1), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ])


def generate_pdf_report(record: Dict[str, Any], output_dir: str = None) -> str:
    """
    Generate a professional static analysis PDF report
    
    Args:
        record: Analysis record from Fathom
        output_dir: Directory to save the report (defaults to server/out)
    
    Returns:
        Path to the generated PDF report
    """
    if output_dir is None:
        output_dir = Path(__file__).parent / "out"
    else:
        output_dir = Path(output_dir)
    
    output_dir.mkdir(exist_ok=True)
    
    # Generate filename
    sha256 = record.get("sha256", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"static_analysis_report_{sha256[:16]}_{timestamp}.pdf"
    output_path = output_dir / filename
    
    # Generate report
    generator = StaticAnalysisReportGenerator()
    generator.generate_report(record, str(output_path))
    
    return str(output_path)