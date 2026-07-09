#!/usr/bin/env python3
"""
Advanced PDF Extraction System for Fathom
Extracts embedded files, JavaScript, and other content from PDFs using multiple libraries
"""

import os
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Professional PDF libraries
try:
    import fitz  # PyMuPDF - Best for extraction
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    from peepdf.PDFCore import PDFParser
    PEEPDF_AVAILABLE = True
except ImportError:
    PEEPDF_AVAILABLE = False

try:
    import PyPDF4
    PYPDF_AVAILABLE = True
except ImportError:
    try:
        import PyPDF2 as PyPDF4
        PYPDF_AVAILABLE = True
    except ImportError:
        PYPDF_AVAILABLE = False

try:
    import pdfplumber
    PDFPLUMBER_AVAILABLE = True
except ImportError:
    PDFPLUMBER_AVAILABLE = False

# Additional extraction libraries
try:
    import pdfminer
    from pdfminer.high_level import extract_text
    from pdfminer.layout import LAParams
    PDFMINER_AVAILABLE = True
except ImportError:
    PDFMINER_AVAILABLE = False

class PDFExtractor:
    """Advanced PDF content extractor"""
    
    def __init__(self, output_dir: str = "extracted_content"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "embedded_files").mkdir(exist_ok=True)
        (self.output_dir / "javascript").mkdir(exist_ok=True)
        (self.output_dir / "images").mkdir(exist_ok=True)
        (self.output_dir / "fonts").mkdir(exist_ok=True)
        (self.output_dir / "metadata").mkdir(exist_ok=True)
    
    def extract_all_content(self, pdf_path: str) -> Dict[str, Any]:
        """Extract all possible content from a PDF"""
        
        pdf_hash = self._get_file_hash(pdf_path)
        extraction_dir = self.output_dir / pdf_hash
        extraction_dir.mkdir(exist_ok=True)
        
        results = {
            "pdf_path": pdf_path,
            "pdf_hash": pdf_hash,
            "extraction_dir": str(extraction_dir),
            "timestamp": datetime.now().isoformat(),
            "extracted_content": {
                "embedded_files": [],
                "javascript_objects": [],
                "images": [],
                "fonts": [],
                "text_content": None,
                "metadata": {}
            },
            "extraction_summary": {
                "total_embedded_files": 0,
                "total_javascript_objects": 0,
                "total_images": 0,
                "total_fonts": 0,
                "extraction_success": True,
                "errors": []
            }
        }
        
        try:
            # Extract using PyMuPDF (most comprehensive)
            if PYMUPDF_AVAILABLE:
                self._extract_with_pymupdf(pdf_path, extraction_dir, results)
            
            # Extract using peepdf (good for malicious content)
            if PEEPDF_AVAILABLE:
                self._extract_with_peepdf(pdf_path, extraction_dir, results)
            
            # Extract text using pdfminer (best text extraction)
            if PDFMINER_AVAILABLE:
                self._extract_text_with_pdfminer(pdf_path, extraction_dir, results)
            
            # Manual extraction for advanced cases
            self._manual_extraction(pdf_path, extraction_dir, results)
            
        except Exception as e:
            results["extraction_summary"]["extraction_success"] = False
            results["extraction_summary"]["errors"].append(f"extraction_error: {e}")
        
        # Save extraction report
        report_path = extraction_dir / "extraction_report.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return results
    
    def _extract_with_pymupdf(self, pdf_path: str, extraction_dir: Path, results: Dict):
        """Extract content using PyMuPDF"""
        
        try:
            doc = fitz.open(pdf_path)
            
            # Extract embedded files
            embfile_count = doc.embfile_count()
            for i in range(embfile_count):
                try:
                    embfile_info = doc.embfile_info(i)
                    embfile_content = doc.embfile_get(i)
                    
                    filename = embfile_info.get("filename", f"embedded_file_{i}")
                    # Sanitize filename
                    filename = re.sub(r'[<>:"|?*\\\/]', '_', filename)
                    
                    file_path = extraction_dir / "embedded_files" / filename
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, 'wb') as f:
                        f.write(embfile_content)
                    
                    file_hash = hashlib.sha256(embfile_content).hexdigest()
                    
                    results["extracted_content"]["embedded_files"].append({
                        "original_name": embfile_info.get("filename", f"embedded_file_{i}"),
                        "extracted_path": str(file_path),
                        "size": len(embfile_content),
                        "sha256": file_hash,
                        "file_info": embfile_info
                    })
                    
                except Exception as e:
                    results["extraction_summary"]["errors"].append(f"embfile_{i}_error: {e}")
            
            results["extraction_summary"]["total_embedded_files"] = len(results["extracted_content"]["embedded_files"])
            
            # Extract images
            for page_num in range(doc.page_count):
                page = doc[page_num]
                image_list = page.get_images()
                
                for img_index, img in enumerate(image_list):
                    try:
                        xref = img[0]
                        pix = fitz.Pixmap(doc, xref)
                        
                        if pix.n - pix.alpha < 4:  # GRAY or RGB
                            img_filename = f"page_{page_num+1}_img_{img_index+1}.png"
                            img_path = extraction_dir / "images" / img_filename
                            img_path.parent.mkdir(parents=True, exist_ok=True)
                            pix.save(str(img_path))
                            
                            results["extracted_content"]["images"].append({
                                "page": page_num + 1,
                                "index": img_index + 1,
                                "extracted_path": str(img_path),
                                "width": pix.width,
                                "height": pix.height,
                                "colorspace": pix.colorspace.name if pix.colorspace else "unknown"
                            })
                        
                        pix = None
                        
                    except Exception as e:
                        results["extraction_summary"]["errors"].append(f"image_page_{page_num}_img_{img_index}_error: {e}")
            
            results["extraction_summary"]["total_images"] = len(results["extracted_content"]["images"])
            
            # Extract JavaScript (enhanced)
            self._extract_javascript_pymupdf(doc, extraction_dir, results)
            
            # Extract fonts
            self._extract_fonts_pymupdf(doc, extraction_dir, results)
            
            doc.close()
            
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"pymupdf_extraction_error: {e}")
    
    def _extract_javascript_pymupdf(self, doc, extraction_dir: Path, results: Dict):
        """Extract JavaScript using PyMuPDF with enhanced detection"""
        
        try:
            # Get raw PDF data for manual parsing
            pdf_bytes = doc.tobytes()
            
            # Look for JavaScript patterns
            js_patterns = [
                (rb'/S\s*/JavaScript\s*/JS\s*\((.*?)\)', "action_javascript"),
                (rb'/JavaScript\s*<<.*?/JS\s*\((.*?)\)', "named_javascript"),
                (rb'app\.alert\s*\((.*?)\)', "app_alert"),
                (rb'console\.println\s*\((.*?)\)', "console_output"),
                (rb'eval\s*\((.*?)\)', "eval_code"),
                (rb'unescape\s*\((.*?)\)', "unescape_code")
            ]
            
            js_counter = 0
            
            for pattern, js_type in js_patterns:
                matches = re.findall(pattern, pdf_bytes, re.DOTALL | re.IGNORECASE)
                
                for match in matches:
                    try:
                        js_content = match.decode('latin-1', errors='ignore')
                        
                        # Clean up JavaScript content
                        js_content = self._clean_javascript_content(js_content)
                        
                        if len(js_content.strip()) > 10:  # Only save substantial content
                            js_counter += 1
                            js_filename = f"javascript_{js_counter}_{js_type}.js"
                            js_path = extraction_dir / "javascript" / js_filename
                            js_path.parent.mkdir(parents=True, exist_ok=True)
                            
                            with open(js_path, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(f"// Extracted JavaScript ({js_type})\n")
                                f.write(f"// Extraction timestamp: {datetime.now().isoformat()}\n\n")
                                f.write(js_content)
                            
                            results["extracted_content"]["javascript_objects"].append({
                                "type": js_type,
                                "extracted_path": str(js_path),
                                "size": len(js_content),
                                "preview": js_content[:200] + "..." if len(js_content) > 200 else js_content,
                                "sha256": hashlib.sha256(js_content.encode('utf-8')).hexdigest()
                            })
                    
                    except Exception as e:
                        results["extraction_summary"]["errors"].append(f"js_extraction_error: {e}")
            
            results["extraction_summary"]["total_javascript_objects"] = len(results["extracted_content"]["javascript_objects"])
            
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"javascript_extraction_error: {e}")
    
    def _extract_fonts_pymupdf(self, doc, extraction_dir: Path, results: Dict):
        """Extract embedded fonts"""
        
        try:
            font_list = []
            
            for page_num in range(doc.page_count):
                page = doc[page_num]
                
                # Get font information
                fonts = page.get_fonts()
                
                for font in fonts:
                    try:
                        font_info = {
                            "page": page_num + 1,
                            "xref": font[0],
                            "name": font[1],
                            "type": font[2],
                            "encoding": font[3] if len(font) > 3 else "unknown"
                        }
                        
                        # Try to extract font data
                        try:
                            font_data = doc.extract_font(font[0])
                            if font_data:
                                font_filename = f"font_{font[0]}_{font[1].replace('/', '_')}.ttf"
                                font_filename = re.sub(r'[<>:"|?*\\\/]', '_', font_filename)
                                font_path = extraction_dir / "fonts" / font_filename
                                
                                with open(font_path, 'wb') as f:
                                    f.write(font_data[1])  # font_data is (ext, data, name)
                                
                                font_info["extracted_path"] = str(font_path)
                                font_info["size"] = len(font_data[1])
                        
                        except:
                            pass  # Font extraction failed, but we still have info
                        
                        font_list.append(font_info)
                    
                    except Exception as e:
                        results["extraction_summary"]["errors"].append(f"font_extraction_error: {e}")
            
            results["extracted_content"]["fonts"] = font_list
            results["extraction_summary"]["total_fonts"] = len(font_list)
            
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"fonts_extraction_error: {e}")
    
    def _extract_with_peepdf(self, pdf_path: str, extraction_dir: Path, results: Dict):
        """Extract content using peepdf (good for malicious analysis)"""
        
        try:
            # peepdf is excellent for analyzing malicious PDFs
            # It can extract JavaScript, embedded files, and suspicious objects
            
            parser = PDFParser()
            ret, pdf_file = parser.parse(pdf_path, forceMode=True, looseMode=True)
            
            if ret == 0:  # Success
                # Extract JavaScript objects
                js_objects = pdf_file.getJSCode()
                
                for i, js_code in enumerate(js_objects):
                    if js_code and len(js_code.strip()) > 10:
                        js_filename = f"peepdf_javascript_{i+1}.js"
                        js_path = extraction_dir / "javascript" / js_filename
                        
                        with open(js_path, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(f"// Extracted with peepdf\n")
                            f.write(f"// Extraction timestamp: {datetime.now().isoformat()}\n\n")
                            f.write(js_code)
                        
                        # Avoid duplicates by checking if we already have this content
                        js_hash = hashlib.sha256(js_code.encode('utf-8')).hexdigest()
                        existing_hashes = [js["sha256"] for js in results["extracted_content"]["javascript_objects"]]
                        
                        if js_hash not in existing_hashes:
                            results["extracted_content"]["javascript_objects"].append({
                                "type": "peepdf_javascript",
                                "extracted_path": str(js_path),
                                "size": len(js_code),
                                "preview": js_code[:200] + "..." if len(js_code) > 200 else js_code,
                                "sha256": js_hash
                            })
            
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"peepdf_extraction_error: {e}")
    
    def _extract_text_with_pdfminer(self, pdf_path: str, extraction_dir: Path, results: Dict):
        """Extract text content using pdfminer"""
        
        try:
            # Extract text with layout analysis
            laparams = LAParams(
                line_margin=0.5,
                word_margin=0.1,
                char_margin=2.0,
                boxes_flow=0.5,
                all_texts=False
            )
            
            text_content = extract_text(pdf_path, laparams=laparams)
            
            if text_content and len(text_content.strip()) > 0:
                text_path = extraction_dir / "text_content.txt"
                
                with open(text_path, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(f"# PDF Text Content\n")
                    f.write(f"# Extracted with pdfminer\n")
                    f.write(f"# Timestamp: {datetime.now().isoformat()}\n\n")
                    f.write(text_content)
                
                results["extracted_content"]["text_content"] = {
                    "extracted_path": str(text_path),
                    "size": len(text_content),
                    "preview": text_content[:500] + "..." if len(text_content) > 500 else text_content
                }
        
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"text_extraction_error: {e}")
    
    def _manual_extraction(self, pdf_path: str, extraction_dir: Path, results: Dict):
        """Manual extraction for advanced cases"""
        
        try:
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            
            # Look for embedded file patterns
            # PDF embedded files are often in stream objects
            stream_pattern = rb'stream\s*\n(.*?)\nendstream'
            streams = re.findall(stream_pattern, pdf_data, re.DOTALL)
            
            suspicious_streams = []
            
            for i, stream_data in enumerate(streams):
                # Check if stream looks like an embedded file
                if len(stream_data) > 1000:  # Substantial content
                    # Check for file signatures
                    file_sigs = {
                        b'\x4D\x5A': 'exe',  # PE/EXE
                        b'\x50\x4B': 'zip',  # ZIP/Office
                        b'\x25\x50\x44\x46': 'pdf',  # PDF
                        b'\xFF\xD8\xFF': 'jpg',  # JPEG
                        b'\x89\x50\x4E\x47': 'png',  # PNG
                    }
                    
                    for sig, ext in file_sigs.items():
                        if stream_data.startswith(sig):
                            stream_filename = f"manual_extracted_stream_{i}.{ext}"
                            stream_path = extraction_dir / "embedded_files" / stream_filename
                            
                            with open(stream_path, 'wb') as sf:
                                sf.write(stream_data)
                            
                            stream_hash = hashlib.sha256(stream_data).hexdigest()
                            
                            # Check for duplicates
                            existing_hashes = [ef["sha256"] for ef in results["extracted_content"]["embedded_files"]]
                            
                            if stream_hash not in existing_hashes:
                                results["extracted_content"]["embedded_files"].append({
                                    "original_name": f"stream_{i}.{ext}",
                                    "extracted_path": str(stream_path),
                                    "size": len(stream_data),
                                    "sha256": stream_hash,
                                    "extraction_method": "manual_stream_analysis"
                                })
                            
                            break
        
        except Exception as e:
            results["extraction_summary"]["errors"].append(f"manual_extraction_error: {e}")
    
    def _clean_javascript_content(self, js_content: str) -> str:
        """Clean and format JavaScript content"""
        
        # Remove PDF-specific escaping
        js_content = js_content.replace('\\n', '\n')
        js_content = js_content.replace('\\t', '\t')
        js_content = js_content.replace('\\r', '\r')
        js_content = js_content.replace('\\"', '"')
        js_content = js_content.replace("\\'", "'")
        
        # Remove trailing parentheses and brackets
        js_content = js_content.rstrip(')')
        js_content = js_content.rstrip(']')
        js_content = js_content.rstrip('}')
        
        return js_content.strip()
    
    def _get_file_hash(self, file_path: str) -> str:
        """Get SHA256 hash of file"""
        
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]  # First 16 chars for directory name

# Convenience functions
def extract_pdf_content(pdf_path: str, output_dir: str = "extracted_content") -> Dict[str, Any]:
    """Extract all content from a PDF file"""
    
    extractor = PDFExtractor(output_dir)
    return extractor.extract_all_content(pdf_path)

def get_extraction_capabilities() -> Dict[str, bool]:
    """Get available extraction capabilities"""
    
    return {
        "PyMuPDF": PYMUPDF_AVAILABLE,
        "peepdf": PEEPDF_AVAILABLE,
        "PyPDF4": PYPDF_AVAILABLE,
        "pdfplumber": PDFPLUMBER_AVAILABLE,
        "pdfminer": PDFMINER_AVAILABLE
    }

if __name__ == "__main__":
    # Test extraction
    import sys
    
    if len(sys.argv) > 1:
        pdf_path = sys.argv[1]
        print(f"🔍 Extracting content from: {pdf_path}")
        
        capabilities = get_extraction_capabilities()
        print(f"📚 Available libraries: {capabilities}")
        
        results = extract_pdf_content(pdf_path)
        
        print(f"\n📊 Extraction Results:")
        print(f"   Embedded Files: {results['extraction_summary']['total_embedded_files']}")
        print(f"   JavaScript Objects: {results['extraction_summary']['total_javascript_objects']}")
        print(f"   Images: {results['extraction_summary']['total_images']}")
        print(f"   Fonts: {results['extraction_summary']['total_fonts']}")
        print(f"   Extraction Directory: {results['extraction_dir']}")
        
        if results['extraction_summary']['errors']:
            print(f"\n⚠️  Errors: {len(results['extraction_summary']['errors'])}")
            for error in results['extraction_summary']['errors'][:3]:
                print(f"   • {error}")
    else:
        print("Usage: python pdf_extractor.py <pdf_file>")
        print("Example: python pdf_extractor.py ../test_samples/advanced_js_test.pdf")