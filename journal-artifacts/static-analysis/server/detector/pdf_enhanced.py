"""
Professional PDF Analysis using industry-standard libraries
Replaces basic pdf_full.py with comprehensive analysis
"""

import json
import re
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Professional PDF libraries (with fallbacks)
try:
    import fitz  # PyMuPDF
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

# Configuration
MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_STRING_EXTRACTION = 10000
MAX_JAVASCRIPT_PREVIEW = 2000

def get_available_libraries() -> Dict[str, bool]:
    """Return which PDF analysis libraries are available"""
    return {
        "PyMuPDF": PYMUPDF_AVAILABLE,
        "peepdf": PEEPDF_AVAILABLE, 
        "PyPDF4": PYPDF_AVAILABLE,
        "pdfplumber": PDFPLUMBER_AVAILABLE
    }

def analyze_pdf_enhanced(file_path: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
    """Professional PDF analysis using multiple libraries"""
    
    # Initialize result structure
    static_pdf = {
        "versions": [],
        "headers": [],
        "trailers": [],
        "objects": [],
        "names": [],
        "embedded_files": [],
        "actions": [],
        "anomalies": [],
        "metadata": {
            "Producer": None, "Creator": None, "CreationDate": None, "ModDate": None,
            "Title": None, "Author": None, "Subject": None, "Keywords": None,
        },
        "encryption": {
            "Filter": None, "V": None, "R": None, "Length": None, "P": None,
        },
        "strings": {},
        "javascript": {"present": False, "objects": []},
        "extracted_content": {
            "embedded_files": [],
            "javascript_objects": [],
            "images": [],
            "fonts": [],
            "text_content": None
        },
        "analysis_metadata": {"engines_used": [], "extraction_method": "enhanced"}
    }
    
    counts = {
        "objects_total": 0, "streams_total": 0, "js_objects_total": 0, 
        "auto_actions_total": 0, "embedded_files_total": 0, "urls_total": 0, 
        "strings_total": 0, "ioc_urls_total": 0
    }
    
    errors = []
    
    # Check file size
    try:
        file_size = Path(file_path).stat().st_size
        if file_size > MAX_INPUT_SIZE:
            errors.append("file_too_large")
            return {"static": {"pdf": static_pdf}, "counts": counts, "errors": errors}
    except Exception as e:
        errors.append(f"file_access_error:{e}")
        return {"static": {"pdf": static_pdf}, "counts": counts, "errors": errors}
    
    # Use PyMuPDF as primary engine
    if PYMUPDF_AVAILABLE:
        try:
            fitz_results = analyze_with_pymupdf(file_path)
            merge_pymupdf_results(static_pdf, counts, fitz_results)
            static_pdf["analysis_metadata"]["engines_used"].append("PyMuPDF")
        except Exception as e:
            errors.append(f"pymupdf_error:{e}")
    
    # Use PyPDF4 as fallback
    if PYPDF_AVAILABLE and not static_pdf["metadata"]["Producer"]:
        try:
            pypdf_results = analyze_with_pypdf(file_path)
            merge_pypdf_results(static_pdf, counts, pypdf_results)
            static_pdf["analysis_metadata"]["engines_used"].append("PyPDF4")
        except Exception as e:
            errors.append(f"pypdf_error:{e}")
    
    # Extract strings and IOCs
    try:
        strings_info = extract_strings_and_iocs(file_path)
        static_pdf["strings"] = strings_info
        counts["strings_total"] = strings_info.get("total", 0)
        counts["ioc_urls_total"] = len(strings_info.get("ioc_urls", []))
    except Exception as e:
        errors.append(f"string_extraction_error:{e}")
    
    return {
        "static": {"pdf": static_pdf},
        "counts": counts,
        "errors": errors
    }

def analyze_with_pymupdf(file_path: str) -> Dict[str, Any]:
    """Comprehensive analysis using PyMuPDF (fitz)"""
    results = {"metadata": {}, "structure": {}, "content": {}}
    
    try:
        doc = fitz.open(file_path)
        
        # Extract metadata
        metadata = doc.metadata
        results["metadata"] = {
            "Producer": clean_metadata_value(metadata.get("producer")),
            "Creator": clean_metadata_value(metadata.get("creator")), 
            "CreationDate": format_fitz_date(metadata.get("creationDate")),
            "ModDate": format_fitz_date(metadata.get("modDate")),
            "Title": clean_metadata_value(metadata.get("title")),
            "Author": clean_metadata_value(metadata.get("author")),
            "Subject": clean_metadata_value(metadata.get("subject")),
            "Keywords": clean_metadata_value(metadata.get("keywords")),
        }
        
        # Document structure
        results["structure"] = {
            "page_count": doc.page_count,
            "is_encrypted": doc.needs_pass,
            "is_pdf": doc.is_pdf
        }
        
        # Content analysis
        javascript_objects = []
        embedded_files = []
        
        # Check for JavaScript in document-level actions (OpenAction, etc.)
        try:
            # Get the document's JavaScript
            js_count = doc.embfile_count()  # This might include JS
            
            # Check for OpenAction JavaScript
            if hasattr(doc, 'metadata') and doc.metadata:
                # Look for JavaScript in document structure
                pass
            
            # Try to extract JavaScript from the document
            # PyMuPDF doesn't have direct JS extraction, so we'll parse manually
            pdf_source = doc.tobytes()
            
            # Look for JavaScript patterns in the raw PDF
            js_patterns = [
                rb'/S\s*/JavaScript',
                rb'/JS\s*\(',
                rb'app\.alert',
                rb'console\.println',
                rb'eval\s*\(',
                rb'unescape\s*\('
            ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, pdf_source, re.IGNORECASE)
                if matches:
                    # Found JavaScript pattern, try to extract content
                    js_match = re.search(rb'/JS\s*\((.*?)\)', pdf_source, re.DOTALL)
                    if js_match:
                        js_content = js_match.group(1).decode('latin-1', errors='ignore')
                        javascript_objects.append({
                            "type": "document_action",
                            "content": js_content[:500],
                            "pattern": pattern.decode('latin-1', errors='ignore')
                        })
                        break
            
            # Look for Named JavaScript objects
            names_pattern = rb'/JavaScript\s*<<.*?/Names\s*\[(.*?)\]'
            names_match = re.search(names_pattern, pdf_source, re.DOTALL)
            if names_match:
                names_content = names_match.group(1).decode('latin-1', errors='ignore')
                # Extract individual JavaScript objects
                js_refs = re.findall(r'\((.*?)\)\s+(\d+\s+\d+\s+R)', names_content)
                for js_name, js_ref in js_refs:
                    javascript_objects.append({
                        "type": "named_javascript",
                        "name": js_name,
                        "reference": js_ref,
                        "content": f"Named JavaScript object: {js_name}"
                    })
            
            # Look for individual JavaScript objects
            js_obj_pattern = rb'/S\s*/JavaScript\s*/JS\s*\((.*?)\)'
            js_obj_matches = re.findall(js_obj_pattern, pdf_source, re.DOTALL)
            for i, js_content in enumerate(js_obj_matches):
                content = js_content.decode('latin-1', errors='ignore')
                javascript_objects.append({
                    "type": "javascript_object",
                    "object_index": i,
                    "content": content[:500]
                })
                
        except Exception as e:
            pass
        
        # Analyze pages (first 10 for performance)
        for page_num in range(min(doc.page_count, 10)):
            page = doc[page_num]
            
            # Check annotations for JavaScript
            for annot in page.annots():
                annot_dict = annot.info
                content = annot_dict.get("content", "")
                if content and "javascript" in content.lower():
                    javascript_objects.append({
                        "page": page_num + 1,
                        "type": "annotation",
                        "content": content[:500]
                    })
        
        # Check embedded files and extract content
        try:
            embfile_count = doc.embfile_count()
            for i in range(embfile_count):
                embfile_info = doc.embfile_info(i)
                
                # Extract embedded file content
                try:
                    embfile_content = doc.embfile_get(i)
                    filename = embfile_info.get("filename", f"embedded_{i}")
                    
                    # Get file hash and preview
                    file_hash = hashlib.sha256(embfile_content).hexdigest()
                    
                    # Detect file type from content
                    file_type = "unknown"
                    if embfile_content.startswith(b'\x4D\x5A'):
                        file_type = "PE/EXE"
                    elif embfile_content.startswith(b'\x50\x4B'):
                        file_type = "ZIP/Office"
                    elif embfile_content.startswith(b'%PDF'):
                        file_type = "PDF"
                    elif embfile_content.startswith(b'\xFF\xD8\xFF'):
                        file_type = "JPEG"
                    elif embfile_content.startswith(b'\x89\x50\x4E\x47'):
                        file_type = "PNG"
                    elif filename.lower().endswith(('.bat', '.cmd')):
                        file_type = "Batch Script"
                    elif filename.lower().endswith(('.js', '.vbs')):
                        file_type = "Script"
                    
                    # Get text preview for text files
                    text_preview = None
                    if file_type in ["Batch Script", "Script"] or len(embfile_content) < 1000:
                        try:
                            text_preview = embfile_content.decode('utf-8', errors='ignore')[:500]
                        except:
                            try:
                                text_preview = embfile_content.decode('latin-1', errors='ignore')[:500]
                            except:
                                pass
                    
                    embedded_files.append({
                        "name": filename,
                        "size": len(embfile_content),
                        "obj_ref": f"embedded_{i}",
                        "file_type": file_type,
                        "sha256": file_hash,
                        "content_preview": text_preview,
                        "raw_content": embfile_content[:1000].hex() if len(embfile_content) <= 1000 else None  # Convert bytes to hex string
                    })
                    
                except Exception as e:
                    # Fallback to basic info if extraction fails
                    embedded_files.append({
                        "name": embfile_info.get("filename", f"embedded_{i}"),
                        "size": embfile_info.get("size", 0),
                        "obj_ref": f"embedded_{i}",
                        "extraction_error": str(e)
                    })
        except:
            pass
        
        results["content"] = {
            "javascript_objects": javascript_objects,
            "embedded_files": embedded_files
        }
        
        # Store extracted content for UI display
        results["extracted_content"] = {
            "embedded_files": embedded_files,
            "javascript_objects": javascript_objects
        }
        
        doc.close()
        
    except Exception as e:
        results["error"] = str(e)
    
    return results

def analyze_with_pypdf(file_path: str) -> Dict[str, Any]:
    """Fallback analysis using PyPDF4"""
    results = {"metadata": {}, "structure": {}}
    
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF4.PdfFileReader(file)
            
            # Extract metadata
            if pdf_reader.documentInfo:
                doc_info = pdf_reader.documentInfo
                results["metadata"] = {
                    "Producer": clean_metadata_value(doc_info.get("/Producer")),
                    "Creator": clean_metadata_value(doc_info.get("/Creator")),
                    "CreationDate": clean_metadata_value(doc_info.get("/CreationDate")),
                    "ModDate": clean_metadata_value(doc_info.get("/ModDate")),
                    "Title": clean_metadata_value(doc_info.get("/Title")),
                    "Author": clean_metadata_value(doc_info.get("/Author")),
                    "Subject": clean_metadata_value(doc_info.get("/Subject")),
                    "Keywords": clean_metadata_value(doc_info.get("/Keywords")),
                }
            
            # Basic structure
            results["structure"] = {
                "page_count": pdf_reader.numPages,
                "is_encrypted": pdf_reader.isEncrypted
            }
            
    except Exception as e:
        results["error"] = str(e)
    
    return results

def extract_strings_and_iocs(file_path: str) -> Dict[str, Any]:
    """Extract strings and IOCs from PDF"""
    strings_info = {
        "total": 0,
        "unique": 0,
        "ioc_urls": [],
        "suspicious_keywords": [],
        "sample_strings": []
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Extract ASCII strings
        ascii_strings = re.findall(rb'[\x20-\x7e]{6,}', data)
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        
        # Deduplicate
        unique_strings = list(set(all_strings))
        
        strings_info["total"] = len(all_strings)
        strings_info["unique"] = len(unique_strings)
        
        # Extract URLs
        url_pattern = re.compile(r'https?://[\w\-\.\/?#%&=:+,@~]+', re.IGNORECASE)
        urls = set()
        for s in unique_strings:
            urls.update(url_pattern.findall(s))
        
        strings_info["ioc_urls"] = list(urls)[:20]
        
        # Suspicious keywords
        suspicious_keywords = [
            "javascript", "activex", "shellcode", "exploit", "payload",
            "eval", "unescape", "fromcharcode", "wscript", "shell"
        ]
        
        found_keywords = []
        for keyword in suspicious_keywords:
            for s in unique_strings:
                if keyword.lower() in s.lower():
                    found_keywords.append(keyword)
                    break
        
        strings_info["suspicious_keywords"] = found_keywords
        strings_info["sample_strings"] = unique_strings[:10]
        
    except Exception as e:
        strings_info["error"] = str(e)
    
    return strings_info

def merge_pymupdf_results(static_pdf: Dict, counts: Dict, results: Dict):
    """Merge PyMuPDF results into static analysis structure"""
    if "metadata" in results:
        for key, value in results["metadata"].items():
            if value:
                static_pdf["metadata"][key] = value
    
    if "structure" in results:
        structure = results["structure"]
        counts["objects_total"] = structure.get("page_count", 0)
        
        if structure.get("is_encrypted"):
            static_pdf["encryption"]["Filter"] = "Standard"
    
    if "content" in results:
        content = results["content"]
        
        # JavaScript objects
        js_objects = content.get("javascript_objects", [])
        static_pdf["javascript"]["objects"] = js_objects
        static_pdf["javascript"]["present"] = len(js_objects) > 0
        counts["js_objects_total"] = len(js_objects)
        
        # Embedded files
        embedded = content.get("embedded_files", [])
        static_pdf["embedded_files"] = embedded
        counts["embedded_files_total"] = len(embedded)
        
    
    # Store extracted content for UI
    if "extracted_content" in results:
        static_pdf["extracted_content"] = results["extracted_content"]

def merge_pypdf_results(static_pdf: Dict, counts: Dict, results: Dict):
    """Merge PyPDF4 results into static analysis structure"""
    if "metadata" in results:
        for key, value in results["metadata"].items():
            if value and not static_pdf["metadata"].get(key):
                static_pdf["metadata"][key] = value
    
    if "structure" in results:
        structure = results["structure"]
        if not counts["objects_total"]:
            counts["objects_total"] = structure.get("page_count", 0)

def clean_metadata_value(value) -> Optional[str]:
    """Clean and validate metadata values"""
    if not value:
        return None
    
    # Handle PyPDF objects
    if hasattr(value, 'getObject'):
        value = str(value.getObject())
    elif not isinstance(value, str):
        value = str(value)
    
    # Clean up common PDF encoding issues
    value = value.strip()
    if value.startswith('D:'):
        return format_pdf_date(value)
    
    # Remove null bytes and control characters
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    
    return value if value else None

def format_fitz_date(date_str: str) -> Optional[str]:
    """Format PyMuPDF date strings"""
    if not date_str:
        return None
    
    try:
        # PyMuPDF returns ISO format dates
        if 'T' in date_str:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        return date_str
    except:
        return date_str

def format_pdf_date(date_str: str) -> Optional[str]:
    """Format PDF date strings (D:YYYYMMDDHHmmSSOHH'mm')"""
    if not date_str or not date_str.startswith('D:'):
        return date_str
    
    try:
        # Extract date part (remove D: prefix and timezone)
        date_part = date_str[2:16]  # YYYYMMDDHHmmSS
        if len(date_part) >= 8:
            year = date_part[:4]
            month = date_part[4:6] if len(date_part) >= 6 else '01'
            day = date_part[6:8] if len(date_part) >= 8 else '01'
            hour = date_part[8:10] if len(date_part) >= 10 else '00'
            minute = date_part[10:12] if len(date_part) >= 12 else '00'
            second = date_part[12:14] if len(date_part) >= 14 else '00'
            
            return f"{year}-{month}-{day} {hour}:{minute}:{second}"
    except:
        pass
    
    return date_str