"""
Enhanced Office Analysis using professional libraries
Comprehensive macro extraction and analysis for Office documents
"""

import json
import re
import hashlib
import time
import zipfile
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import io

# Professional Office analysis libraries (with fallbacks)
try:
    import oletools.olevba as olevba
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    import oletools.oleid as oleid
    OLEID_AVAILABLE = True
except ImportError:
    OLEID_AVAILABLE = False

try:
    import oletools.oleobj as oleobj
    OLEOBJ_AVAILABLE = True
except ImportError:
    OLEOBJ_AVAILABLE = False

try:
    import oletools.rtfobj as rtfobj
    RTFOBJ_AVAILABLE = True
except ImportError:
    RTFOBJ_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

# Configuration
MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_MACRO_PREVIEW = 2000
MAX_EMBEDDED_FILES = 100

def get_available_libraries() -> Dict[str, bool]:
    """Return which Office analysis libraries are available"""
    return {
        'oletools': OLETOOLS_AVAILABLE,
        'oleid': OLEID_AVAILABLE,
        'oleobj': OLEOBJ_AVAILABLE,
        'rtfobj': RTFOBJ_AVAILABLE,
        'olefile': OLEFILE_AVAILABLE,
        'zipfile': True,  # Built-in
    }

def extract_macros_with_oletools(file_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract macros using oletools VBA_Parser"""
    macros = []
    errors = []
    
    if not OLETOOLS_AVAILABLE:
        errors.append("oletools_not_available")
        return macros, errors
    
    try:
        vbaparser = VBA_Parser(file_path)
        
        if vbaparser.detect_vba_macros():
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                if vba_code:
                    # Analyze macro for suspicious patterns
                    autoexec_keywords = [
                        'AutoOpen', 'AutoExec', 'Auto_Open', 'Auto_Exec',
                        'Document_Open', 'DocumentOpen', 'Workbook_Open',
                        'WorkbookOpen', 'Auto_Close', 'Document_Close'
                    ]
                    
                    suspicious_keywords = [
                        'Shell', 'CreateObject', 'GetObject', 'CallByName',
                        'MacScript', 'ExecuteExcel4Macro', 'Application.Run',
                        'WScript.Shell', 'cmd.exe', 'powershell', 'rundll32',
                        'URLDownloadToFile', 'InternetOpen', 'HttpOpenRequest'
                    ]
                    
                    # Find autoexec indicators
                    autoexec_found = []
                    for keyword in autoexec_keywords:
                        if keyword.lower() in vba_code.lower():
                            autoexec_found.append(keyword)
                    
                    # Find suspicious indicators
                    suspicious_found = []
                    for keyword in suspicious_keywords:
                        if keyword.lower() in vba_code.lower():
                            suspicious_found.append(keyword)
                    
                    # Detect obfuscation
                    obfuscation_indicators = []
                    if len(re.findall(r'Chr\s*\(', vba_code, re.IGNORECASE)) > 5:
                        obfuscation_indicators.append('chr_encoding')
                    if len(re.findall(r'&\s*["\']', vba_code)) > 10:
                        obfuscation_indicators.append('string_concatenation')
                    if 'Environ(' in vba_code:
                        obfuscation_indicators.append('environment_variables')
                    
                    macro_info = {
                        'module_name': vba_filename or filename,
                        'stream_path': stream_path,
                        'code_size': len(vba_code),
                        'autoexec_indicators': autoexec_found,
                        'suspicious_indicators': suspicious_found,
                        'obfuscation_indicators': obfuscation_indicators,
                        'preview': vba_code[:MAX_MACRO_PREVIEW] if vba_code else '',
                        'preview_truncated': len(vba_code) > MAX_MACRO_PREVIEW,
                        'has_autoexec': len(autoexec_found) > 0,
                        'has_suspicious': len(suspicious_found) > 0,
                        'is_obfuscated': len(obfuscation_indicators) > 0
                    }
                    
                    macros.append(macro_info)
        
        vbaparser.close()
        
    except Exception as e:
        errors.append(f"oletools_macro_extraction_error: {str(e)}")
    
    return macros, errors

def analyze_ole_structure(file_path: str) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze OLE file structure using olefile"""
    structure = {
        'streams': [],
        'storage_objects': [],
        'metadata': {},
        'ole_type': 'unknown'
    }
    errors = []
    
    if not OLEFILE_AVAILABLE:
        errors.append("olefile_not_available")
        return structure, errors
    
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            
            # Get OLE metadata
            meta = ole.get_metadata()
            if meta:
                structure['metadata'] = {
                    'author': getattr(meta, 'author', None),
                    'title': getattr(meta, 'title', None),
                    'subject': getattr(meta, 'subject', None),
                    'creating_application': getattr(meta, 'creating_application', None),
                    'last_saved_by': getattr(meta, 'last_saved_by', None),
                    'created': str(getattr(meta, 'created', None)),
                    'last_saved_time': str(getattr(meta, 'last_saved_time', None)),
                }
            
            # List all streams and storages
            for item in ole.listdir():
                item_path = '/'.join(item)
                if ole._olestream_size(item) is not None:
                    # It's a stream
                    size = ole._olestream_size(item)
                    structure['streams'].append({
                        'name': item_path,
                        'size': size,
                        'type': 'stream'
                    })
                else:
                    # It's a storage
                    structure['storage_objects'].append({
                        'name': item_path,
                        'type': 'storage'
                    })
            
            # Determine OLE document type
            if ole.exists('WordDocument'):
                structure['ole_type'] = 'word_document'
            elif ole.exists('Workbook') or ole.exists('Book'):
                structure['ole_type'] = 'excel_workbook'
            elif ole.exists('PowerPoint Document'):
                structure['ole_type'] = 'powerpoint_presentation'
            
            ole.close()
            
    except Exception as e:
        errors.append(f"ole_structure_analysis_error: {str(e)}")
    
    return structure, errors

def extract_embedded_objects(file_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Extract embedded objects using oletools"""
    embedded_objects = []
    errors = []
    
    if not OLEOBJ_AVAILABLE:
        errors.append("oleobj_not_available")
        return embedded_objects, errors
    
    try:
        # Try to extract OLE objects - simplified approach
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # For now, skip oleobj extraction due to API changes
        # Focus on the macro extraction which is working well
        # This can be enhanced later with proper oleobj integration
        
        # Basic embedded object detection by scanning for common signatures
        pe_signatures = [b'MZ', b'\\x4D\\x5A']
        zip_signatures = [b'PK\\x03\\x04', b'PK\\x05\\x06']
        pdf_signatures = [b'%PDF']
        
        for i, signature in enumerate(pe_signatures + zip_signatures + pdf_signatures):
            if signature in file_data:
                # Found potential embedded object
                obj_type = "PE/EXE" if signature in pe_signatures else \
                          "ZIP/Archive" if signature in zip_signatures else \
                          "PDF" if signature in pdf_signatures else "unknown"
                
                # This is a basic detection - could be enhanced
                embedded_objects.append({
                    'index': i,
                    'type': obj_type,
                    'size': 0,  # Size unknown in basic detection
                    'sha256': '',  # Hash unknown in basic detection
                    'ole_type': 'detected_signature',
                    'text_preview': '',
                    'raw_content': None
                })
                
                if len(embedded_objects) >= MAX_EMBEDDED_FILES:
                    break
                
    except Exception as e:
        errors.append(f"embedded_objects_extraction_error: {str(e)}")
    
    return embedded_objects, errors

def analyze_ooxml_structure(file_path: str) -> Tuple[Dict[str, Any], List[str]]:
    """Analyze OOXML structure using zipfile"""
    structure = {
        'parts': [],
        'relationships': [],
        'content_types': {},
        'external_references': []
    }
    errors = []
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # List all parts
            for info in zf.infolist():
                structure['parts'].append({
                    'name': info.filename,
                    'size': info.file_size,
                    'compressed_size': info.compress_size,
                    'compression_type': info.compress_type,
                    'date_time': info.date_time
                })
            
            # Read content types
            try:
                content_types_xml = zf.read('[Content_Types].xml').decode('utf-8')
                structure['content_types'] = {'raw': content_types_xml[:1000]}
            except:
                pass
            
            # Read main relationships
            try:
                rels_xml = zf.read('_rels/.rels').decode('utf-8')
                structure['relationships'] = {'main': rels_xml[:1000]}
                
                # Look for external references
                external_refs = re.findall(r'Target="(https?://[^"]+)"', rels_xml)
                structure['external_references'].extend(external_refs)
                
            except:
                pass
            
            # Look for macro-related files
            macro_files = []
            for info in zf.infolist():
                if 'vbaProject.bin' in info.filename.lower():
                    macro_files.append(info.filename)
                elif 'macros' in info.filename.lower():
                    macro_files.append(info.filename)
            
            structure['macro_files'] = macro_files
            
    except Exception as e:
        errors.append(f"ooxml_structure_analysis_error: {str(e)}")
    
    return structure, errors

def detect_office_type(file_path: str) -> str:
    """Detect specific Office document type"""
    try:
        # Check if it's an OLE file
        if OLEFILE_AVAILABLE and olefile.isOleFile(file_path):
            return "ole"
        
        # Check if it's OOXML (ZIP-based)
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                files = zf.namelist()
                if any('word/' in f for f in files):
                    return "docx"
                elif any('xl/' in f for f in files):
                    return "xlsx"
                elif any('ppt/' in f for f in files):
                    return "pptx"
                else:
                    return "ooxml"
        except:
            pass
        
        # Check file extension as fallback
        suffix = Path(file_path).suffix.lower()
        if suffix in ['.doc', '.dot', '.xls', '.xlt', '.ppt', '.pot']:
            return "ole"
        elif suffix in ['.docx', '.docm', '.dotx', '.dotm']:
            return "docx"
        elif suffix in ['.xlsx', '.xlsm', '.xltx', '.xltm']:
            return "xlsx"
        elif suffix in ['.pptx', '.pptm', '.potx', '.potm']:
            return "pptx"
        
    except Exception:
        pass
    
    return "unknown"

def analyze_office_enhanced(file_path: str) -> Dict[str, Any]:
    """
    Enhanced Office analysis using professional libraries
    """
    start_time = time.time()
    
    # Initialize result structure
    result = {
        "static": {
            "office": {
                "structure": {},
                "macros": [],
                "embedded_objects": [],
                "metadata": {},
                "strings": {},
                "entropy": {"overall": 0.0},
                "flags": {
                    "macro_present": False,
                    "suspicious_auto_exec": False,
                    "has_embedded_objects": False,
                    "has_external_links": False,
                    "is_encrypted": False
                },
                "anomalies": [],
                "analysis_engine": "enhanced"
            }
        },
        "counts": {
            "macros_total": 0,
            "autoexec_macros_total": 0,
            "suspicious_macros_total": 0,
            "embedded_objects_total": 0,
            "external_references_total": 0,
            "strings_total": 0,
            "ioc_urls_total": 0
        },
        "errors": []
    }
    
    try:
        # Check file size
        file_size = Path(file_path).stat().st_size
        if file_size > MAX_INPUT_SIZE:
            result["errors"].append(f"file_too_large: {file_size} bytes")
            return result
        
        # Detect Office document type
        office_type = detect_office_type(file_path)
        result["static"]["office"]["document_type"] = office_type
        
        # Extract macros using oletools
        macros, macro_errors = extract_macros_with_oletools(file_path)
        result["static"]["office"]["macros"] = macros
        result["errors"].extend(macro_errors)
        
        # Update macro counts and flags
        result["counts"]["macros_total"] = len(macros)
        result["counts"]["autoexec_macros_total"] = sum(1 for m in macros if m.get("has_autoexec", False))
        result["counts"]["suspicious_macros_total"] = sum(1 for m in macros if m.get("has_suspicious", False))
        result["static"]["office"]["flags"]["macro_present"] = len(macros) > 0
        result["static"]["office"]["flags"]["suspicious_auto_exec"] = any(m.get("has_autoexec", False) for m in macros)
        
        # Extract embedded objects
        embedded_objects, embed_errors = extract_embedded_objects(file_path)
        result["static"]["office"]["embedded_objects"] = embedded_objects
        result["errors"].extend(embed_errors)
        
        # Update embedded object counts and flags
        result["counts"]["embedded_objects_total"] = len(embedded_objects)
        result["static"]["office"]["flags"]["has_embedded_objects"] = len(embedded_objects) > 0
        
        # Analyze structure based on document type
        if office_type == "ole":
            structure, struct_errors = analyze_ole_structure(file_path)
            result["static"]["office"]["structure"] = structure
            result["errors"].extend(struct_errors)
            
            # Use OLE metadata if available
            if structure.get("metadata"):
                result["static"]["office"]["metadata"] = structure["metadata"]
                
        elif office_type in ["docx", "xlsx", "pptx", "ooxml"]:
            structure, struct_errors = analyze_ooxml_structure(file_path)
            result["static"]["office"]["structure"] = structure
            result["errors"].extend(struct_errors)
            
            # Update external references
            ext_refs = structure.get("external_references", [])
            result["counts"]["external_references_total"] = len(ext_refs)
            result["static"]["office"]["flags"]["has_external_links"] = len(ext_refs) > 0
        
        # Basic string analysis (fallback)
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Extract strings
            ascii_strings = re.findall(rb'[\\x20-\\x7e]{6,}', file_data)
            all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings[:1000]]
            
            # Find URLs
            url_pattern = re.compile(r'https?://[\\w\\-\\./?#%&=:+,@~]+', re.IGNORECASE)
            urls = []
            for s in all_strings:
                urls.extend(url_pattern.findall(s))
            
            # Find suspicious keywords
            suspicious_keywords = [
                'powershell', 'cmd.exe', 'rundll32', 'WScript.Shell',
                'CreateObject', 'Shell', 'URLDownloadToFile'
            ]
            found_keywords = []
            for keyword in suspicious_keywords:
                for s in all_strings:
                    if keyword.lower() in s.lower():
                        found_keywords.append(keyword)
                        break
            
            result["static"]["office"]["strings"] = {
                "total": len(all_strings),
                "ioc_urls": urls[:50],
                "suspicious_keywords": found_keywords,
                "sample_strings": all_strings[:10]
            }
            
            result["counts"]["strings_total"] = len(all_strings)
            result["counts"]["ioc_urls_total"] = len(urls)
            
        except Exception as e:
            result["errors"].append(f"string_analysis_error: {str(e)}")
        
        # Detect anomalies
        anomalies = []
        if result["static"]["office"]["flags"]["suspicious_auto_exec"]:
            anomalies.append("suspicious_autoexec_macros")
        if result["counts"]["embedded_objects_total"] > 10:
            anomalies.append("excessive_embedded_objects")
        if result["counts"]["external_references_total"] > 0:
            anomalies.append("external_references_present")
        if any(m.get("is_obfuscated", False) for m in macros):
            anomalies.append("obfuscated_macros_detected")
        
        result["static"]["office"]["anomalies"] = anomalies
        
        # Add analysis metadata
        result["static"]["office"]["analysis_metadata"] = {
            "analysis_time": round(time.time() - start_time, 2),
            "libraries_used": get_available_libraries(),
            "file_size": file_size,
            "document_type": office_type
        }
        
    except Exception as e:
        result["errors"].append(f"enhanced_office_analysis_error: {str(e)}")
    
    return result

# Test function
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        result = analyze_office_enhanced(sys.argv[1])
        print(json.dumps(result, indent=2))
    else:
        print("Available libraries:", get_available_libraries())