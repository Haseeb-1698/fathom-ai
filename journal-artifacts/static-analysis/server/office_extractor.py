"""
Office Macro Extractor - Extract and analyze VBA macros from Office documents
Similar to PDF extractor but focused on Office documents and VBA macros
"""

import os
import json
import hashlib
import zipfile
import tempfile
import struct
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Professional Office analysis libraries
try:
    import oletools.olevba as olevba
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    import oletools.oleobj as oleobj
    OLEOBJ_AVAILABLE = True
except ImportError:
    OLEOBJ_AVAILABLE = False

# Configuration
MAX_MACRO_SIZE = 1024 * 1024  # 1MB max per macro
MAX_MACROS_EXTRACT = 50
EXTRACTION_TIMEOUT = 30  # seconds

def extract_vba_from_ooxml(file_path: str, output_dir: str) -> Dict[str, Any]:
    """Extract VBA macros from OOXML files (docx, xlsx, pptx)"""
    
    extraction_results = {
        "macros": [],
        "vba_files": [],
        "extraction_success": False,
        "errors": []
    }
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Look for VBA project files
            vba_files = []
            for file_info in zf.infolist():
                if 'vbaproject.bin' in file_info.filename.lower():
                    vba_files.append(file_info.filename)
            
            extraction_results["vba_files"] = vba_files
            
            # Extract VBA project files
            for vba_file in vba_files:
                try:
                    # Extract the VBA project binary
                    vba_data = zf.read(vba_file)
                    
                    # Save to temporary file for analysis
                    temp_vba_path = os.path.join(output_dir, f"vba_project_{len(extraction_results['macros'])}.bin")
                    with open(temp_vba_path, 'wb') as f:
                        f.write(vba_data)
                    
                    # Try to parse with oletools
                    if OLETOOLS_AVAILABLE:
                        try:
                            # Use VBA_Parser on the extracted VBA project
                            vba_parser = VBA_Parser(temp_vba_path)
                            
                            if vba_parser.detect_vba_macros():
                                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                                    if vba_code and len(vba_code.strip()) > 0:
                                        # Calculate hash
                                        macro_hash = hashlib.sha256(vba_code.encode('utf-8')).hexdigest()
                                        
                                        # Save macro code
                                        macro_filename = f"macro_{len(extraction_results['macros'])}_{vba_filename}.vba"
                                        macro_path = os.path.join(output_dir, macro_filename)
                                        
                                        with open(macro_path, 'w', encoding='utf-8', errors='ignore') as f:
                                            f.write(vba_code)
                                        
                                        # Analyze macro content
                                        macro_info = analyze_macro_content(vba_code, vba_filename)
                                        macro_info.update({
                                            "source_file": vba_file,
                                            "stream_path": stream_path,
                                            "extracted_path": macro_path,
                                            "filename": macro_filename,
                                            "sha256": macro_hash,
                                            "size": len(vba_code),
                                            "extraction_method": "oletools_vba_parser"
                                        })
                                        
                                        extraction_results["macros"].append(macro_info)
                            
                            vba_parser.close()
                            
                        except Exception as e:
                            extraction_results["errors"].append(f"oletools_vba_parsing_error: {str(e)}")
                    
                    # Alternative: Manual VBA project parsing
                    if not extraction_results["macros"]:
                        manual_macros = extract_vba_manual(vba_data, output_dir)
                        extraction_results["macros"].extend(manual_macros)
                    
                except Exception as e:
                    extraction_results["errors"].append(f"vba_extraction_error_{vba_file}: {str(e)}")
            
            if extraction_results["macros"]:
                extraction_results["extraction_success"] = True
                
    except Exception as e:
        extraction_results["errors"].append(f"ooxml_extraction_error: {str(e)}")
    
    return extraction_results

def extract_vba_from_ole(file_path: str, output_dir: str) -> Dict[str, Any]:
    """Extract VBA macros from OLE files (doc, xls, ppt)"""
    
    extraction_results = {
        "macros": [],
        "ole_streams": [],
        "extraction_success": False,
        "errors": []
    }
    
    try:
        # Use oletools for OLE macro extraction
        if OLETOOLS_AVAILABLE:
            vba_parser = VBA_Parser(file_path)
            
            if vba_parser.detect_vba_macros():
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code and len(vba_code.strip()) > 0:
                        # Calculate hash
                        macro_hash = hashlib.sha256(vba_code.encode('utf-8')).hexdigest()
                        
                        # Save macro code
                        macro_filename = f"macro_{len(extraction_results['macros'])}_{vba_filename}.vba"
                        macro_path = os.path.join(output_dir, macro_filename)
                        
                        with open(macro_path, 'w', encoding='utf-8', errors='ignore') as f:
                            f.write(vba_code)
                        
                        # Analyze macro content
                        macro_info = analyze_macro_content(vba_code, vba_filename)
                        macro_info.update({
                            "source_file": filename,
                            "stream_path": stream_path,
                            "extracted_path": macro_path,
                            "filename": macro_filename,
                            "sha256": macro_hash,
                            "size": len(vba_code),
                            "extraction_method": "oletools_ole_parser"
                        })
                        
                        extraction_results["macros"].append(macro_info)
                
                extraction_results["extraction_success"] = len(extraction_results["macros"]) > 0
            
            vba_parser.close()
        
        # Alternative: Manual OLE stream parsing
        if not extraction_results["macros"] and OLEFILE_AVAILABLE:
            manual_macros = extract_ole_streams_manual(file_path, output_dir)
            extraction_results["macros"].extend(manual_macros)
            extraction_results["extraction_success"] = len(extraction_results["macros"]) > 0
            
    except Exception as e:
        extraction_results["errors"].append(f"ole_extraction_error: {str(e)}")
    
    return extraction_results

def extract_vba_manual(vba_data: bytes, output_dir: str) -> List[Dict[str, Any]]:
    """Manual VBA extraction for cases where oletools fails"""
    
    macros = []
    
    try:
        # Look for VBA module signatures
        vba_signatures = [
            b'Attribute VB_Name',
            b'Sub ',
            b'Function ',
            b'Private Sub',
            b'Public Sub',
            b'Private Function',
            b'Public Function'
        ]
        
        # Convert to text for analysis
        try:
            vba_text = vba_data.decode('utf-8', errors='ignore')
        except:
            try:
                vba_text = vba_data.decode('latin-1', errors='ignore')
            except:
                vba_text = str(vba_data)
        
        # Look for VBA code patterns
        if any(sig.decode('utf-8', errors='ignore') in vba_text for sig in vba_signatures):
            # Found potential VBA code
            macro_hash = hashlib.sha256(vba_data).hexdigest()
            
            # Save the extracted content
            macro_filename = f"manual_extracted_macro_{len(macros)}.vba"
            macro_path = os.path.join(output_dir, macro_filename)
            
            with open(macro_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(vba_text)
            
            # Analyze the content
            macro_info = analyze_macro_content(vba_text, "manual_extraction")
            macro_info.update({
                "source_file": "vba_project_manual",
                "stream_path": "manual_extraction",
                "extracted_path": macro_path,
                "filename": macro_filename,
                "sha256": macro_hash,
                "size": len(vba_text),
                "extraction_method": "manual_signature_detection"
            })
            
            macros.append(macro_info)
            
    except Exception as e:
        # Silent failure for manual extraction
        pass
    
    return macros

def extract_ole_streams_manual(file_path: str, output_dir: str) -> List[Dict[str, Any]]:
    """Manual OLE stream extraction"""
    
    macros = []
    
    try:
        if OLEFILE_AVAILABLE and olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            
            # Look for VBA-related streams
            vba_streams = []
            for item in ole.listdir():
                item_path = '/'.join(item)
                if any(vba_keyword in item_path.lower() for vba_keyword in ['vba', 'macro', '_vba_project']):
                    vba_streams.append(item)
            
            # Extract VBA streams
            for stream in vba_streams:
                try:
                    stream_data = ole.openfile(stream).read()
                    
                    # Try to find VBA code in the stream
                    manual_macros = extract_vba_manual(stream_data, output_dir)
                    for macro in manual_macros:
                        macro["source_file"] = '/'.join(stream)
                        macro["extraction_method"] = "manual_ole_stream"
                    
                    macros.extend(manual_macros)
                    
                except Exception:
                    continue
            
            ole.close()
            
    except Exception:
        pass
    
    return macros

def analyze_macro_content(vba_code: str, module_name: str) -> Dict[str, Any]:
    """Analyze VBA macro content for threats and patterns"""
    
    analysis = {
        "module_name": module_name,
        "code_preview": vba_code[:500] if len(vba_code) > 500 else vba_code,
        "code_size": len(vba_code),
        "autoexec_indicators": [],
        "suspicious_indicators": [],
        "obfuscation_indicators": [],
        "network_indicators": [],
        "file_operations": [],
        "registry_operations": [],
        "has_autoexec": False,
        "has_suspicious": False,
        "is_obfuscated": False,
        "threat_score": 0
    }
    
    # Autoexec detection
    autoexec_keywords = [
        'AutoOpen', 'AutoExec', 'Auto_Open', 'Auto_Exec',
        'Document_Open', 'DocumentOpen', 'Workbook_Open',
        'WorkbookOpen', 'Auto_Close', 'Document_Close',
        'PresentationOpen', 'Slide_SelectionChanged'
    ]
    
    for keyword in autoexec_keywords:
        if keyword.lower() in vba_code.lower():
            analysis["autoexec_indicators"].append(keyword)
    
    analysis["has_autoexec"] = len(analysis["autoexec_indicators"]) > 0
    
    # Suspicious API detection
    suspicious_apis = [
        'Shell', 'CreateObject', 'GetObject', 'CallByName',
        'MacScript', 'ExecuteExcel4Macro', 'Application.Run',
        'WScript.Shell', 'cmd.exe', 'powershell', 'rundll32',
        'URLDownloadToFile', 'InternetOpen', 'HttpOpenRequest',
        'WinExec', 'ShellExecute', 'CreateProcess'
    ]
    
    for api in suspicious_apis:
        if api.lower() in vba_code.lower():
            analysis["suspicious_indicators"].append(api)
    
    analysis["has_suspicious"] = len(analysis["suspicious_indicators"]) > 0
    
    # Obfuscation detection
    chr_count = len([m for m in re.finditer(r'Chr\s*\(', vba_code, re.IGNORECASE)])
    if chr_count > 5:
        analysis["obfuscation_indicators"].append(f"chr_encoding_{chr_count}_instances")
    
    concat_count = len([m for m in re.finditer(r'&\s*["\']', vba_code)])
    if concat_count > 10:
        analysis["obfuscation_indicators"].append(f"string_concatenation_{concat_count}_instances")
    
    if 'Environ(' in vba_code:
        analysis["obfuscation_indicators"].append("environment_variables")
    
    analysis["is_obfuscated"] = len(analysis["obfuscation_indicators"]) > 0
    
    # Network indicators
    network_patterns = [
        r'https?://[^\s\'"]+',
        r'ftp://[^\s\'"]+',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    ]
    
    for pattern in network_patterns:
        matches = re.findall(pattern, vba_code, re.IGNORECASE)
        analysis["network_indicators"].extend(matches)
    
    # File operations
    file_ops = ['Open', 'Close', 'Write', 'Print', 'Put', 'Get', 'Kill', 'FileCopy', 'MkDir']
    for op in file_ops:
        if op.lower() in vba_code.lower():
            analysis["file_operations"].append(op)
    
    # Registry operations
    reg_ops = ['RegWrite', 'RegRead', 'RegDelete', 'CreateKey', 'DeleteKey']
    for op in reg_ops:
        if op.lower() in vba_code.lower():
            analysis["registry_operations"].append(op)
    
    # Calculate threat score
    score = 0
    score += len(analysis["autoexec_indicators"]) * 2
    score += len(analysis["suspicious_indicators"]) * 3
    score += len(analysis["obfuscation_indicators"]) * 2
    score += len(analysis["network_indicators"]) * 1
    score += len(analysis["file_operations"]) * 1
    score += len(analysis["registry_operations"]) * 2
    
    analysis["threat_score"] = min(score, 100)  # Cap at 100
    
    return analysis

def extract_office_macros(file_path: str, output_dir: str) -> Dict[str, Any]:
    """
    Main function to extract macros from Office documents
    Supports both OLE (legacy) and OOXML (modern) formats
    """
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize results
    extraction_summary = {
        "extraction_success": False,
        "total_macros": 0,
        "autoexec_macros": 0,
        "suspicious_macros": 0,
        "obfuscated_macros": 0,
        "extraction_time": 0,
        "file_size": 0,
        "document_type": "unknown",
        "extraction_methods": [],
        "errors": []
    }
    
    extracted_content = {
        "macros": [],
        "vba_modules": [],
        "ole_streams": []
    }
    
    start_time = datetime.now()
    
    try:
        # Get file info
        file_size = os.path.getsize(file_path)
        extraction_summary["file_size"] = file_size
        
        # Detect document type
        if zipfile.is_zipfile(file_path):
            # OOXML format (docx, xlsx, pptx)
            extraction_summary["document_type"] = "ooxml"
            extraction_summary["extraction_methods"].append("ooxml_zip_extraction")
            
            ooxml_results = extract_vba_from_ooxml(file_path, output_dir)
            extracted_content["macros"].extend(ooxml_results["macros"])
            extracted_content["vba_modules"] = ooxml_results["vba_files"]
            extraction_summary["errors"].extend(ooxml_results["errors"])
            
        elif OLEFILE_AVAILABLE and olefile.isOleFile(file_path):
            # OLE format (doc, xls, ppt)
            extraction_summary["document_type"] = "ole"
            extraction_summary["extraction_methods"].append("ole_compound_document")
            
            ole_results = extract_vba_from_ole(file_path, output_dir)
            extracted_content["macros"].extend(ole_results["macros"])
            extracted_content["ole_streams"] = ole_results["ole_streams"]
            extraction_summary["errors"].extend(ole_results["errors"])
            
        else:
            # Unknown format - try both methods
            extraction_summary["document_type"] = "unknown"
            extraction_summary["extraction_methods"].append("fallback_detection")
            
            # Try OOXML first
            try:
                ooxml_results = extract_vba_from_ooxml(file_path, output_dir)
                if ooxml_results["macros"]:
                    extracted_content["macros"].extend(ooxml_results["macros"])
                    extraction_summary["document_type"] = "ooxml_fallback"
            except:
                pass
            
            # Try OLE if no OOXML macros found
            if not extracted_content["macros"]:
                try:
                    ole_results = extract_vba_from_ole(file_path, output_dir)
                    if ole_results["macros"]:
                        extracted_content["macros"].extend(ole_results["macros"])
                        extraction_summary["document_type"] = "ole_fallback"
                except:
                    pass
        
        # Calculate summary statistics
        extraction_summary["total_macros"] = len(extracted_content["macros"])
        extraction_summary["autoexec_macros"] = sum(1 for m in extracted_content["macros"] if m.get("has_autoexec", False))
        extraction_summary["suspicious_macros"] = sum(1 for m in extracted_content["macros"] if m.get("has_suspicious", False))
        extraction_summary["obfuscated_macros"] = sum(1 for m in extracted_content["macros"] if m.get("is_obfuscated", False))
        
        extraction_summary["extraction_success"] = extraction_summary["total_macros"] > 0
        
        # Calculate extraction time
        end_time = datetime.now()
        extraction_summary["extraction_time"] = (end_time - start_time).total_seconds()
        
    except Exception as e:
        extraction_summary["errors"].append(f"extraction_error: {str(e)}")
    
    return {
        "extraction_summary": extraction_summary,
        "extracted_content": extracted_content,
        "extraction_dir": output_dir
    }

# Test function
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        output_dir = f"extracted_macros_{int(datetime.now().timestamp())}"
        
        print(f"Extracting macros from: {file_path}")
        print(f"Output directory: {output_dir}")
        
        result = extract_office_macros(file_path, output_dir)
        print(json.dumps(result, indent=2, default=str))
    else:
        print("Usage: python office_extractor.py <office_file_path>")