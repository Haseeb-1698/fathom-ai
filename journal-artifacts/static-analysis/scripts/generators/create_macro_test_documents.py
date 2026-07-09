#!/usr/bin/env python3
"""
Create Office documents with VBA macros for testing enhanced Office analysis
This creates realistic test files with various macro patterns
"""

import os
import zipfile
import tempfile
import struct
from pathlib import Path

def create_vba_project_bin():
    """Create a realistic vbaProject.bin with VBA macro code"""
    # This is a simplified VBA project structure
    # Real VBA projects are complex OLE compound documents
    
    # VBA macro code samples
    macro_code_samples = [
        # Autoexec macro
        '''
Sub AutoOpen()
    ' This macro runs automatically when document opens
    MsgBox "Document opened automatically"
    Call SuspiciousFunction
End Sub

Sub Document_Open()
    ' Alternative autoexec method
    Shell "cmd.exe /c echo Hello World", vbHide
End Sub
        ''',
        
        # Suspicious macro with shell commands
        '''
Sub SuspiciousFunction()
    Dim objShell As Object
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -Command Write-Host 'Test'", 0, True
    
    ' URL download simulation
    Dim http As Object
    Set http = CreateObject("MSXML2.XMLHTTP")
    ' This would be suspicious in real malware
End Sub
        ''',
        
        # Obfuscated macro
        '''
Sub ObfuscatedMacro()
    Dim s As String
    s = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108)
    ' This spells "powershell" using Chr() obfuscation
    
    Dim cmd As String
    cmd = "c" & "m" & "d" & ".exe"
    ' String concatenation obfuscation
    
    Shell s & " -Command " & cmd, vbHide
End Sub
        ''',
        
        # Environment variable usage
        '''
Sub EnvironmentMacro()
    Dim tempPath As String
    tempPath = Environ("TEMP")
    
    Dim userProfile As String
    userProfile = Environ("USERPROFILE")
    
    ' Suspicious file operations
    Open tempPath & "\\malicious.bat" For Output As #1
    Print #1, "@echo off"
    Print #1, "echo This is a test batch file"
    Close #1
End Sub
        '''
    ]
    
    # Create a basic VBA project structure
    # This is highly simplified - real VBA projects are complex
    vba_content = b'VBA_PROJECT_HEADER'
    
    # Add macro code as binary data
    for i, macro in enumerate(macro_code_samples):
        module_header = f'MODULE_{i}_HEADER'.encode('utf-8')
        macro_bytes = macro.encode('utf-8')
        vba_content += struct.pack('<I', len(module_header)) + module_header
        vba_content += struct.pack('<I', len(macro_bytes)) + macro_bytes
    
    # Add VBA project footer
    vba_content += b'VBA_PROJECT_FOOTER'
    
    return vba_content

def create_docm_with_macros():
    """Create a Word document with macros (.docm)"""
    
    # DOCM structure (macro-enabled Word document)
    docm_files = {
        '[Content_Types].xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
    <Override PartName="/word/vbaData.xml" ContentType="application/vnd.ms-word.vbaData+xml"/>
</Types>''',
        
        '_rels/.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''',
        
        'word/_rels/document.xml.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>''',
        
        'word/document.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>This document contains VBA macros for testing purposes.</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>Macros include:</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>- AutoOpen (autoexec)</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>- Shell commands</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>- Obfuscated code</w:t>
            </w:r>
        </w:p>
        <w:p>
            <w:r>
                <w:t>- Environment variables</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>''',
        
        'word/vbaData.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<wne:vbaSuppData xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml">
    <wne:docEvents>
        <wne:eventHandler wne:fVirusProt="false" wne:fMacroEnabled="true" wne:name="AutoOpen"/>
        <wne:eventHandler wne:fVirusProt="false" wne:fMacroEnabled="true" wne:name="Document_Open"/>
    </wne:docEvents>
</wne:vbaSuppData>''',
        
        'word/vbaProject.bin': create_vba_project_bin()
    }
    
    # Create DOCM file
    output_path = Path('test_macro_document.docm')
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in docm_files.items():
            if isinstance(content, str):
                zf.writestr(filename, content.encode('utf-8'))
            else:
                zf.writestr(filename, content)
    
    return output_path

def create_xlsm_with_macros():
    """Create an Excel workbook with macros (.xlsm)"""
    
    # XLSM structure (macro-enabled Excel workbook)
    xlsm_files = {
        '[Content_Types].xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
    <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
    <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
    <Override PartName="/xl/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>''',
        
        '_rels/.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>''',
        
        'xl/_rels/workbook.xml.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
    <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>''',
        
        'xl/workbook.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheets>
        <sheet name="Sheet1" sheetId="1" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
    </sheets>
</workbook>''',
        
        'xl/worksheets/sheet1.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>
        <row r="1">
            <c r="A1" t="inlineStr">
                <is><t>Excel Macro Test Document</t></is>
            </c>
        </row>
        <row r="2">
            <c r="A2" t="inlineStr">
                <is><t>Contains VBA macros with:</t></is>
            </c>
        </row>
        <row r="3">
            <c r="A3" t="inlineStr">
                <is><t>- Workbook_Open autoexec</t></is>
            </c>
        </row>
        <row r="4">
            <c r="A4" t="inlineStr">
                <is><t>- Suspicious API calls</t></is>
            </c>
        </row>
    </sheetData>
</worksheet>''',
        
        'xl/vbaProject.bin': create_vba_project_bin()
    }
    
    # Create XLSM file
    output_path = Path('test_macro_workbook.xlsm')
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in xlsm_files.items():
            if isinstance(content, str):
                zf.writestr(filename, content.encode('utf-8'))
            else:
                zf.writestr(filename, content)
    
    return output_path

def create_legacy_doc_with_macros():
    """Create a legacy Word document with macros (.doc)"""
    
    # This creates a minimal OLE compound document structure
    # Real .doc files are much more complex
    
    ole_header = b'\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1'  # OLE signature
    
    # Simplified OLE structure with VBA indicators
    ole_content = ole_header
    ole_content += b'\\x00' * 504  # OLE header padding
    
    # Add VBA project markers that oletools will detect
    vba_markers = [
        b'_VBA_PROJECT',
        b'ThisDocument',
        b'Module1',
        b'AutoOpen',
        b'Document_Open',
        b'Shell',
        b'CreateObject',
        b'WScript.Shell',
        b'powershell',
        b'cmd.exe'
    ]
    
    for marker in vba_markers:
        ole_content += marker + b'\\x00' * (64 - len(marker))
    
    # Add some macro code content
    macro_content = '''
    Sub AutoOpen()
        Shell "cmd.exe /c echo Legacy macro test", vbHide
        CreateObject("WScript.Shell").Run "powershell -Command Write-Host Test"
    End Sub
    
    Sub Document_Open()
        Dim obj As Object
        Set obj = CreateObject("Scripting.FileSystemObject")
    End Sub
    '''.encode('utf-8')
    
    ole_content += macro_content
    ole_content += b'\\x00' * (8192 - (len(ole_content) % 8192))  # Pad to sector boundary
    
    # Create DOC file
    output_path = Path('test_legacy_macro.doc')
    with open(output_path, 'wb') as f:
        f.write(ole_content)
    
    return output_path

def main():
    """Create all test macro documents"""
    print("🔧 Creating Office documents with VBA macros for testing...")
    print("=" * 60)
    
    created_files = []
    
    try:
        # Create DOCM (Word with macros)
        print("📄 Creating Word document with macros (.docm)...")
        docm_path = create_docm_with_macros()
        created_files.append(docm_path)
        print(f"   ✅ Created: {docm_path}")
        
        # Create XLSM (Excel with macros)
        print("📊 Creating Excel workbook with macros (.xlsm)...")
        xlsm_path = create_xlsm_with_macros()
        created_files.append(xlsm_path)
        print(f"   ✅ Created: {xlsm_path}")
        
        # Create legacy DOC (Word legacy with macros)
        print("📜 Creating legacy Word document with macros (.doc)...")
        doc_path = create_legacy_doc_with_macros()
        created_files.append(doc_path)
        print(f"   ✅ Created: {doc_path}")
        
        print(f"\\n🎉 Successfully created {len(created_files)} test documents!")
        print("\\n📋 Test Documents Summary:")
        print("   • test_macro_document.docm - Word with comprehensive VBA macros")
        print("   • test_macro_workbook.xlsm - Excel with VBA macros")
        print("   • test_legacy_macro.doc - Legacy Word with OLE-embedded macros")
        
        print("\\n🔍 Macro Features Included:")
        print("   ✅ Autoexec functions (AutoOpen, Document_Open, Workbook_Open)")
        print("   ✅ Suspicious API calls (Shell, CreateObject, WScript.Shell)")
        print("   ✅ Obfuscated code (Chr() encoding, string concatenation)")
        print("   ✅ Environment variable usage (Environ)")
        print("   ✅ Command execution (cmd.exe, powershell)")
        print("   ✅ File system operations")
        
        print("\\n🧪 Ready for Enhanced Office Analysis Testing!")
        print("   Use these files to test:")
        print("   • Macro extraction and analysis")
        print("   • Autoexec detection")
        print("   • Suspicious pattern identification")
        print("   • Obfuscation detection")
        print("   • Threat intelligence generation")
        
    except Exception as e:
        print(f"❌ Error creating test documents: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    if success:
        print("\\n✅ Macro test document creation completed successfully!")
    else:
        print("\\n❌ Macro test document creation failed!")