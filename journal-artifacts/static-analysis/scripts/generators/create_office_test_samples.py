#!/usr/bin/env python3
"""
Create test Office documents with macros for testing enhanced Office analysis
"""

import os
import zipfile
import tempfile
from pathlib import Path

def create_docx_with_macro():
    """Create a simple DOCX with VBA macro"""
    # This is a simplified example - real macro creation would require more complex XML
    
    # Basic DOCX structure
    docx_files = {
        '[Content_Types].xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    <Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/>
</Types>''',
        
        '_rels/.rels': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>''',
        
        'word/document.xml': '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>Test document with macro</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>''',
        
        'word/vbaProject.bin': b'VBA_PROJECT_PLACEHOLDER_WITH_MACRO_CODE'
    }
    
    # Create DOCX file
    output_path = Path('test_macro_document.docx')
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in docx_files.items():
            if isinstance(content, str):
                zf.writestr(filename, content.encode('utf-8'))
            else:
                zf.writestr(filename, content)
    
    return output_path

def main():
    """Create test Office documents"""
    print("Creating test Office documents...")
    
    # Create DOCX with macro
    docx_path = create_docx_with_macro()
    print(f"Created: {docx_path}")
    
    print("Test documents created successfully!")
    print("Note: These are minimal test files for structure testing.")
    print("For comprehensive macro testing, use real Office documents with VBA macros.")

if __name__ == "__main__":
    main()