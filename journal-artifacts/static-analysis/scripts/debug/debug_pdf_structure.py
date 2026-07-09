#!/usr/bin/env python3
"""
Debug PDF structure to understand why JavaScript isn't being detected
"""

import re
from pathlib import Path

def debug_pdf_structure(pdf_path):
    """Debug the structure of a PDF file"""
    
    print(f"\n🔍 Debugging PDF Structure: {pdf_path}")
    
    with open(pdf_path, 'rb') as f:
        data = f.read()
    
    print(f"📊 File size: {len(data)} bytes")
    
    # Look for PDF objects
    obj_pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj")
    objects = obj_pattern.findall(data)
    print(f"📦 Found {len(objects)} PDF objects: {objects}")
    
    # Look for JavaScript keywords
    js_keywords = [b"JavaScript", b"/JS", b"app.alert", b"eval", b"unescape"]
    print(f"\n🔧 JavaScript keyword search:")
    for keyword in js_keywords:
        matches = data.count(keyword)
        if matches > 0:
            print(f"   ✅ '{keyword.decode()}': {matches} occurrences")
            # Show context around matches
            pos = data.find(keyword)
            if pos != -1:
                start = max(0, pos - 50)
                end = min(len(data), pos + len(keyword) + 50)
                context = data[start:end].decode('latin-1', errors='ignore')
                print(f"      Context: ...{context}...")
        else:
            print(f"   ❌ '{keyword.decode()}': not found")
    
    # Look for OpenAction
    if b"OpenAction" in data:
        print(f"\n🚀 OpenAction found!")
        pos = data.find(b"OpenAction")
        start = max(0, pos - 100)
        end = min(len(data), pos + 200)
        context = data[start:end].decode('latin-1', errors='ignore')
        print(f"   Context: ...{context}...")
    
    # Look for Names tree
    if b"Names" in data:
        print(f"\n📛 Names tree found!")
        pos = data.find(b"Names")
        start = max(0, pos - 50)
        end = min(len(data), pos + 150)
        context = data[start:end].decode('latin-1', errors='ignore')
        print(f"   Context: ...{context}...")
    
    # Show raw PDF structure
    print(f"\n📄 Raw PDF content (first 500 chars):")
    print(data[:500].decode('latin-1', errors='ignore'))
    
    print(f"\n📄 Raw PDF content (last 200 chars):")
    print(data[-200:].decode('latin-1', errors='ignore'))

def main():
    """Debug all test PDF files"""
    
    print("🐛 PDF STRUCTURE DEBUG TOOL")
    print("=" * 50)
    
    test_dir = Path("test_samples")
    if not test_dir.exists():
        print("❌ Test samples directory not found.")
        return
    
    test_files = [
        "simple_js_test.pdf",
        "advanced_js_test.pdf", 
        "embedded_files_test.pdf"
    ]
    
    for filename in test_files:
        pdf_path = test_dir / filename
        if pdf_path.exists():
            debug_pdf_structure(pdf_path)
        else:
            print(f"❌ File not found: {pdf_path}")

if __name__ == "__main__":
    main()