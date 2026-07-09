# Install Office Analysis Libraries for Enhanced Office Analysis
# Run this script to install professional Office document analysis libraries

Write-Host "Installing Office Analysis Libraries..." -ForegroundColor Green

# Navigate to server directory
Set-Location "server"

# Activate virtual environment if it exists
if (Test-Path ".venv") {
    Write-Host "Activating virtual environment..." -ForegroundColor Yellow
    .\.venv\Scripts\Activate.ps1
} else {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
}

# Install Office analysis libraries
Write-Host "Installing oletools (comprehensive Office analysis)..." -ForegroundColor Cyan
pip install oletools

Write-Host "Installing olefile (OLE file parsing)..." -ForegroundColor Cyan
pip install olefile

Write-Host "Installing python-magic (file type detection)..." -ForegroundColor Cyan
pip install python-magic

Write-Host "Installing additional dependencies..." -ForegroundColor Cyan
pip install cryptography
pip install pycryptodome

# Test installations
Write-Host "`nTesting installations..." -ForegroundColor Green

python -c "
import sys
libraries = {}

try:
    import oletools.olevba
    libraries['oletools'] = 'OK'
except ImportError as e:
    libraries['oletools'] = f'FAILED: {e}'

try:
    import olefile
    libraries['olefile'] = 'OK'
except ImportError as e:
    libraries['olefile'] = f'FAILED: {e}'

try:
    import oletools.oleid
    libraries['oleid'] = 'OK'
except ImportError as e:
    libraries['oleid'] = f'FAILED: {e}'

try:
    import oletools.oleobj
    libraries['oleobj'] = 'OK'
except ImportError as e:
    libraries['oleobj'] = f'FAILED: {e}'

print('\\n=== Office Analysis Libraries Status ===')
for lib, status in libraries.items():
    print(f'{lib:15} : {status}')

# Test enhanced office analyzer
try:
    from detector.office_enhanced import get_available_libraries, analyze_office_enhanced
    print('\\n=== Enhanced Office Analyzer Status ===')
    available = get_available_libraries()
    for lib, status in available.items():
        print(f'{lib:15} : {'Available' if status else 'Not Available'}')
    print('\\nEnhanced Office Analyzer: READY')
except Exception as e:
    print(f'\\nEnhanced Office Analyzer: FAILED - {e}')
"

Write-Host "`n=== Installation Complete ===" -ForegroundColor Green
Write-Host "Office analysis libraries have been installed." -ForegroundColor White
Write-Host "You can now analyze Office documents with:" -ForegroundColor White
Write-Host "- Comprehensive macro extraction and analysis" -ForegroundColor Cyan
Write-Host "- Embedded object detection and extraction" -ForegroundColor Cyan
Write-Host "- OLE and OOXML structure analysis" -ForegroundColor Cyan
Write-Host "- Suspicious pattern detection" -ForegroundColor Cyan
Write-Host "- Obfuscation detection" -ForegroundColor Cyan

Write-Host "`nRestart your server to use the enhanced Office analyzer." -ForegroundColor Yellow