# Install professional PDF analysis libraries
Write-Host "Installing professional PDF analysis libraries..." -ForegroundColor Green
Write-Host ""

Set-Location "File Scan\server"
& ".\\.venv\\Scripts\\Activate.ps1"

Write-Host "Installing PyMuPDF (fitz) - Excellent metadata extraction..." -ForegroundColor Cyan
pip install PyMuPDF

Write-Host ""
Write-Host "Installing peepdf-3 - Security-focused PDF analysis (Kali tool)..." -ForegroundColor Cyan
pip install peepdf-3

Write-Host ""
Write-Host "Installing PyPDF4 - Fallback PDF parser..." -ForegroundColor Cyan
pip install PyPDF4

Write-Host ""
Write-Host "Installing pdfplumber - Advanced text analysis..." -ForegroundColor Cyan
pip install pdfplumber

Write-Host ""
Write-Host "All PDF analysis libraries installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Available libraries:" -ForegroundColor Yellow
Write-Host "- PyMuPDF (fitz): Robust metadata extraction and general analysis" -ForegroundColor White
Write-Host "- peepdf: Security analysis and malware detection (used in Kali Linux)" -ForegroundColor White
Write-Host "- PyPDF4: Reliable fallback parser" -ForegroundColor White
Write-Host "- pdfplumber: Advanced text and layout analysis" -ForegroundColor White
Write-Host ""
Write-Host "Your PDF analysis capabilities are now significantly enhanced!" -ForegroundColor Green

Read-Host "Press Enter to continue"