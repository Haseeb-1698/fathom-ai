# Install PDF report generation dependencies
Write-Host "Installing PDF report generation dependencies..." -ForegroundColor Green

Set-Location "File Scan\server"

# Activate virtual environment
& ".\\.venv\\Scripts\\Activate.ps1"

# Install reportlab
pip install reportlab>=4.0.0

Write-Host ""
Write-Host "PDF report generation dependencies installed successfully!" -ForegroundColor Green
Write-Host "You can now generate professional PDF reports from the dashboard." -ForegroundColor Cyan

Read-Host "Press Enter to continue"