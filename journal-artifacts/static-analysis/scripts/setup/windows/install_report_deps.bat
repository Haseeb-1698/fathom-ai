@echo off
echo Installing PDF report generation dependencies...
cd "File Scan\server"
.\.venv\Scripts\activate.bat
pip install reportlab>=4.0.0
echo.
echo PDF report generation dependencies installed successfully!
echo You can now generate professional PDF reports from the dashboard.
pause