@echo off
echo Installing professional PDF analysis libraries...
echo.

cd "File Scan\server"
call .\.venv\Scripts\activate.bat

echo Installing PyMuPDF (fitz) - Excellent metadata extraction...
pip install PyMuPDF

echo.
echo Installing peepdf-3 - Security-focused PDF analysis (Kali tool)...
pip install peepdf-3

echo.
echo Installing PyPDF4 - Fallback PDF parser...
pip install PyPDF4

echo.
echo Installing pdfplumber - Advanced text analysis...
pip install pdfplumber

echo.
echo All PDF analysis libraries installed successfully!
echo.
echo Available libraries:
echo - PyMuPDF (fitz): Robust metadata extraction and general analysis
echo - peepdf: Security analysis and malware detection (used in Kali Linux)
echo - PyPDF4: Reliable fallback parser
echo - pdfplumber: Advanced text and layout analysis
echo.
echo Your PDF analysis capabilities are now significantly enhanced!
pause