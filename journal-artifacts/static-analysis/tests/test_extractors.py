"""
Comprehensive tests for Office and PDF extractors
"""
import pytest
import os
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys

# Add server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

# Import extractors
try:
    from office_extractor import (
        extract_vba_from_ooxml,
        extract_vba_from_ole,
        extract_embedded_objects,
        analyze_macro_content,
        calculate_macro_hash
    )
    OFFICE_EXTRACTOR_AVAILABLE = True
except ImportError:
    OFFICE_EXTRACTOR_AVAILABLE = False

try:
    from pdf_extractor import (
        extract_embedded_files,
        extract_javascript,
        extract_metadata,
        extract_fonts,
        extract_images
    )
    PDF_EXTRACTOR_AVAILABLE = True
except ImportError:
    PDF_EXTRACTOR_AVAILABLE = False


class TestOfficeExtractor:
    """Test Office document extraction functionality"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test outputs"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def mock_docx_file(self, temp_dir):
        """Create a mock DOCX file"""
        file_path = os.path.join(temp_dir, "test.docx")
        # Create minimal valid DOCX structure
        with open(file_path, 'wb') as f:
            f.write(b'PK\x03\x04')  # ZIP signature
        return file_path
    
    def test_calculate_macro_hash(self):
        """Test macro hash calculation"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        test_code = "Sub Test()\nMsgBox \"Hello\"\nEnd Sub"
        hash_result = calculate_macro_hash(test_code)
        
        assert hash_result is not None
        assert len(hash_result) == 64  # SHA256 hash length
        assert isinstance(hash_result, str)
    
    def test_analyze_macro_content_suspicious(self):
        """Test macro content analysis for suspicious patterns"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        suspicious_code = """
        Sub AutoOpen()
            Shell "cmd.exe /c powershell.exe"
            CreateObject("WScript.Shell")
        End Sub
        """
        
        result = analyze_macro_content(suspicious_code)
        
        assert result is not None
        assert 'suspicious_keywords' in result
        assert 'risk_score' in result
        assert result['risk_score'] > 0
    
    def test_analyze_macro_content_clean(self):
        """Test macro content analysis for clean code"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        clean_code = """
        Sub FormatDocument()
            Selection.Font.Bold = True
            Selection.Font.Size = 12
        End Sub
        """
        
        result = analyze_macro_content(clean_code)
        
        assert result is not None
        assert 'suspicious_keywords' in result
        assert 'risk_score' in result
    
    @patch('office_extractor.olevba')
    def test_extract_vba_from_ooxml_success(self, mock_olevba, temp_dir, mock_docx_file):
        """Test successful VBA extraction from OOXML"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        # Mock VBA_Parser
        mock_parser = MagicMock()
        mock_parser.extract_all_macros.return_value = [
            ('vbaProject.bin', 'VBA/Module1', 'Sub Test()\nEnd Sub')
        ]
        mock_olevba.VBA_Parser.return_value = mock_parser
        
        result = extract_vba_from_ooxml(mock_docx_file, temp_dir)
        
        assert result is not None
        assert 'macros' in result
        assert 'extraction_success' in result
    
    @patch('office_extractor.olefile')
    def test_extract_vba_from_ole_success(self, mock_olefile, temp_dir):
        """Test successful VBA extraction from OLE files"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        # Create mock OLE file
        mock_ole = MagicMock()
        mock_ole.exists.return_value = True
        mock_ole.listdir.return_value = [['Macros', 'VBA', 'Module1']]
        mock_olefile.OleFileIO.return_value = mock_ole
        
        test_file = os.path.join(temp_dir, "test.doc")
        with open(test_file, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0')  # OLE signature
        
        result = extract_vba_from_ole(test_file, temp_dir)
        
        assert result is not None
        assert 'macros' in result
    
    def test_extract_embedded_objects_no_objects(self, temp_dir, mock_docx_file):
        """Test embedded object extraction with no objects"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        result = extract_embedded_objects(mock_docx_file, temp_dir)
        
        assert result is not None
        assert 'embedded_objects' in result
        assert isinstance(result['embedded_objects'], list)


class TestPDFExtractor:
    """Test PDF extraction functionality"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test outputs"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def mock_pdf_file(self, temp_dir):
        """Create a mock PDF file"""
        file_path = os.path.join(temp_dir, "test.pdf")
        # Create minimal valid PDF
        pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
"""
        with open(file_path, 'wb') as f:
            f.write(pdf_content)
        return file_path
    
    @patch('pdf_extractor.fitz')
    def test_extract_metadata_success(self, mock_fitz, mock_pdf_file, temp_dir):
        """Test successful metadata extraction"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        # Mock PyMuPDF document
        mock_doc = MagicMock()
        mock_doc.metadata = {
            'title': 'Test Document',
            'author': 'Test Author',
            'creator': 'Test Creator',
            'producer': 'Test Producer'
        }
        mock_fitz.open.return_value = mock_doc
        
        result = extract_metadata(mock_pdf_file, temp_dir)
        
        assert result is not None
        assert 'metadata' in result
        assert result['extraction_success'] is True
    
    @patch('pdf_extractor.fitz')
    def test_extract_javascript_found(self, mock_fitz, mock_pdf_file, temp_dir):
        """Test JavaScript extraction when JS is present"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        # Mock document with JavaScript
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_text.return_value = "app.alert('test');"
        mock_doc.__iter__.return_value = [mock_page]
        mock_doc.page_count = 1
        mock_fitz.open.return_value = mock_doc
        
        result = extract_javascript(mock_pdf_file, temp_dir)
        
        assert result is not None
        assert 'javascript_found' in result
    
    @patch('pdf_extractor.fitz')
    def test_extract_embedded_files_success(self, mock_fitz, mock_pdf_file, temp_dir):
        """Test embedded file extraction"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        # Mock document with embedded files
        mock_doc = MagicMock()
        mock_doc.embfile_count.return_value = 1
        mock_doc.embfile_info.return_value = {
            'name': 'embedded.txt',
            'size': 100
        }
        mock_doc.embfile_get.return_value = b'test content'
        mock_fitz.open.return_value = mock_doc
        
        result = extract_embedded_files(mock_pdf_file, temp_dir)
        
        assert result is not None
        assert 'embedded_files' in result
    
    @patch('pdf_extractor.fitz')
    def test_extract_images_success(self, mock_fitz, mock_pdf_file, temp_dir):
        """Test image extraction from PDF"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        # Mock document with images
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_images.return_value = [(1, 0, 100, 100, 8, 'DeviceRGB', '', 'Im1', 'DCTDecode')]
        mock_doc.__iter__.return_value = [mock_page]
        mock_doc.page_count = 1
        mock_fitz.open.return_value = mock_doc
        
        result = extract_images(mock_pdf_file, temp_dir)
        
        assert result is not None
        assert 'images' in result
    
    @patch('pdf_extractor.fitz')
    def test_extract_fonts_success(self, mock_fitz, mock_pdf_file, temp_dir):
        """Test font extraction from PDF"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        # Mock document with fonts
        mock_doc = MagicMock()
        mock_page = MagicMock()
        mock_page.get_fonts.return_value = [
            (1, 'n/a', 'Arial', 'Type1', 'WinAnsiEncoding')
        ]
        mock_doc.__iter__.return_value = [mock_page]
        mock_doc.page_count = 1
        mock_fitz.open.return_value = mock_doc
        
        result = extract_fonts(mock_pdf_file, temp_dir)
        
        assert result is not None
        assert 'fonts' in result
    
    def test_extract_metadata_invalid_file(self, temp_dir):
        """Test metadata extraction with invalid file"""
        if not PDF_EXTRACTOR_AVAILABLE:
            pytest.skip("PDF extractor not available")
        
        invalid_file = os.path.join(temp_dir, "invalid.pdf")
        with open(invalid_file, 'wb') as f:
            f.write(b'not a pdf')
        
        result = extract_metadata(invalid_file, temp_dir)
        
        assert result is not None
        assert 'errors' in result or result.get('extraction_success') is False


class TestExtractorIntegration:
    """Integration tests for extractors"""
    
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_hash_consistency(self):
        """Test that hash calculation is consistent"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        test_code = "Sub Test()\nEnd Sub"
        hash1 = calculate_macro_hash(test_code)
        hash2 = calculate_macro_hash(test_code)
        
        assert hash1 == hash2
    
    def test_different_content_different_hash(self):
        """Test that different content produces different hashes"""
        if not OFFICE_EXTRACTOR_AVAILABLE:
            pytest.skip("Office extractor not available")
        
        code1 = "Sub Test1()\nEnd Sub"
        code2 = "Sub Test2()\nEnd Sub"
        
        hash1 = calculate_macro_hash(code1)
        hash2 = calculate_macro_hash(code2)
        
        assert hash1 != hash2
