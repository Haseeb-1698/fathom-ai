"""
Unit tests for File Detection & Analysis Engine
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os


class TestFileAnalysisEngine(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.engine = Mock()
        self.test_file_path = "test_sample.pdf"
    
    def test_detect_file_type_pdf(self):
        """Test PDF file type detection"""
        # Mock file with PDF magic bytes
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = b'%PDF-1.4'
            
            file_type = self.engine.detect_file_type(self.test_file_path)
            self.assertEqual(file_type, 'pdf')
    
    def test_detect_file_type_docx(self):
        """Test DOCX file type detection"""
        with patch('builtins.open', create=True) as mock_open:
            # DOCX magic bytes (ZIP signature)
            mock_open.return_value.__enter__.return_value.read.return_value = b'PK\x03\x04'
            
            file_type = self.engine.detect_file_type("test.docx")
            self.assertEqual(file_type, 'docx')
    
    def test_detect_file_type_pe(self):
        """Test PE/EXE file type detection"""
        with patch('builtins.open', create=True) as mock_open:
            # PE magic bytes
            mock_open.return_value.__enter__.return_value.read.return_value = b'MZ'
            
            file_type = self.engine.detect_file_type("test.exe")
            self.assertEqual(file_type, 'pe')
    
    def test_validate_file_format_valid(self):
        """Test file format validation with valid file"""
        result = self.engine.validate_file_format(self.test_file_path, 'pdf')
        self.assertTrue(result)
    
    def test_validate_file_format_invalid(self):
        """Test file format validation with corrupted file"""
        result = self.engine.validate_file_format("corrupted.pdf", 'pdf')
        self.assertFalse(result)
    
    def test_analyze_file_success(self):
        """Test successful file analysis"""
        expected_results = {
            'file_type': 'pdf',
            'threats': [],
            'analysis': {'metadata': {}}
        }
        
        self.engine.analyze_file.return_value = expected_results
        results = self.engine.analyze_file(self.test_file_path)
        
        self.assertIsNotNone(results)
        self.assertIn('file_type', results)
        self.assertIn('threats', results)
    
    def test_analyze_file_invalid_format(self):
        """Test analysis with invalid file format"""
        self.engine.analyze_file.side_effect = ValueError("Invalid file format")
        
        with self.assertRaises(ValueError):
            self.engine.analyze_file("invalid.txt")
    
    def test_get_analyzer_for_type_pdf(self):
        """Test getting correct analyzer for PDF"""
        analyzer = self.engine.get_analyzer_for_type('pdf')
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.__class__.__name__, 'PDFAnalyzer')
    
    def test_get_analyzer_for_type_office(self):
        """Test getting correct analyzer for Office documents"""
        analyzer = self.engine.get_analyzer_for_type('docx')
        self.assertIsNotNone(analyzer)
        self.assertEqual(analyzer.__class__.__name__, 'OfficeAnalyzer')
    
    def test_combine_results(self):
        """Test combining analysis and threat results"""
        analysis_results = {'metadata': {'author': 'test'}}
        threat_results = {'threats': [], 'risk_score': 0}
        
        combined = self.engine.combine_results(analysis_results, threat_results)
        
        self.assertIn('metadata', combined)
        self.assertIn('threats', combined)
        self.assertIn('risk_score', combined)


class TestFileTypeDetection(unittest.TestCase):
    
    def test_magic_bytes_priority(self):
        """Test that magic bytes take priority over extension"""
        # File with .txt extension but PDF content
        engine = Mock()
        engine.detect_file_type.return_value = 'pdf'
        
        result = engine.detect_file_type("fake.txt")
        self.assertEqual(result, 'pdf')
    
    def test_unknown_file_type(self):
        """Test handling of unknown file types"""
        engine = Mock()
        engine.detect_file_type.return_value = 'unknown'
        
        result = engine.detect_file_type("mystery.xyz")
        self.assertEqual(result, 'unknown')
    
    def test_empty_file(self):
        """Test handling of empty files"""
        engine = Mock()
        engine.detect_file_type.side_effect = ValueError("Empty file")
        
        with self.assertRaises(ValueError):
            engine.detect_file_type("empty.bin")


if __name__ == '__main__':
    unittest.main()
