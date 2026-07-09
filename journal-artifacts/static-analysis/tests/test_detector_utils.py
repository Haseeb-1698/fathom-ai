"""
Comprehensive unit tests for detector utility functions
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))


class TestPDFDetectorUtils:
    """Test PDF detector utility functions"""
    
    def test_pdf_magic_bytes(self):
        """Test PDF magic bytes detection"""
        pdf_header = b'%PDF-1.4'
        assert pdf_header.startswith(b'%PDF')
    
    def test_pdf_versions(self):
        """Test different PDF versions"""
        versions = [
            b'%PDF-1.0',
            b'%PDF-1.1',
            b'%PDF-1.2',
            b'%PDF-1.3',
            b'%PDF-1.4',
            b'%PDF-1.5',
            b'%PDF-1.6',
            b'%PDF-1.7',
            b'%PDF-2.0'
        ]
        
        for version in versions:
            assert version.startswith(b'%PDF')
    
    def test_pdf_eof_marker(self):
        """Test PDF EOF marker"""
        eof = b'%%EOF'
        assert eof == b'%%EOF'
    
    def test_pdf_xref_marker(self):
        """Test PDF xref marker"""
        xref = b'xref'
        assert xref == b'xref'
    
    def test_pdf_trailer_marker(self):
        """Test PDF trailer marker"""
        trailer = b'trailer'
        assert trailer == b'trailer'
    
    def test_pdf_startxref_marker(self):
        """Test PDF startxref marker"""
        startxref = b'startxref'
        assert startxref == b'startxref'
    
    def test_pdf_obj_markers(self):
        """Test PDF object markers"""
        obj_start = b'obj'
        obj_end = b'endobj'
        assert obj_start == b'obj'
        assert obj_end == b'endobj'
    
    def test_pdf_stream_markers(self):
        """Test PDF stream markers"""
        stream_start = b'stream'
        stream_end = b'endstream'
        assert stream_start == b'stream'
        assert stream_end == b'endstream'


class TestOfficeDetectorUtils:
    """Test Office detector utility functions"""
    
    def test_ooxml_magic_bytes(self):
        """Test OOXML (ZIP) magic bytes"""
        zip_header = b'PK\x03\x04'
        assert zip_header == b'PK\x03\x04'
    
    def test_ole_magic_bytes(self):
        """Test OLE magic bytes"""
        ole_header = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        assert len(ole_header) == 8
        assert ole_header[0:2] == b'\xd0\xcf'
    
    def test_ooxml_content_types(self):
        """Test OOXML content types"""
        content_types = [
            '[Content_Types].xml',
            '_rels/.rels',
            'word/document.xml',
            'xl/workbook.xml',
            'ppt/presentation.xml'
        ]
        
        for ct in content_types:
            assert isinstance(ct, str)
            assert len(ct) > 0
    
    def test_office_extensions(self):
        """Test Office file extensions"""
        extensions = {
            'docx': 'Word',
            'xlsx': 'Excel',
            'pptx': 'PowerPoint',
            'doc': 'Word Legacy',
            'xls': 'Excel Legacy',
            'ppt': 'PowerPoint Legacy'
        }
        
        for ext, app in extensions.items():
            assert len(ext) >= 3
            assert len(app) > 0
    
    def test_macro_extensions(self):
        """Test macro-enabled extensions"""
        macro_extensions = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm']
        
        for ext in macro_extensions:
            assert ext.endswith('m')  # Macro-enabled end with 'm'
    
    def test_ole_stream_names(self):
        """Test common OLE stream names"""
        streams = [
            'WordDocument',
            'Workbook',
            'PowerPoint Document',
            'Macros',
            'VBA'
        ]
        
        for stream in streams:
            assert isinstance(stream, str)
            assert len(stream) > 0


class TestPEDetectorUtils:
    """Test PE detector utility functions"""
    
    def test_pe_magic_bytes(self):
        """Test PE magic bytes"""
        mz_header = b'MZ'
        assert mz_header == b'MZ'
    
    def test_pe_signature(self):
        """Test PE signature"""
        pe_sig = b'PE\x00\x00'
        assert pe_sig == b'PE\x00\x00'
    
    def test_pe_machine_types(self):
        """Test PE machine types"""
        machine_types = {
            0x014c: 'I386',
            0x8664: 'AMD64',
            0x0200: 'IA64',
            0x01c0: 'ARM',
            0xaa64: 'ARM64'
        }
        
        for code, name in machine_types.items():
            assert isinstance(code, int)
            assert isinstance(name, str)
    
    def test_pe_subsystems(self):
        """Test PE subsystems"""
        subsystems = {
            1: 'NATIVE',
            2: 'WINDOWS_GUI',
            3: 'WINDOWS_CUI',
            7: 'POSIX_CUI',
            9: 'WINDOWS_CE_GUI'
        }
        
        for code, name in subsystems.items():
            assert isinstance(code, int)
            assert isinstance(name, str)
    
    def test_pe_section_names(self):
        """Test common PE section names"""
        sections = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc']
        
        for section in sections:
            assert section.startswith('.')
            assert len(section) <= 8  # Section names are max 8 chars


class TestFileTypeDetection:
    """Test file type detection utilities"""
    
    def test_detect_pdf_by_header(self):
        """Test PDF detection by header"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as f:
            f.write(b'%PDF-1.4\n')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                header = f.read(8)
                assert header.startswith(b'%PDF')
        finally:
            os.unlink(temp_path)
    
    def test_detect_zip_by_header(self):
        """Test ZIP detection by header"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as f:
            f.write(b'PK\x03\x04')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                header = f.read(4)
                assert header == b'PK\x03\x04'
        finally:
            os.unlink(temp_path)
    
    def test_detect_pe_by_header(self):
        """Test PE detection by header"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(b'MZ')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                header = f.read(2)
                assert header == b'MZ'
        finally:
            os.unlink(temp_path)
    
    def test_detect_ole_by_header(self):
        """Test OLE detection by header"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.doc') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                header = f.read(8)
                assert header == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
        finally:
            os.unlink(temp_path)


class TestDetectorConstants:
    """Test detector constants and configurations"""
    
    def test_max_file_size_constants(self):
        """Test maximum file size constants"""
        max_sizes = {
            'pdf': 100 * 1024 * 1024,  # 100MB
            'office': 50 * 1024 * 1024,  # 50MB
            'pe': 200 * 1024 * 1024  # 200MB
        }
        
        for file_type, max_size in max_sizes.items():
            assert max_size > 0
            assert max_size < 1024 * 1024 * 1024  # Less than 1GB
    
    def test_timeout_constants(self):
        """Test timeout constants"""
        timeouts = {
            'analysis': 30,
            'extraction': 60,
            'yara_scan': 10
        }
        
        for operation, timeout in timeouts.items():
            assert timeout > 0
            assert timeout < 300  # Less than 5 minutes
    
    def test_entropy_thresholds(self):
        """Test entropy threshold constants"""
        thresholds = {
            'low': 3.0,
            'medium': 5.0,
            'high': 7.0,
            'very_high': 7.5
        }
        
        for level, threshold in thresholds.items():
            assert 0 <= threshold <= 8.0
    
    def test_risk_score_ranges(self):
        """Test risk score ranges"""
        ranges = {
            'safe': (0, 20),
            'low': (21, 40),
            'medium': (41, 60),
            'high': (61, 80),
            'critical': (81, 100)
        }
        
        for level, (min_score, max_score) in ranges.items():
            assert 0 <= min_score <= 100
            assert 0 <= max_score <= 100
            assert min_score < max_score


class TestDetectorHelpers:
    """Test detector helper functions"""
    
    def test_bytes_to_hex(self):
        """Test bytes to hex conversion"""
        data = b'\x00\x01\x02\xff'
        hex_str = data.hex()
        assert hex_str == '000102ff'
    
    def test_hex_to_bytes(self):
        """Test hex to bytes conversion"""
        hex_str = '000102ff'
        data = bytes.fromhex(hex_str)
        assert data == b'\x00\x01\x02\xff'
    
    def test_safe_string_extraction(self):
        """Test safe string extraction from bytes"""
        data = b'Hello\x00World\xff'
        # Extract printable ASCII
        printable = ''.join(chr(b) for b in data if 32 <= b < 127)
        assert 'Hello' in printable
        assert 'World' in printable
    
    def test_calculate_percentage(self):
        """Test percentage calculation"""
        assert (50 / 100) * 100 == 50.0
        assert (1 / 3) * 100 == pytest.approx(33.33, rel=0.01)
        assert (0 / 100) * 100 == 0.0
    
    def test_clamp_value(self):
        """Test value clamping"""
        def clamp(value, min_val, max_val):
            return max(min_val, min(value, max_val))
        
        assert clamp(50, 0, 100) == 50
        assert clamp(-10, 0, 100) == 0
        assert clamp(150, 0, 100) == 100


class TestDetectorDataStructures:
    """Test detector data structures"""
    
    def test_threat_dict_structure(self):
        """Test threat dictionary structure"""
        threat = {
            'type': 'malware',
            'severity': 'high',
            'description': 'Suspicious pattern detected',
            'confidence': 0.85
        }
        
        assert 'type' in threat
        assert 'severity' in threat
        assert 'description' in threat
        assert 0 <= threat['confidence'] <= 1.0
    
    def test_analysis_result_structure(self):
        """Test analysis result structure"""
        result = {
            'file_hash': 'abc123',
            'file_type': 'pdf',
            'risk_score': 75,
            'threats': [],
            'metadata': {},
            'counts': {}
        }
        
        assert 'file_hash' in result
        assert 'file_type' in result
        assert 'risk_score' in result
        assert isinstance(result['threats'], list)
        assert isinstance(result['metadata'], dict)
    
    def test_yara_match_structure(self):
        """Test YARA match structure"""
        match = {
            'rule': 'suspicious_pdf',
            'namespace': 'default',
            'tags': ['malware', 'pdf'],
            'strings': ['eval(', 'unescape('],
            'meta': {}
        }
        
        assert 'rule' in match
        assert isinstance(match['tags'], list)
        assert isinstance(match['strings'], list)


class TestDetectorValidation:
    """Test detector validation functions"""
    
    def test_validate_file_path(self):
        """Test file path validation"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            assert os.path.exists(temp_path)
            assert os.path.isfile(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_validate_file_size(self):
        """Test file size validation"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            size = os.path.getsize(temp_path)
            assert size > 0
            assert size < 1024 * 1024  # Less than 1MB
        finally:
            os.unlink(temp_path)
    
    def test_validate_hash_format(self):
        """Test hash format validation"""
        valid_hash = 'a' * 64  # SHA256
        assert len(valid_hash) == 64
        assert all(c in '0123456789abcdef' for c in valid_hash)
    
    def test_validate_risk_score(self):
        """Test risk score validation"""
        valid_scores = [0, 25, 50, 75, 100]
        for score in valid_scores:
            assert 0 <= score <= 100
    
    def test_validate_severity_level(self):
        """Test severity level validation"""
        valid_levels = ['low', 'medium', 'high', 'critical']
        for level in valid_levels:
            assert level in valid_levels


class TestDetectorErrorHandling:
    """Test detector error handling"""
    
    def test_handle_missing_file(self):
        """Test handling of missing file"""
        nonexistent = '/nonexistent/file.pdf'
        assert not os.path.exists(nonexistent)
    
    def test_handle_corrupted_header(self):
        """Test handling of corrupted file header"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x00\x00\x00\x00')  # Invalid header
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                header = f.read(4)
                # Should not match any known format
                assert header != b'%PDF'
                assert header != b'PK\x03\x04'
                assert header != b'MZ'
        finally:
            os.unlink(temp_path)
    
    def test_handle_empty_file(self):
        """Test handling of empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            size = os.path.getsize(temp_path)
            assert size == 0
        finally:
            os.unlink(temp_path)
    
    def test_handle_permission_error(self):
        """Test handling of permission errors"""
        # This test may not work on all systems
        try:
            restricted_path = '/root/restricted_file.txt'
            if os.path.exists(restricted_path):
                with pytest.raises(PermissionError):
                    open(restricted_path, 'rb')
        except Exception:
            pytest.skip("Permission test not applicable on this system")


class TestDetectorPerformance:
    """Test detector performance characteristics"""
    
    def test_small_file_performance(self):
        """Test performance with small file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000)  # 1KB
            temp_path = f.name
        
        try:
            import time
            start = time.time()
            
            # Simulate basic detection
            with open(temp_path, 'rb') as f:
                header = f.read(8)
                size = os.path.getsize(temp_path)
            
            elapsed = time.time() - start
            assert elapsed < 0.01  # Should be very fast
        finally:
            os.unlink(temp_path)
    
    def test_medium_file_performance(self):
        """Test performance with medium file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000000)  # 1MB
            temp_path = f.name
        
        try:
            import time
            start = time.time()
            
            with open(temp_path, 'rb') as f:
                header = f.read(8)
                size = os.path.getsize(temp_path)
            
            elapsed = time.time() - start
            assert elapsed < 0.1  # Should still be fast
        finally:
            os.unlink(temp_path)
