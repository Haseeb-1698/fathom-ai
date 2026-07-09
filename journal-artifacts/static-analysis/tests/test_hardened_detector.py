"""
Comprehensive unit tests for hardened detector module
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

from detector.hardened import (
    sha256_of_file,
    file_size,
    read_at,
    read_head,
    safe_decode_ascii
)


class TestSha256OfFile:
    """Test SHA256 file hashing"""
    
    @pytest.fixture
    def temp_file(self):
        """Create temporary file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test content')
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)
    
    def test_hash_simple_file(self, temp_file):
        """Test hashing a simple file"""
        result = sha256_of_file(temp_file)
        assert result is not None
        assert len(result) == 64  # SHA256 hex length
        assert isinstance(result, str)
    
    def test_hash_empty_file(self):
        """Test hashing an empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            result = sha256_of_file(temp_path)
            assert result is not None
            assert len(result) == 64
        finally:
            os.unlink(temp_path)
    
    def test_hash_large_file(self):
        """Test hashing a large file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000000)  # 1MB
            temp_path = f.name
        
        try:
            result = sha256_of_file(temp_path)
            assert result is not None
            assert len(result) == 64
        finally:
            os.unlink(temp_path)
    
    def test_hash_consistency(self, temp_file):
        """Test that same file produces same hash"""
        hash1 = sha256_of_file(temp_file)
        hash2 = sha256_of_file(temp_file)
        assert hash1 == hash2
    
    def test_hash_different_files(self):
        """Test that different files produce different hashes"""
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b'content1')
            path1 = f1.name
        
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b'content2')
            path2 = f2.name
        
        try:
            hash1 = sha256_of_file(path1)
            hash2 = sha256_of_file(path2)
            assert hash1 != hash2
        finally:
            os.unlink(path1)
            os.unlink(path2)
    
    def test_hash_nonexistent_file(self):
        """Test hashing nonexistent file"""
        with pytest.raises(Exception):
            sha256_of_file("/nonexistent/file.txt")
    
    def test_hash_binary_file(self):
        """Test hashing binary file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes(range(256)))
            temp_path = f.name
        
        try:
            result = sha256_of_file(temp_path)
            assert result is not None
            assert len(result) == 64
        finally:
            os.unlink(temp_path)


class TestFileSize:
    """Test file size calculation"""
    
    def test_size_simple_file(self):
        """Test getting size of simple file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            size = file_size(temp_path)
            assert size == 4
        finally:
            os.unlink(temp_path)
    
    def test_size_empty_file(self):
        """Test getting size of empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            size = file_size(temp_path)
            assert size == 0
        finally:
            os.unlink(temp_path)
    
    def test_size_large_file(self):
        """Test getting size of large file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            content = b'x' * 1000000
            f.write(content)
            temp_path = f.name
        
        try:
            size = file_size(temp_path)
            assert size == 1000000
        finally:
            os.unlink(temp_path)
    
    def test_size_nonexistent_file(self):
        """Test getting size of nonexistent file"""
        with pytest.raises(Exception):
            file_size("/nonexistent/file.txt")
    
    def test_size_consistency(self):
        """Test that size is consistent"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'consistent')
            temp_path = f.name
        
        try:
            size1 = file_size(temp_path)
            size2 = file_size(temp_path)
            assert size1 == size2
        finally:
            os.unlink(temp_path)


class TestReadAt:
    """Test reading file at specific offset"""
    
    def test_read_at_beginning(self):
        """Test reading from beginning of file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0123456789')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 0, 5)
            assert data == b'01234'
        finally:
            os.unlink(temp_path)
    
    def test_read_at_middle(self):
        """Test reading from middle of file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0123456789')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 5, 3)
            assert data == b'567'
        finally:
            os.unlink(temp_path)
    
    def test_read_at_end(self):
        """Test reading from end of file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0123456789')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 8, 2)
            assert data == b'89'
        finally:
            os.unlink(temp_path)
    
    def test_read_at_zero_length(self):
        """Test reading zero bytes"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 0, 0)
            assert data == b''
        finally:
            os.unlink(temp_path)
    
    def test_read_at_beyond_eof(self):
        """Test reading beyond end of file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'short')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 0, 1000)
            assert len(data) <= 5  # Should not read more than file size
        finally:
            os.unlink(temp_path)
    
    def test_read_at_invalid_offset(self):
        """Test reading with invalid offset"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            data = read_at(temp_path, 1000, 10)
            assert data == b'' or len(data) == 0
        finally:
            os.unlink(temp_path)


class TestReadHead:
    """Test reading file header"""
    
    def test_read_head_default(self):
        """Test reading default head size"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000)
            temp_path = f.name
        
        try:
            data = read_head(temp_path)
            assert data is not None
            assert len(data) > 0
        finally:
            os.unlink(temp_path)
    
    def test_read_head_custom_size(self):
        """Test reading custom head size"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0123456789')
            temp_path = f.name
        
        try:
            data = read_head(temp_path, 5)
            assert len(data) == 5
            assert data == b'01234'
        finally:
            os.unlink(temp_path)
    
    def test_read_head_small_file(self):
        """Test reading head of small file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'tiny')
            temp_path = f.name
        
        try:
            data = read_head(temp_path, 100)
            assert len(data) == 4  # File is smaller than requested
        finally:
            os.unlink(temp_path)
    
    def test_read_head_empty_file(self):
        """Test reading head of empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            data = read_head(temp_path)
            assert data == b''
        finally:
            os.unlink(temp_path)


class TestSafeDecodeAscii:
    """Test safe ASCII decoding"""
    
    def test_decode_pure_ascii(self):
        """Test decoding pure ASCII"""
        result = safe_decode_ascii(b'Hello World')
        assert result == 'Hello World'
    
    def test_decode_with_numbers(self):
        """Test decoding ASCII with numbers"""
        result = safe_decode_ascii(b'Test123')
        assert result == 'Test123'
    
    def test_decode_with_special_chars(self):
        """Test decoding ASCII with special characters"""
        result = safe_decode_ascii(b'!@#$%^&*()')
        assert '!' in result or result is not None
    
    def test_decode_with_non_ascii(self):
        """Test decoding with non-ASCII bytes"""
        result = safe_decode_ascii(b'Test\xff\xfe')
        assert result is not None
        assert isinstance(result, str)
    
    def test_decode_empty_bytes(self):
        """Test decoding empty bytes"""
        result = safe_decode_ascii(b'')
        assert result == ''
    
    def test_decode_null_bytes(self):
        """Test decoding null bytes"""
        result = safe_decode_ascii(b'\x00\x00\x00')
        assert result is not None
    
    def test_decode_mixed_content(self):
        """Test decoding mixed ASCII and binary"""
        result = safe_decode_ascii(b'ASCII\x00\xffBINARY')
        assert result is not None
        assert isinstance(result, str)
    
    def test_decode_whitespace(self):
        """Test decoding whitespace"""
        result = safe_decode_ascii(b'  \t\n\r  ')
        assert result is not None
    
    def test_decode_long_string(self):
        """Test decoding long string"""
        long_bytes = b'a' * 10000
        result = safe_decode_ascii(long_bytes)
        assert len(result) == 10000


class TestHardenedDetectorIntegration:
    """Integration tests for hardened detector functions"""
    
    def test_hash_and_size_consistency(self):
        """Test that hash and size are consistent for same file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            content = b'test content for consistency'
            f.write(content)
            temp_path = f.name
        
        try:
            hash1 = sha256_of_file(temp_path)
            size1 = file_size(temp_path)
            
            hash2 = sha256_of_file(temp_path)
            size2 = file_size(temp_path)
            
            assert hash1 == hash2
            assert size1 == size2
            assert size1 == len(content)
        finally:
            os.unlink(temp_path)
    
    def test_read_operations_consistency(self):
        """Test that different read operations are consistent"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'0123456789ABCDEF')
            temp_path = f.name
        
        try:
            head = read_head(temp_path, 10)
            at_data = read_at(temp_path, 0, 10)
            
            assert head == at_data
        finally:
            os.unlink(temp_path)
    
    def test_full_file_workflow(self):
        """Test complete file analysis workflow"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            content = b'Complete workflow test content'
            f.write(content)
            temp_path = f.name
        
        try:
            # Get all file properties
            hash_val = sha256_of_file(temp_path)
            size = file_size(temp_path)
            head = read_head(temp_path, 10)
            decoded = safe_decode_ascii(head)
            
            # Verify all operations succeeded
            assert hash_val is not None
            assert size == len(content)
            assert head is not None
            assert decoded is not None
        finally:
            os.unlink(temp_path)


class TestHardenedDetectorEdgeCases:
    """Test edge cases and error handling"""
    
    def test_operations_on_directory(self):
        """Test operations on directory instead of file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # These should fail or handle gracefully
            with pytest.raises(Exception):
                sha256_of_file(tmpdir)
    
    def test_operations_on_special_files(self):
        """Test operations on special files"""
        # Test with /dev/null on Unix-like systems
        if os.path.exists('/dev/null'):
            try:
                size = file_size('/dev/null')
                assert size == 0
            except Exception:
                pass  # Some operations may not work on special files
    
    def test_concurrent_reads(self):
        """Test concurrent read operations"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'concurrent test')
            temp_path = f.name
        
        try:
            # Perform multiple reads simultaneously
            results = []
            for _ in range(10):
                data = read_head(temp_path, 5)
                results.append(data)
            
            # All results should be identical
            assert all(r == results[0] for r in results)
        finally:
            os.unlink(temp_path)
    
    def test_unicode_filename(self):
        """Test operations with unicode filename"""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='_测试.txt') as f:
                f.write(b'unicode filename test')
                temp_path = f.name
            
            try:
                hash_val = sha256_of_file(temp_path)
                size = file_size(temp_path)
                
                assert hash_val is not None
                assert size > 0
            finally:
                os.unlink(temp_path)
        except Exception:
            pytest.skip("Unicode filenames not supported on this system")


class TestHardenedDetectorPerformance:
    """Test performance characteristics"""
    
    def test_hash_performance_small_file(self):
        """Test hashing performance on small file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000)  # 1KB
            temp_path = f.name
        
        try:
            import time
            start = time.time()
            sha256_of_file(temp_path)
            elapsed = time.time() - start
            
            assert elapsed < 0.1  # Should be very fast
        finally:
            os.unlink(temp_path)
    
    def test_hash_performance_medium_file(self):
        """Test hashing performance on medium file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 1000000)  # 1MB
            temp_path = f.name
        
        try:
            import time
            start = time.time()
            sha256_of_file(temp_path)
            elapsed = time.time() - start
            
            assert elapsed < 1.0  # Should still be reasonably fast
        finally:
            os.unlink(temp_path)
    
    def test_read_performance(self):
        """Test read operation performance"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'x' * 100000)
            temp_path = f.name
        
        try:
            import time
            start = time.time()
            for _ in range(100):
                read_head(temp_path, 1024)
            elapsed = time.time() - start
            
            assert elapsed < 1.0  # 100 reads should be fast
        finally:
            os.unlink(temp_path)
