"""
Comprehensive unit tests for entropy_utils module
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

from detector.entropy_utils import (
    calculate_shannon_entropy,
    calculate_entropy_from_frequencies,
    is_high_entropy,
    shannon_entropy
)


class TestCalculateShannonEntropy:
    """Test Shannon entropy calculation"""
    
    def test_empty_data(self):
        """Test entropy of empty data"""
        result = calculate_shannon_entropy(b'')
        assert result == 0.0
    
    def test_single_byte(self):
        """Test entropy of single repeated byte"""
        result = calculate_shannon_entropy(b'\x00' * 100)
        assert result == 0.0
    
    def test_two_bytes_equal(self):
        """Test entropy of two equally distributed bytes"""
        data = b'\x00\xFF' * 50
        result = calculate_shannon_entropy(data)
        assert 0.9 < result < 1.1  # Should be close to 1.0
    
    def test_random_data_high_entropy(self):
        """Test entropy of random-like data"""
        # Create data with all byte values
        data = bytes(range(256)) * 10
        result = calculate_shannon_entropy(data)
        assert result > 7.0  # Should be high entropy
    
    def test_text_data_low_entropy(self):
        """Test entropy of text data"""
        data = b'Hello World! ' * 100
        result = calculate_shannon_entropy(data)
        assert result < 5.0  # Text has lower entropy
    
    def test_compressed_data_high_entropy(self):
        """Test entropy of compressed-like data"""
        import random
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(1000)])
        result = calculate_shannon_entropy(data)
        assert result > 6.0
    
    def test_bytearray_input(self):
        """Test with bytearray input"""
        data = bytearray(b'test data')
        result = calculate_shannon_entropy(data)
        assert isinstance(result, float)
        assert result > 0
    
    def test_all_zeros(self):
        """Test entropy of all zeros"""
        result = calculate_shannon_entropy(b'\x00' * 1000)
        assert result == 0.0
    
    def test_all_ones(self):
        """Test entropy of all ones"""
        result = calculate_shannon_entropy(b'\xFF' * 1000)
        assert result == 0.0
    
    def test_alternating_pattern(self):
        """Test entropy of alternating pattern"""
        data = b'\x00\xFF' * 500
        result = calculate_shannon_entropy(data)
        assert 0.9 < result < 1.1
    
    def test_small_data(self):
        """Test entropy of very small data"""
        result = calculate_shannon_entropy(b'ab')
        assert result > 0
    
    def test_large_data(self):
        """Test entropy of large data"""
        data = b'x' * 1000000
        result = calculate_shannon_entropy(data)
        assert result == 0.0


class TestCalculateEntropyFromFrequencies:
    """Test entropy calculation from frequency counts"""
    
    def test_empty_frequencies(self):
        """Test with empty frequency list"""
        result = calculate_entropy_from_frequencies([])
        assert result == 0.0
    
    def test_single_frequency(self):
        """Test with single frequency"""
        result = calculate_entropy_from_frequencies([100])
        assert result == 0.0
    
    def test_equal_frequencies(self):
        """Test with equal frequencies"""
        result = calculate_entropy_from_frequencies([50, 50])
        assert 0.9 < result < 1.1  # Should be 1.0
    
    def test_unequal_frequencies(self):
        """Test with unequal frequencies"""
        result = calculate_entropy_from_frequencies([90, 10])
        assert 0 < result < 1.0
    
    def test_many_equal_frequencies(self):
        """Test with many equal frequencies"""
        result = calculate_entropy_from_frequencies([10] * 256)
        assert result > 7.0  # Should be high
    
    def test_zero_frequencies(self):
        """Test with zero frequencies"""
        result = calculate_entropy_from_frequencies([0, 0, 0])
        assert result == 0.0
    
    def test_mixed_frequencies(self):
        """Test with mixed frequencies including zeros"""
        result = calculate_entropy_from_frequencies([100, 0, 50, 0, 25])
        assert result > 0
    
    def test_large_frequencies(self):
        """Test with large frequency values"""
        result = calculate_entropy_from_frequencies([1000000, 1000000])
        assert 0.9 < result < 1.1


class TestIsHighEntropy:
    """Test high entropy detection"""
    
    def test_low_entropy_data(self):
        """Test low entropy data returns False"""
        data = b'aaaaaaaaaa' * 100
        assert is_high_entropy(data) is False
    
    def test_high_entropy_data(self):
        """Test high entropy data returns True"""
        data = bytes(range(256)) * 10
        assert is_high_entropy(data) is True
    
    def test_custom_threshold_low(self):
        """Test with custom low threshold"""
        data = b'Hello World'
        assert is_high_entropy(data, threshold=2.0) is True
    
    def test_custom_threshold_high(self):
        """Test with custom high threshold"""
        data = bytes(range(256))
        assert is_high_entropy(data, threshold=9.0) is False
    
    def test_empty_data(self):
        """Test empty data"""
        assert is_high_entropy(b'') is False
    
    def test_compressed_like_data(self):
        """Test compressed-like data"""
        import random
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(1000)])
        assert is_high_entropy(data, threshold=7.0) is True
    
    def test_text_data(self):
        """Test text data"""
        data = b'This is normal text data' * 100
        assert is_high_entropy(data, threshold=7.5) is False
    
    def test_boundary_threshold(self):
        """Test at exact threshold boundary"""
        data = b'\x00\xFF' * 500
        entropy = calculate_shannon_entropy(data)
        assert is_high_entropy(data, threshold=entropy) is True
        assert is_high_entropy(data, threshold=entropy + 0.1) is False


class TestBackwardCompatibility:
    """Test backward compatibility aliases"""
    
    def test_shannon_entropy_alias(self):
        """Test shannon_entropy alias works"""
        data = b'test data'
        result1 = shannon_entropy(data)
        result2 = calculate_shannon_entropy(data)
        assert result1 == result2
    
    def test_alias_with_empty_data(self):
        """Test alias with empty data"""
        assert shannon_entropy(b'') == 0.0
    
    def test_alias_with_high_entropy(self):
        """Test alias with high entropy data"""
        data = bytes(range(256))
        result = shannon_entropy(data)
        assert result > 7.0


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_single_byte_value(self):
        """Test with single byte"""
        result = calculate_shannon_entropy(b'a')
        assert result == 0.0
    
    def test_two_different_bytes(self):
        """Test with two different bytes"""
        result = calculate_shannon_entropy(b'ab')
        assert result > 0
    
    def test_very_long_data(self):
        """Test with very long data"""
        data = b'x' * 10000000  # 10MB
        result = calculate_shannon_entropy(data)
        assert result == 0.0
    
    def test_all_byte_values(self):
        """Test with all possible byte values"""
        data = bytes(range(256))
        result = calculate_shannon_entropy(data)
        assert result > 7.9  # Should be close to 8.0
    
    def test_negative_threshold(self):
        """Test is_high_entropy with negative threshold"""
        data = b'test'
        assert is_high_entropy(data, threshold=-1.0) is True
    
    def test_zero_threshold(self):
        """Test is_high_entropy with zero threshold"""
        data = b'a'
        assert is_high_entropy(data, threshold=0.0) is False


class TestEntropyProperties:
    """Test mathematical properties of entropy"""
    
    def test_entropy_non_negative(self):
        """Entropy should always be non-negative"""
        test_cases = [
            b'',
            b'a',
            b'ab',
            b'abc' * 100,
            bytes(range(256))
        ]
        for data in test_cases:
            assert calculate_shannon_entropy(data) >= 0
    
    def test_entropy_bounded(self):
        """Entropy should be bounded by log2(alphabet_size)"""
        # For bytes, max entropy is log2(256) = 8.0
        test_cases = [
            b'test',
            bytes(range(256)),
            b'random data here',
        ]
        for data in test_cases:
            assert calculate_shannon_entropy(data) <= 8.0
    
    def test_uniform_distribution_max_entropy(self):
        """Uniform distribution should have maximum entropy"""
        # Create uniform distribution of all byte values
        data = bytes(range(256)) * 100
        result = calculate_shannon_entropy(data)
        assert result > 7.99  # Very close to 8.0
    
    def test_deterministic_results(self):
        """Same input should always give same output"""
        data = b'test data for determinism'
        result1 = calculate_shannon_entropy(data)
        result2 = calculate_shannon_entropy(data)
        assert result1 == result2
    
    def test_order_independence(self):
        """Entropy should be independent of byte order"""
        data1 = b'abcdefgh'
        data2 = b'hgfedcba'
        # Same bytes, different order = same entropy
        result1 = calculate_shannon_entropy(data1)
        result2 = calculate_shannon_entropy(data2)
        assert result1 == result2


class TestRealWorldScenarios:
    """Test with real-world-like data"""
    
    def test_english_text(self):
        """Test with English text"""
        text = b"The quick brown fox jumps over the lazy dog. " * 100
        result = calculate_shannon_entropy(text)
        assert 3.0 < result < 5.0  # English text has moderate entropy
    
    def test_json_data(self):
        """Test with JSON-like data"""
        json_data = b'{"key": "value", "number": 123}' * 50
        result = calculate_shannon_entropy(json_data)
        assert result < 6.0
    
    def test_binary_executable_like(self):
        """Test with binary executable-like data"""
        # Mix of different byte patterns
        data = b'\x4D\x5A\x90\x00' * 250  # PE header pattern
        result = calculate_shannon_entropy(data)
        assert result < 3.0
    
    def test_encrypted_like_data(self):
        """Test with encrypted-like data"""
        import random
        random.seed(12345)
        data = bytes([random.randint(0, 255) for _ in range(10000)])
        result = calculate_shannon_entropy(data)
        assert result > 7.0  # Encrypted data has high entropy
    
    def test_repeated_pattern(self):
        """Test with repeated pattern"""
        pattern = b'\x00\x01\x02\x03'
        data = pattern * 1000
        result = calculate_shannon_entropy(data)
        assert result < 3.0  # Low entropy due to repetition
    
    def test_html_data(self):
        """Test with HTML-like data"""
        html = b'<html><body><p>Content</p></body></html>' * 100
        result = calculate_shannon_entropy(html)
        assert 3.0 < result < 5.5
    
    def test_base64_encoded(self):
        """Test with base64-like data"""
        # Base64 uses limited character set
        b64_like = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' * 100
        result = calculate_shannon_entropy(b64_like)
        assert 5.0 < result < 7.0
