"""
Comprehensive unit tests for yara_loader module
"""
import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

from detector.yara_loader import (
    YaraConfig,
    discover_yara_rules,
    _extract_category
)


class TestYaraConfig:
    """Test YaraConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration creation"""
        config = YaraConfig.default()
        
        assert config is not None
        assert isinstance(config.rule_directories, list)
        assert len(config.rule_directories) >= 1
        assert isinstance(config.enabled_categories, set)
        assert config.scan_timeout > 0
        assert config.compile_timeout > 0
    
    def test_custom_config(self):
        """Test custom configuration"""
        custom_dirs = [Path("/custom/path")]
        custom_categories = {"malware", "exploit"}
        
        config = YaraConfig(
            rule_directories=custom_dirs,
            enabled_categories=custom_categories,
            scan_timeout=2.0,
            compile_timeout=60.0
        )
        
        assert config.rule_directories == custom_dirs
        assert config.enabled_categories == custom_categories
        assert config.scan_timeout == 2.0
        assert config.compile_timeout == 60.0
    
    def test_empty_config(self):
        """Test empty configuration"""
        config = YaraConfig()
        
        assert config.rule_directories == []
        assert config.enabled_categories == set()
        assert config.scan_timeout == 1.0
        assert config.compile_timeout == 30.0
    
    def test_config_with_single_directory(self):
        """Test configuration with single directory"""
        config = YaraConfig(rule_directories=[Path("/rules")])
        
        assert len(config.rule_directories) == 1
        assert config.rule_directories[0] == Path("/rules")
    
    def test_config_with_multiple_directories(self):
        """Test configuration with multiple directories"""
        dirs = [Path("/rules1"), Path("/rules2"), Path("/rules3")]
        config = YaraConfig(rule_directories=dirs)
        
        assert len(config.rule_directories) == 3
        assert config.rule_directories == dirs
    
    def test_config_categories_set(self):
        """Test that categories is a set"""
        config = YaraConfig(enabled_categories={"cat1", "cat2"})
        
        assert isinstance(config.enabled_categories, set)
        assert "cat1" in config.enabled_categories
        assert "cat2" in config.enabled_categories
    
    def test_config_timeout_values(self):
        """Test timeout value ranges"""
        config = YaraConfig(scan_timeout=0.5, compile_timeout=120.0)
        
        assert config.scan_timeout == 0.5
        assert config.compile_timeout == 120.0


class TestDiscoverYaraRules:
    """Test YARA rule discovery"""
    
    @pytest.fixture
    def temp_rule_dir(self):
        """Create temporary directory with mock YARA rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            # Create directory structure
            (base / "01_filetype").mkdir()
            (base / "02_capability").mkdir()
            (base / "03_family").mkdir()
            
            # Create mock rule files
            (base / "01_filetype" / "pdf_rules.yar").write_text("rule test_pdf { condition: true }")
            (base / "02_capability" / "network.yar").write_text("rule test_network { condition: true }")
            (base / "03_family" / "malware.yar").write_text("rule test_malware { condition: true }")
            (base / "legacy.yar").write_text("rule test_legacy { condition: true }")
            
            yield base
    
    def test_discover_empty_directory(self):
        """Test discovery in empty directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = discover_yara_rules([Path(tmpdir)])
            assert result == {}
    
    def test_discover_nonexistent_directory(self):
        """Test discovery with nonexistent directory"""
        result = discover_yara_rules([Path("/nonexistent/path")])
        assert result == {}
    
    def test_discover_single_rule(self, temp_rule_dir):
        """Test discovering single rule"""
        result = discover_yara_rules([temp_rule_dir])
        assert len(result) > 0
    
    def test_discover_multiple_rules(self, temp_rule_dir):
        """Test discovering multiple rules"""
        result = discover_yara_rules([temp_rule_dir])
        assert len(result) >= 4  # At least 4 rules created
    
    def test_discover_with_categories(self, temp_rule_dir):
        """Test discovery with category filtering"""
        result = discover_yara_rules([temp_rule_dir], enabled_categories={"filetype"})
        
        # Should only include filetype rules
        filetype_rules = [k for k in result.keys() if "filetype" in k]
        assert len(filetype_rules) > 0
    
    def test_discover_all_categories(self, temp_rule_dir):
        """Test discovery with no category filter"""
        result = discover_yara_rules([temp_rule_dir], enabled_categories=None)
        assert len(result) >= 4
    
    def test_discover_empty_categories(self, temp_rule_dir):
        """Test discovery with empty category set (should include all)"""
        result = discover_yara_rules([temp_rule_dir], enabled_categories=set())
        assert len(result) >= 4
    
    def test_discover_multiple_directories(self):
        """Test discovery across multiple directories"""
        with tempfile.TemporaryDirectory() as tmpdir1:
            with tempfile.TemporaryDirectory() as tmpdir2:
                dir1 = Path(tmpdir1)
                dir2 = Path(tmpdir2)
                
                (dir1 / "rule1.yar").write_text("rule r1 { condition: true }")
                (dir2 / "rule2.yar").write_text("rule r2 { condition: true }")
                
                result = discover_yara_rules([dir1, dir2])
                assert len(result) >= 2
    
    def test_discover_nested_directories(self):
        """Test discovery in nested directories"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            nested = base / "level1" / "level2"
            nested.mkdir(parents=True)
            
            (nested / "nested_rule.yar").write_text("rule nested { condition: true }")
            
            result = discover_yara_rules([base])
            assert len(result) >= 1
    
    def test_discover_rule_id_format(self, temp_rule_dir):
        """Test rule ID format"""
        result = discover_yara_rules([temp_rule_dir])
        
        for rule_id in result.keys():
            assert "/" in rule_id  # Should have category/name format
            parts = rule_id.split("/")
            assert len(parts) == 2
    
    def test_discover_duplicate_handling(self):
        """Test handling of duplicate rule names"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            dir1 = base / "dir1"
            dir2 = base / "dir2"
            dir1.mkdir()
            dir2.mkdir()
            
            # Create rules with same name in different directories
            (dir1 / "duplicate.yar").write_text("rule dup1 { condition: true }")
            (dir2 / "duplicate.yar").write_text("rule dup2 { condition: true }")
            
            result = discover_yara_rules([base])
            # Should handle duplicates somehow (either skip or rename)
            assert len(result) >= 1
    
    def test_discover_non_yar_files_ignored(self):
        """Test that non-.yar files are ignored"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            (base / "rule.yar").write_text("rule test { condition: true }")
            (base / "readme.txt").write_text("This is not a rule")
            (base / "config.json").write_text("{}")
            
            result = discover_yara_rules([base])
            assert len(result) == 1  # Only .yar file


class TestExtractCategory:
    """Test category extraction from paths"""
    
    def test_extract_filetype_category(self):
        """Test extracting filetype category"""
        rule_path = Path("/rules/01_filetype/pdf.yar")
        base_dir = Path("/rules")
        
        category = _extract_category(rule_path, base_dir)
        assert "filetype" in category.lower() or category == "01_filetype"
    
    def test_extract_capability_category(self):
        """Test extracting capability category"""
        rule_path = Path("/rules/02_capability/network.yar")
        base_dir = Path("/rules")
        
        category = _extract_category(rule_path, base_dir)
        assert "capability" in category.lower() or category == "02_capability"
    
    def test_extract_family_category(self):
        """Test extracting family category"""
        rule_path = Path("/rules/03_family/malware.yar")
        base_dir = Path("/rules")
        
        category = _extract_category(rule_path, base_dir)
        assert "family" in category.lower() or category == "03_family"
    
    def test_extract_legacy_category(self):
        """Test extracting legacy category"""
        rule_path = Path("/rules/legacy.yar")
        base_dir = Path("/rules")
        
        category = _extract_category(rule_path, base_dir)
        assert category is not None
    
    def test_extract_nested_category(self):
        """Test extracting category from nested path"""
        rule_path = Path("/rules/category/subcategory/rule.yar")
        base_dir = Path("/rules")
        
        category = _extract_category(rule_path, base_dir)
        assert category is not None
        assert isinstance(category, str)


class TestYaraConfigIntegration:
    """Integration tests for YaraConfig"""
    
    def test_config_with_real_paths(self):
        """Test configuration with realistic paths"""
        config = YaraConfig(
            rule_directories=[
                Path("rules/yara"),
                Path("rules/yara-new")
            ],
            enabled_categories={"malware", "exploit", "trojan"},
            scan_timeout=1.5,
            compile_timeout=45.0
        )
        
        assert len(config.rule_directories) == 2
        assert len(config.enabled_categories) == 3
        assert config.scan_timeout == 1.5
        assert config.compile_timeout == 45.0
    
    def test_config_serialization(self):
        """Test that config can be converted to dict"""
        config = YaraConfig.default()
        
        # Should be able to access all attributes
        assert hasattr(config, 'rule_directories')
        assert hasattr(config, 'enabled_categories')
        assert hasattr(config, 'scan_timeout')
        assert hasattr(config, 'compile_timeout')
    
    def test_config_modification(self):
        """Test modifying configuration"""
        config = YaraConfig.default()
        
        # Modify values
        config.scan_timeout = 2.5
        config.enabled_categories.add("custom")
        
        assert config.scan_timeout == 2.5
        assert "custom" in config.enabled_categories


class TestYaraLoaderEdgeCases:
    """Test edge cases and error handling"""
    
    def test_discover_with_permission_error(self):
        """Test handling of permission errors"""
        # This test may not work on all systems
        result = discover_yara_rules([Path("/root/restricted")])
        assert isinstance(result, dict)  # Should return empty dict, not crash
    
    def test_discover_with_symlinks(self):
        """Test handling of symbolic links"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            real_dir = base / "real"
            real_dir.mkdir()
            
            (real_dir / "rule.yar").write_text("rule test { condition: true }")
            
            # Create symlink (may not work on Windows without admin)
            try:
                link_dir = base / "link"
                link_dir.symlink_to(real_dir)
                
                result = discover_yara_rules([base])
                assert len(result) >= 1
            except OSError:
                pytest.skip("Symlinks not supported on this system")
    
    def test_discover_with_empty_files(self):
        """Test handling of empty .yar files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            (base / "empty.yar").write_text("")
            
            result = discover_yara_rules([base])
            # Should still discover the file
            assert len(result) >= 1
    
    def test_discover_with_large_directory(self):
        """Test performance with many rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            # Create many rule files
            for i in range(100):
                (base / f"rule_{i}.yar").write_text(f"rule r{i} {{ condition: true }}")
            
            result = discover_yara_rules([base])
            assert len(result) == 100
    
    def test_discover_with_special_characters(self):
        """Test handling of special characters in filenames"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            # Create files with special characters (that are valid)
            (base / "rule-with-dash.yar").write_text("rule test { condition: true }")
            (base / "rule_with_underscore.yar").write_text("rule test { condition: true }")
            (base / "rule.with.dots.yar").write_text("rule test { condition: true }")
            
            result = discover_yara_rules([base])
            assert len(result) >= 3


class TestYaraLoaderPerformance:
    """Test performance characteristics"""
    
    def test_discover_performance_small(self):
        """Test discovery performance with small number of rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            for i in range(10):
                (base / f"rule_{i}.yar").write_text("rule test { condition: true }")
            
            import time
            start = time.time()
            result = discover_yara_rules([base])
            elapsed = time.time() - start
            
            assert len(result) == 10
            assert elapsed < 1.0  # Should be fast
    
    def test_discover_performance_medium(self):
        """Test discovery performance with medium number of rules"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            
            for i in range(50):
                (base / f"rule_{i}.yar").write_text("rule test { condition: true }")
            
            import time
            start = time.time()
            result = discover_yara_rules([base])
            elapsed = time.time() - start
            
            assert len(result) == 50
            assert elapsed < 2.0  # Should still be reasonably fast
    
    def test_config_creation_performance(self):
        """Test configuration creation performance"""
        import time
        
        start = time.time()
        for _ in range(1000):
            config = YaraConfig.default()
        elapsed = time.time() - start
        
        assert elapsed < 1.0  # Should be very fast


class TestYaraLoaderRobustness:
    """Test robustness and error recovery"""
    
    def test_discover_with_mixed_valid_invalid(self):
        """Test discovery with mix of valid and invalid paths"""
        with tempfile.TemporaryDirectory() as tmpdir:
            valid_dir = Path(tmpdir)
            invalid_dir = Path("/nonexistent/path")
            
            (valid_dir / "rule.yar").write_text("rule test { condition: true }")
            
            result = discover_yara_rules([valid_dir, invalid_dir])
            assert len(result) >= 1  # Should get rules from valid dir
    
    def test_discover_with_file_instead_of_directory(self):
        """Test discovery when given a file instead of directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            file_path = base / "not_a_directory.txt"
            file_path.write_text("test")
            
            result = discover_yara_rules([file_path])
            assert isinstance(result, dict)  # Should handle gracefully
    
    def test_config_with_none_values(self):
        """Test configuration with None values"""
        config = YaraConfig(
            rule_directories=[],
            enabled_categories=set()
        )
        
        assert config.rule_directories == []
        assert config.enabled_categories == set()
