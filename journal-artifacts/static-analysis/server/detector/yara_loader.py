"""
YARA Rule Loader Module

This module provides utilities for discovering, loading, and compiling YARA rules
from multiple directories with category-based organization.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any

# YARA support
try:
    import yara
except ImportError:
    yara = None

# Configure logging
logger = logging.getLogger(__name__)

DEFAULT_YARA_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
}



@dataclass
class YaraConfig:
    """Configuration for YARA rule loading and scanning"""
    
    # Base directories to scan for rules
    rule_directories: List[Path] = field(default_factory=list)
    
    # Categories to enable (empty = all enabled)
    enabled_categories: Set[str] = field(default_factory=set)
    
    # Scanning timeout in seconds
    scan_timeout: float = 1.0
    
    # Compilation timeout in seconds
    compile_timeout: float = 30.0

    # Optional denylist of rule IDs to skip during discovery/compile
    denylist_path: Optional[Path] = None
    
    @classmethod
    def default(cls) -> 'YaraConfig':
        """
        Create default configuration with standard rule directories.
        
        Returns:
            YaraConfig with default settings pointing to yara and yara-new directories
        """
        # Determine base path relative to this module
        base_path = Path(__file__).parent / "rules"
        
        return cls(
            rule_directories=[
                base_path / "yara",
                base_path / "yara-new"
            ],
            enabled_categories=set(),  # Empty = all enabled
            scan_timeout=1.0,
            compile_timeout=30.0,
            denylist_path=base_path / "denylist.txt"
        )


def discover_yara_rules(
    base_dirs: List[Path],
    enabled_categories: Optional[Set[str]] = None,
    denylisted_rule_ids: Optional[Set[str]] = None
) -> Dict[str, str]:
    """
    Recursively discover all .yar files in the given directories.
    
    This function scans the provided base directories and their subdirectories
    to find all YARA rule files (.yar extension). It categorizes rules based on
    their directory structure and filters by enabled categories if specified.
    
    Args:
        base_dirs: List of base directories to scan for YARA rules
        enabled_categories: Set of category names to include. If None or empty,
                          all categories are included.
    
    Returns:
        Dictionary mapping rule identifiers to file paths.
        Format: {"category/filename": "/path/to/file.yar"}
        
        Categories are extracted from directory names:
        - "legacy" for rules in the base yara directory
        - "filetype" for rules in 01_filetype
        - "capability" for rules in 02_capability
        - "family" for rules in 03_family
        - "research" for rules in 99_research
    
    Example:
        >>> base_dirs = [Path("rules/yara"), Path("rules/yara-new")]
        >>> rules = discover_yara_rules(base_dirs)
        >>> print(rules)
        {
            "legacy/office_rules": "/path/to/yara/office_rules.yar",
            "filetype/gen_bad_pdf": "/path/to/yara-new/01_filetype/gen_bad_pdf.yar",
            ...
        }
    """
    rule_files: Dict[str, str] = {}
    
    if enabled_categories is None:
        enabled_categories = set()
    if denylisted_rule_ids is None:
        denylisted_rule_ids = set()
    
    # If no categories specified, enable all
    enable_all = len(enabled_categories) == 0
    
    for base_dir in base_dirs:
        if not base_dir.exists():
            logger.warning(f"YARA rule directory does not exist: {base_dir}")
            continue
        
        if not base_dir.is_dir():
            logger.warning(f"YARA rule path is not a directory: {base_dir}")
            continue
        
        # Recursively find all .yar files
        for yar_file in base_dir.rglob("*.yar"):
            try:
                # Extract category from directory structure
                category = _extract_category(yar_file, base_dir)
                
                # Filter by enabled categories
                if not enable_all and category not in enabled_categories:
                    logger.debug(f"Skipping rule {yar_file.name} (category '{category}' not enabled)")
                    continue
                
                # Create unique identifier: category/filename_without_extension
                rule_id = f"{category}/{yar_file.stem}"
                
                # Handle duplicate rule IDs by appending parent directory
                if rule_id in rule_files:
                    # Add parent directory to make it unique
                    parent_name = yar_file.parent.name
                    rule_id = f"{category}/{parent_name}_{yar_file.stem}"
                
                if rule_id in denylisted_rule_ids:
                    logger.warning(f"Skipping denylisted YARA rule: {rule_id}")
                    continue

                rule_files[rule_id] = str(yar_file.absolute())
                logger.debug(f"Discovered YARA rule: {rule_id} -> {yar_file}")
                
            except Exception as e:
                logger.error(f"Error processing YARA rule file {yar_file}: {e}")
                continue
    
    logger.info(f"Discovered {len(rule_files)} YARA rule files across {len(base_dirs)} directories")
    return rule_files


def _extract_category(rule_path: Path, base_dir: Path) -> str:
    """
    Extract category from rule file path based on directory structure.
    
    Args:
        rule_path: Full path to the YARA rule file
        base_dir: Base directory being scanned
    
    Returns:
        Category string: "legacy", "filetype", "capability", "family", or "research"
    """
    try:
        # Get relative path from base directory
        rel_path = rule_path.relative_to(base_dir)
        
        # Check if file is directly in base directory (legacy rules)
        if len(rel_path.parts) == 1:
            return "legacy"
        
        # Extract first directory component
        first_dir = rel_path.parts[0]
        
        # Map directory names to categories
        category_mapping = {
            "01_filetype": "filetype",
            "02_capability": "capability",
            "03_family": "family",
            "99_research": "research"
        }
        
        # Return mapped category or use directory name as-is
        return category_mapping.get(first_dir, first_dir)
        
    except ValueError:
        # If relative_to fails, rule is not under base_dir
        logger.warning(f"Rule path {rule_path} is not relative to base {base_dir}")
        return "unknown"


def load_yara_denylist(denylist_path: Optional[Path]) -> Set[str]:
    """Load denylisted rule IDs from a text file."""
    if not denylist_path:
        return set()

    try:
        if not denylist_path.exists():
            logger.info(f"YARA denylist not found, continuing without one: {denylist_path}")
            return set()

        rules = {
            line.strip()
            for line in denylist_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        if rules:
            logger.warning(f"Loaded {len(rules)} denylisted YARA rules from {denylist_path}")
        return rules
    except Exception as e:
        logger.warning(f"Failed to load YARA denylist {denylist_path}: {e}")
        return set()


def get_yara_externals_for_path(file_path: Path) -> Dict[str, str]:
    """Build safe YARA external variables for rules that expect path context."""
    suffix = file_path.suffix.lower()
    return {
        "filename": file_path.name,
        "filepath": str(file_path),
        "extension": suffix,
    }


def compile_yara_rules(
    rule_files: Dict[str, str],
    timeout: Optional[float] = None,
    externals: Optional[Dict[str, str]] = None
) -> Tuple[Optional[Any], List[str]]:
    """
    Compile discovered YARA rules into a single rules object.
    
    This function attempts to compile all provided YARA rule files into a single
    compiled rules object. It handles compilation errors gracefully by logging
    failures and continuing with other rules.
    
    Args:
        rule_files: Dictionary mapping rule identifiers to file paths
                   (as returned by discover_yara_rules)
        timeout: Compilation timeout in seconds (currently not enforced by yara-python)
    
    Returns:
        Tuple of (compiled_rules_object, list_of_error_messages)
        - compiled_rules_object: yara.Rules object if successful, None if YARA unavailable
        - list_of_error_messages: List of error strings for failed compilations
    
    Example:
        >>> rule_files = {"legacy/pdf_rules": "/path/to/pdf_rules.yar"}
        >>> rules, errors = compile_yara_rules(rule_files)
        >>> if rules:
        ...     matches = rules.match("/path/to/file.pdf")
    """
    errors: List[str] = []
    externals = externals or DEFAULT_YARA_EXTERNALS
    
    # Check if YARA module is available
    if yara is None:
        error_msg = "YARA module not available (yara-python not installed)"
        logger.error(error_msg)
        errors.append(error_msg)
        return None, errors
    
    if not rule_files:
        error_msg = "No YARA rule files provided for compilation"
        logger.warning(error_msg)
        errors.append(error_msg)
        return None, errors
    
    # Attempt to compile all rules at once
    # Note: yara.compile() will fail if ANY rule has errors, so we need to
    # compile individually and track failures
    compiled_rules = {}
    failed_rules = []
    
    for rule_id, rule_path in rule_files.items():
        try:
            # Compile individual rule file
            rule = yara.compile(filepath=rule_path, externals=externals)
            compiled_rules[rule_id] = rule_path
            logger.debug(f"Successfully compiled YARA rule: {rule_id}")
            
        except yara.SyntaxError as e:
            error_msg = f"Syntax error in {rule_id} ({rule_path}): {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            failed_rules.append(rule_id)
            
        except yara.Error as e:
            error_msg = f"YARA error compiling {rule_id} ({rule_path}): {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            failed_rules.append(rule_id)
            
        except Exception as e:
            error_msg = f"Unexpected error compiling {rule_id} ({rule_path}): {type(e).__name__}: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            failed_rules.append(rule_id)
    
    # If we have any successfully compiled rules, compile them all together
    if compiled_rules:
        try:
            # Compile all successful rules into a single rules object
            rules_object = yara.compile(filepaths=compiled_rules, externals=externals)
            
            success_count = len(compiled_rules)
            failure_count = len(failed_rules)
            total_count = success_count + failure_count
            
            logger.info(
                f"YARA compilation complete: {success_count}/{total_count} rules compiled successfully"
            )
            
            if failed_rules:
                logger.warning(f"Failed to compile {failure_count} rules: {', '.join(failed_rules[:5])}")
                if len(failed_rules) > 5:
                    logger.warning(f"... and {len(failed_rules) - 5} more")
            
            return rules_object, errors
            
        except Exception as e:
            error_msg = f"Failed to compile combined YARA rules: {type(e).__name__}: {e}"
            logger.error(error_msg)
            errors.append(error_msg)
            return None, errors
    else:
        error_msg = "No YARA rules could be compiled successfully"
        logger.error(error_msg)
        errors.append(error_msg)
        return None, errors
