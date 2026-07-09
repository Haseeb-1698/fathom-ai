# YARA Integration Guide

## Overview

The file scanning system now uses a comprehensive multi-directory YARA rule system that provides extensive malware detection capabilities. The system automatically loads rules from multiple directories and organizes them by category.

## Features

### Multi-Directory Rule Loading

The system loads YARA rules from two main directories:
- `server/detector/rules/yara` - Legacy rules (3 files)
- `server/detector/rules/yara-new` - Comprehensive rule set (1,375+ files)

### Rule Categories

Rules are organized into the following categories:

1. **legacy** - Original rules from the `yara` directory
   - Basic PDF, Office, and PE detection rules
   
2. **filetype** (01_filetype) - File type and format detection
   - Webshells, malicious PDFs, Office macros
   - 51 rule files
   
3. **capability** (02_capability) - Behavioral and capability detection
   - Ransomware, exploits, suspicious behaviors
   - 516 rule files
   
4. **family** (03_family) - Malware family identification
   - APT groups, specific malware families
   - 403 rule files
   
5. **research** (99_research) - Research and experimental rules
   - Emerging threats, experimental detection
   - 405 rule files

### Enhanced Match Information

Each YARA match now includes:
- **rule**: The name of the matched rule
- **tags**: Tags associated with the rule (e.g., "suspicious", "strong")
- **meta**: Metadata from the rule (author, description, etc.)
- **category**: The category the rule belongs to (filetype, capability, etc.)
- **source_file**: The full path to the .yar file containing the rule

### Performance

- **Rule Compilation**: Rules are compiled once at startup (takes ~5-10 seconds)
- **Scanning**: Pre-compiled rules are reused for all scans (fast)
- **Timeout Protection**: Configurable timeout prevents hanging scans
- **Error Handling**: Individual rule failures don't prevent other rules from loading

## Usage

### Command Line Interface

#### Basic Usage (Multi-Directory Mode)

```bash
python server/detector/hardened.py <file_path>
```

This automatically loads all rules from both `yara` and `yara-new` directories.

#### Legacy Single-Directory Mode

```bash
python server/detector/hardened.py <file_path> --yara-dir server/detector/rules/yara
```

Use `--yara-dir` to specify a single directory (legacy mode).

#### Category Filtering

```bash
# Load only filetype rules
python server/detector/hardened.py <file_path> --yara-categories filetype

# Load multiple categories
python server/detector/hardened.py <file_path> --yara-categories "filetype,capability"
```

#### Timeout Configuration

```bash
# Set scan timeout to 2 seconds
python server/detector/hardened.py <file_path> --yara-timeout 2.0
```

#### Output to JSON

```bash
python server/detector/hardened.py <file_path> --out results.json
```

### API Usage

The API automatically uses the multi-directory YARA system when the server starts. No configuration changes are needed.

```python
# The API endpoint /api/upload automatically uses the new YARA system
# Results include category information in the response
```

### Programmatic Usage

```python
from pathlib import Path
from detector.hardened import detect_signatures_and_headers

# Scan a file
result = detect_signatures_and_headers(Path("sample.pdf"))

# Access YARA matches
yara_matches = result["heuristics"]["yara"]["matches"]

for match in yara_matches:
    print(f"Rule: {match['rule']}")
    print(f"Category: {match['category']}")
    print(f"Tags: {match['tags']}")
    print(f"Source: {match['source_file']}")
```

## Configuration

### YaraConfig Class

The `YaraConfig` dataclass in `yara_loader.py` provides configuration options:

```python
from detector.yara_loader import YaraConfig

config = YaraConfig(
    rule_directories=[
        Path("rules/yara"),
        Path("rules/yara-new")
    ],
    enabled_categories={"filetype", "capability"},  # Empty set = all enabled
    scan_timeout=1.0,
    compile_timeout=30.0
)
```

### Default Configuration

The default configuration:
- Loads rules from both `yara` and `yara-new` directories
- Enables all categories
- Scan timeout: 1.0 seconds
- Compile timeout: 30.0 seconds

## Output Format

### YARA Match Structure

```json
{
  "heuristics": {
    "yara": {
      "matches": [
        {
          "rule": "PDF_With_JavaScript_Strict",
          "category": "filetype",
          "tags": ["pdf", "strong"],
          "meta": {
            "family": "pdf",
            "behavior": "embedded_js",
            "confidence": "high"
          },
          "source_file": "path/to/01_filetype/pdf_rules.yar"
        }
      ],
      "errors": [],
      "stats": {
        "rules_used": "multi_directory"
      }
    }
  }
}
```

## Performance Characteristics

### Initialization Time

- **First Load**: ~5-10 seconds to compile 1,374 rules
- **Subsequent Scans**: Instant (uses pre-compiled rules)

### Memory Usage

- **Compiled Rules**: ~50-100 MB in memory
- **Per-Scan Overhead**: Minimal (rules are reused)

### Scan Time

- **Small Files (<1 MB)**: <100ms
- **Medium Files (1-10 MB)**: 100-500ms
- **Large Files (10-64 MB)**: 500ms-1s (with timeout protection)

## Troubleshooting

### Rules Not Loading

If you see "YARA loader module not available":
1. Check that `yara_loader.py` exists in `server/detector/`
2. Verify YARA is installed: `pip install yara-python`
3. Check Python path includes the detector directory

### Compilation Errors

Some rules may fail to compile due to missing external modules:
- This is expected and handled gracefully
- Failed rules are logged but don't prevent other rules from loading
- Currently 4 rules fail due to missing `filepath`, `filename`, and `extension` modules

### Timeout Issues

If scans are timing out:
1. Increase timeout: `--yara-timeout 2.0`
2. Reduce rule set: `--yara-categories filetype`
3. Check file size (64 MB limit)

### Legacy Mode Fallback

The system automatically falls back to legacy mode if:
- `yara_loader.py` is not available
- YARA module is not installed
- Multi-directory initialization fails

## Examples

### Example 1: Scan PDF with JavaScript

```bash
python server/detector/hardened.py test_samples/simple_js_test.pdf
```

Expected matches:
- `PDF_Basic_Robust` (legacy, filetype)
- `PDF_Structure_OK` (legacy, filetype)
- `PDF_With_JavaScript_Strict` (legacy, filetype)

### Example 2: Scan with Category Filter

```bash
python server/detector/hardened.py sample.pdf --yara-categories filetype
```

Only loads 51 filetype rules instead of all 1,378 rules.

### Example 3: Legacy Mode

```bash
python server/detector/hardened.py sample.pdf --yara-dir server/detector/rules/yara
```

Uses only the 3 legacy rules from the original directory.

## Validation

Run the validation suite to verify the integration:

```bash
python test_yara_integration_validation.py
```

This tests:
1. YARA initialization
2. PDF with JavaScript detection
3. Clean file handling
4. Category information
5. Stats information

## Rule Management

### Adding New Rules

1. Place `.yar` files in the appropriate category directory:
   - `rules/yara-new/01_filetype/` for file type rules
   - `rules/yara-new/02_capability/` for capability rules
   - `rules/yara-new/03_family/` for family rules
   - `rules/yara-new/99_research/` for research rules

2. Restart the API server or re-run the CLI tool

3. Rules are automatically discovered and compiled

### Disabling Categories

To disable specific categories, use the `--yara-categories` flag with only the categories you want:

```bash
# Enable only filetype and capability
python server/detector/hardened.py file.pdf --yara-categories "filetype,capability"
```

### Rule Syntax

YARA rules must follow standard YARA syntax. See [YARA documentation](https://yara.readthedocs.io/) for details.

## Migration from Legacy System

### Before (Legacy)

```python
# Only loaded rules from single directory
YARA_DIR = Path("rules/yara")
rules = yara.compile(filepaths={...})
```

### After (Multi-Directory)

```python
# Automatically loads from multiple directories
# Rules are pre-compiled at module import
# Category information is included in matches
```

### Backward Compatibility

The `--yara-dir` flag maintains backward compatibility:
- If specified, uses legacy single-directory mode
- If not specified, uses new multi-directory mode

## Best Practices

1. **Use Category Filtering for Performance**: If you only need specific detection types, filter by category
2. **Monitor Compilation Errors**: Check logs for rules that fail to compile
3. **Adjust Timeouts**: Increase timeout for large files or comprehensive rule sets
4. **Regular Updates**: Keep rule sets updated for latest threat detection
5. **Test New Rules**: Validate new rules with test samples before production use

## Technical Details

### Module Structure

```
server/detector/
├── hardened.py          # Main detector with YARA integration
├── yara_loader.py       # Multi-directory rule loader
└── rules/
    ├── yara/            # Legacy rules (3 files)
    └── yara-new/        # Comprehensive rules (1,375+ files)
        ├── 01_filetype/
        ├── 02_capability/
        ├── 03_family/
        └── 99_research/
```

### Initialization Flow

1. Module import triggers `_initialize_yara_rules()`
2. `YaraConfig.default()` creates configuration
3. `discover_yara_rules()` finds all .yar files
4. `compile_yara_rules()` compiles rules with error handling
5. Compiled rules stored in `YARA_COMPILED_RULES` global
6. Rule mapping stored in `YARA_RULE_MAPPING` global

### Scan Flow

1. `detect_signatures_and_headers()` called with file path
2. `yara_scan_file()` uses pre-compiled rules
3. Matches enriched with category and source information
4. Results include stats about rule usage

## Support

For issues or questions:
1. Check this documentation
2. Run validation suite: `python test_yara_integration_validation.py`
3. Check logs for compilation errors
4. Verify YARA installation: `python -c "import yara; print(yara.__version__)"`

## Version History

### Version 1.0 (Current)
- Multi-directory YARA rule loading
- Category-based organization
- Enhanced match information
- Automatic initialization for API
- Category filtering support
- Comprehensive error handling
- Backward compatibility with legacy mode
