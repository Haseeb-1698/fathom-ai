# Fathom - File Scanning System

A comprehensive file analysis system with advanced malware detection capabilities using YARA rules, static analysis, and behavioral heuristics.

## Features

### Multi-Format Support
- **PDF Files**: Structure analysis, JavaScript detection, encryption detection
- **Office Documents**: OOXML and OLE format support, macro detection, VBA analysis
- **PE/DLL Files**: Header parsing, section analysis, entropy calculation

### Advanced YARA Detection
- **1,378+ YARA Rules**: Comprehensive malware detection across multiple categories
- **Multi-Directory System**: Organized rule sets for different detection types
- **Category-Based Filtering**: Focus on specific threat types
- **Real-Time Scanning**: Pre-compiled rules for fast detection

### Static Analysis
- **PDF Analysis**: Object extraction, stream analysis, metadata parsing
- **Office Analysis**: Relationship mapping, content extraction, macro analysis
- **PE Analysis**: Import/export tables, section characteristics, resource analysis

### Web Interface
- Modern React-based dashboard
- Real-time file upload and analysis
- Interactive visualizations
- Comprehensive reporting

## Quick Start

### Prerequisites

```bash
# Python 3.8+
pip install -r requirements.txt

# YARA (required for malware detection)
pip install yara-python

# Optional: Enhanced analysis libraries
pip install pymupdf pdfminer.six oletools pefile
```

### Running the API Server

```bash
cd "File Scan/server"
uvicorn app:app --reload --port 8000
```

### Running the Dashboard

```bash
cd "File Scan/dashboard"
npm install
npm run dev
```

### Command Line Usage

```bash
# Basic file analysis
python server/detector/hardened.py <file_path>

# With YARA category filtering
python server/detector/hardened.py <file_path> --yara-categories filetype,capability

# Custom timeout
python server/detector/hardened.py <file_path> --yara-timeout 2.0

# Output to JSON
python server/detector/hardened.py <file_path> --out results.json
```

## YARA Integration

The system includes a comprehensive YARA rule set with 1,378+ rules organized into categories:

- **Legacy** (3 rules): Basic detection rules
- **Filetype** (51 rules): File format and type detection
- **Capability** (516 rules): Behavioral and capability detection
- **Family** (403 rules): Malware family identification
- **Research** (405 rules): Experimental and emerging threat detection

For detailed information, see [YARA Integration Guide](docs/guides/YARA_INTEGRATION_GUIDE.md).

### YARA Features

- **Automatic Rule Loading**: Rules are discovered and compiled at startup
- **Category Information**: Each match includes category and source file
- **Performance Optimized**: Pre-compiled rules for fast scanning
- **Error Handling**: Individual rule failures don't prevent other rules from loading
- **Flexible Configuration**: Enable/disable specific categories

### Example YARA Usage

```bash
# Use all rules (default)
python server/detector/hardened.py sample.pdf

# Use only filetype rules
python server/detector/hardened.py sample.pdf --yara-categories filetype

# Legacy single-directory mode
python server/detector/hardened.py sample.pdf --yara-dir server/detector/rules/yara
```

## Project Structure

```
File Scan/
├── server/                         # FastAPI backend and detector engine
├── dashboard/                      # React frontend
├── tests/                          # Maintained pytest suite
├── manual_tests/                   # One-off/manual validation scripts and their assets
├── test_samples/                   # Sample PDFs used for static-analysis testing
├── docs/
│   ├── guides/                     # User-facing analysis guides
│   ├── implementation/             # Project completion and integration notes
│   ├── testing/                    # Coverage and testing summaries
│   └── latex/                      # LaTeX report material
├── scripts/
│   ├── generators/                 # Sample/test-file generation helpers
│   ├── debug/                      # Coverage and debugging helpers
│   └── setup/windows/              # Windows dependency install scripts
└── artifacts/
    ├── coverage/                   # Coverage JSON outputs
    ├── extraction_debug/           # Saved macro/debug extraction outputs
    └── reports/                    # Generated PDF reports
```

## API Endpoints

### POST /api/upload
Upload a file for analysis

**Request**: Multipart form data with file
**Response**: JSON with detection results

```json
{
  "filename": "sample.pdf",
  "sha256": "...",
  "final_guess": {
    "type": "pdf",
    "reasons": ["%PDF- header", "%%EOF in tail"]
  },
  "heuristics": {
    "yara": {
      "matches": [
        {
          "rule": "PDF_With_JavaScript_Strict",
          "category": "filetype",
          "tags": ["pdf", "strong"],
          "meta": {...},
          "source_file": "..."
        }
      ]
    }
  },
  "confidence": 100,
  "confidence_level": "high"
}
```

### GET /api/report/{sha256}
Download PDF report for a scan

## Testing

### Run YARA Integration Tests

```bash
python test_yara_integration_validation.py
```

This validates:
- YARA rule initialization
- Multi-directory loading
- Category information
- Match accuracy

### Run Unit Tests

```bash
pytest tests/
```

## Configuration

### YARA Configuration

Edit `server/detector/yara_loader.py` to customize:

```python
@dataclass
class YaraConfig:
    rule_directories: List[Path]      # Directories to scan
    enabled_categories: Set[str]      # Categories to enable
    scan_timeout: float               # Scan timeout (seconds)
    compile_timeout: float            # Compile timeout (seconds)
```

### API Configuration

Edit `server/app.py` to customize:

```python
MAX_BYTES = 64 * 1024 * 1024  # Maximum file size
```

## Performance

### YARA Performance
- **Initialization**: ~5-10 seconds (one-time at startup)
- **Small Files (<1 MB)**: <100ms per scan
- **Medium Files (1-10 MB)**: 100-500ms per scan
- **Large Files (10-64 MB)**: 500ms-1s per scan

### Memory Usage
- **Base System**: ~100 MB
- **YARA Rules**: ~50-100 MB
- **Per-Scan**: Minimal overhead (rules are reused)

## Troubleshooting

### YARA Rules Not Loading

```bash
# Check YARA installation
python -c "import yara; print(yara.__version__)"

# Verify rule directories exist
ls server/detector/rules/yara
ls server/detector/rules/yara-new
```

### Compilation Errors

Some rules may fail to compile due to missing external modules. This is expected and handled gracefully. Check logs for details.

### API Not Starting

```bash
# Check dependencies
pip install -r requirements.txt

# Check port availability
netstat -an | findstr 8000
```

## Documentation

- [YARA Integration Guide](docs/guides/YARA_INTEGRATION_GUIDE.md) - Comprehensive YARA documentation
- [PDF Static Analysis](server/detector/README_PDF_FULL.md) - PDF analysis details
- [Office Static Analysis](docs/guides/README_OFFICE_STATIC.md) - Office analysis details
- [PE Static Analysis](docs/guides/README_PE_STATIC.md) - PE analysis details

## Development

### Adding New YARA Rules

1. Place `.yar` files in the appropriate category directory
2. Restart the API server
3. Rules are automatically discovered and compiled

### Adding New Detection Features

1. Implement detection logic in `server/detector/`
2. Update `hardened.py` to call new detection
3. Add tests in `tests/`
4. Put one-off/manual validation scripts in `manual_tests/`
5. Update documentation

## License

[Your License Here]

## Contributors

[Your Contributors Here]

## Support

For issues or questions:
1. Check documentation
2. Run validation tests
3. Check logs for errors
4. Open an issue on GitHub

## Version History

### Version 1.0
- Multi-directory YARA integration
- 1,378+ YARA rules
- Category-based organization
- Enhanced match information
- Comprehensive static analysis
- Modern web interface
