***OSV Database Downloader***

A tool to download OSV (Open Source Vulnerabilities) ecosystem data with incremental update support.

## Features

- Downloads complete OSV database for all ecosystems
- Supports incremental updates using `modified_id.csv` files
- Downloads both global and per-ecosystem modified ID files
- Automatic directory creation for organized file storage

## Usage

### Basic Usage (Incremental Mode)
```bash
python osv_database_downloader.py
```

### Force Full Download
```bash
python osv_database_downloader.py --force-full
```

### Debug Mode
```bash
python osv_database_downloader.py --debug
```

### Command Line Options

- `--force-full`: Force download of complete database (ignores timestamps)
- `--incremental`: Perform incremental update only (default behavior)
- `--debug`: Enable debug logging for troubleshooting

## Output Structure

The script creates a `./download/` directory with the following structure:

```
download/
├── osv_ecosystems.txt          # List of all available ecosystems
├── global_modified_id.csv      # Global list of modified vulnerabilities
├── PyPI.zip                    # Complete PyPI vulnerability database
├── npm.zip                     # Complete npm vulnerability database
├── ...                         # Other ecosystem ZIP files
├── PyPI/                       # Per-ecosystem directories
│   └── modified_id.csv         # PyPI-specific modified vulnerabilities
├── npm/
│   └── modified_id.csv         # npm-specific modified vulnerabilities
└── ...
```

## Incremental Updates & Timestamp Tracking

The script implements smart download behavior based on timestamps:

### Timestamp Tracking

- **First Run**: Always performs full download and creates `timestamps.json`
- **Subsequent Runs**: Defaults to incremental mode (downloads only tracking files)
- **Timestamp File**: `./download/timestamps.json` stores last run date and ecosystem list

### Download Behavior

**Incremental Mode (Default):**
- Downloads `modified_id.csv` files for change tracking
- Skips downloading full ZIP files
- Updates timestamp but preserves existing data

**Full Download Mode (`--force-full`):**
- Downloads complete ZIP files for all ecosystems
- Still downloads `modified_id.csv` files for future tracking
- Updates timestamp with current run time

### modified_id.csv Files

The script downloads two types of change tracking files:

1. **Global modified_id.csv**: Contains all modified vulnerabilities across all ecosystems
2. **Per-ecosystem modified_id.csv**: Contains modified vulnerabilities for specific ecosystems

These CSV files contain vulnerability IDs that have been updated, allowing you to identify exactly which vulnerabilities need to be refreshed.