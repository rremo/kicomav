<img src="https://raw.githubusercontent.com/hanul93/kicomav-db/master/logo/k2_full_2.png">

# KicomAV v0.41

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-mac-lightgrey.svg)<br>
![Language](https://img.shields.io/badge/Python-V3.10+-brightgreen)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/kicomav?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=PyPI%20downloads)](https://pepy.tech/projects/kicomav)

KicomAV is an open source antivirus engine designed for detecting malware and disinfecting it. This antivirus engine is created and maintained by [Kei Choi](http://www.hanul93.com).

## Features

- **Multi-format scanning**: Files, archives (ZIP, RAR, 7z, CAB, ALZ, EGG, APK, OneNote), and nested containers
- **YARA integration**: Custom YARA rules support for advanced threat detection
- **Intelligent caching**: Dual-cache system with scan mode awareness for consistent, fast rescans
- **Exclusion rules**: Flexible file/directory exclusion with glob patterns
- **Parallel scanning**: Multi-threaded scanning for improved performance
- **Daemon mode**: REST API and clamd-compatible socket protocol
- **Cross-platform**: Windows, Linux, macOS support
- **Library API**: Use as a Python library in your projects
- **PyInstaller support**: Scan PyInstaller executables (Windows PE and Linux ELF)

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Components](#components)
- [Command-Line Usage (k2)](#command-line-usage-k2)
- [Advanced Features](#advanced-features)
  - [Exclusion Rules](#exclusion-rules)
  - [Scan Cache](#scan-cache)
  - [Parallel Scanning](#parallel-scanning)
- [Library Usage](#library-usage)
- [Daemon Mode (k2d & k2c)](#daemon-mode-k2d--k2c)
- [License](#license)
- [Author](#author)

## Requirements

- Python 3.10+
- [rich](https://github.com/Textualize/rich) - Terminal formatting
- [requests](https://github.com/psf/requests) - HTTP library
- [python-dotenv](https://github.com/theskumar/python-dotenv) - Environment variables
- [yara-python](https://github.com/VirusTotal/yara-python) - YARA rules engine
- [py7zr](https://github.com/miurahr/py7zr) - 7z archive support
- [rarfile](https://github.com/markokr/rarfile) - RAR archive support
- [pycabfile](https://github.com/hanul93/pycabfile) - CAB archive support

**Daemon mode dependencies (k2d, k2c):**
- [fastapi](https://github.com/tiangolo/fastapi) - REST API framework
- [uvicorn](https://github.com/encode/uvicorn) - ASGI server
- [python-multipart](https://github.com/andrew-d/python-multipart) - Form data parsing

**Optional dependencies:**
- [pylzma](https://github.com/fancycode/pylzma) - LZMA compression (for NSIS)

## Installation

### Via pip (Recommended)

```bash
pip install kicomav
```

### From source

```bash
git clone https://github.com/hanul93/kicomav.git
cd kicomav
pip install -e .
```

### With daemon support

```bash
pip install kicomav[daemon]
```

## Configuration

KicomAV uses environment variables for configuration. Create a `.env` file in your home directory:

**Windows:**
```
mkdir %USERPROFILE%\.kicomav
copy .env.example %USERPROFILE%\.kicomav\.env
```

**Linux/macOS:**
```bash
mkdir -p ~/.kicomav
cp .env.example ~/.kicomav/.env
```

Then edit `~/.kicomav/.env` to configure:

| Variable | Description | Example |
|----------|-------------|---------|
| `UNRAR_TOOL` | Path to UnRAR executable | `/usr/bin/unrar` or `C:\Program Files\WinRAR\UnRAR.exe` |
| `RAR_TOOL` | Path to RAR executable | `/usr/bin/rar` or `C:\Program Files\WinRAR\Rar.exe` |
| `SYSTEM_RULES_BASE` | System rules path | `/var/lib/kicomav/rules` or `C:\kicomav\rules` |
| `USER_RULES_BASE` | User rules path | `/home/user/kicomav_rules` or `C:\kicomav\user_rules` |

> **Note:** You can also place a `.env` file in the current working directory for project-specific settings (takes priority over global settings).

## Components

KicomAV provides three command-line tools:

| Tool | Description |
|------|-------------|
| **k2** | Main scanner - scan files and directories for malware |
| **k2d** | Daemon server - REST API and socket protocol service |
| **k2c** | Client - communicate with k2d daemon |

### Quick Overview

- **Standalone scanning**: Use `k2` directly for local file scanning
- **Client-server mode**: Run `k2d` as a service, use `k2c` to send scan requests

---

## Command-Line Usage (k2)

```
$ k2 path[s] [options]
```

### Basic Options

| Option | Description |
|--------|-------------|
| `-f, --files` | Scan files (default) |
| `-r, --arc` | Scan archives |
| `-R, --nor` | Do not recurse into folders |
| `-I, --list` | Display all files |
| `-V, --vlist` | Display virus list |
| `-?, --help` | Show help |

### Scan Actions

| Option | Description |
|--------|-------------|
| `-p, --prompt` | Prompt for action |
| `-d, --dis` | Disinfect files |
| `-l, --del` | Delete infected files |
| `--move` | Move infected files to quarantine |
| `--copy` | Copy infected files to quarantine |

### Performance Options

| Option | Description |
|--------|-------------|
| `--parallel` | Enable parallel file scanning |
| `--workers=N` | Number of worker threads (default: CPU count) |
| `--cache` | Enable scan cache (default) |
| `--no-cache` | Disable scan cache |

### Other Options

| Option | Description |
|--------|-------------|
| `-G, --log=FILE` | Create log file |
| `-e, --app` | Append to log file |
| `-F, --infp=PATH` | Set quarantine folder |
| `--password=PWD` | Password for encrypted archives |
| `--no-color` | Disable colored output |
| `--sigtool` | Extract files from archives to output folder |
| `--update` | Update malware signatures |

### Examples

**Update signatures:**
```bash
$ k2 --update
```

**Scan current directory:**
```bash
$ k2 . -I
```

**Scan with archive support:**
```bash
$ k2 /path/to/scan -r -I
```

**Parallel scanning with 8 workers:**
```bash
$ k2 /path/to/scan --parallel --workers=8
```

**Scan and disinfect:**
```bash
$ k2 /path/to/scan -d
```

---

## Advanced Features

### Exclusion Rules

KicomAV supports flexible file exclusion to skip unwanted files during scans.

#### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--exclude=PATTERN` | Exclude files matching glob pattern | `--exclude=*.log` |
| `--exclude-ext=EXT` | Exclude by extension (comma-separated) | `--exclude-ext=log,tmp` |
| `--max-size=SIZE` | Skip files larger than size | `--max-size=100MB` |
| `--ignore-file=FILE` | Load rules from file | `--ignore-file=.kicomav-ignore` |

**Size units:** B, KB, MB, GB

#### Examples

```bash
# Skip log files and files over 50MB
k2 /path/to/scan --exclude-ext=log --max-size=50MB

# Skip multiple patterns
k2 /path/to/scan --exclude=**/node_modules/** --exclude=**/cache/**

# Use an ignore file
k2 /path/to/scan --ignore-file=.kicomav-ignore
```

#### Ignore File Format (.kicomav-ignore)

Create a `.kicomav-ignore` file (similar to `.gitignore`):

```
# Comment lines start with #
*.log                    # Exclude all .log files
*.tmp                    # Exclude all .tmp files
node_modules/            # Exclude node_modules directory
build/                   # Exclude build directory
**/cache/**              # Exclude cache directories anywhere
>100MB                   # Skip files larger than 100MB
```

**Ignore file search order:**
1. Current directory
2. Parent directories (up to root)
3. `~/.kicomav/.kicomav-ignore`

#### Pattern Matching

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `*.log` | `app.log`, `error.log` | `app.txt`, `log.txt` |
| `**/cache/**` | `/project/cache/file.txt` | `/project/cached/file.txt` |
| `node_modules/` | `/project/node_modules/pkg.json` | `/project/my_modules/pkg.json` |
| `file?.txt` | `file1.txt`, `fileA.txt` | `file10.txt`, `file.txt` |

#### Library Usage

```python
from kicomav.kavcore.k2exclude import ExclusionRule, create_exclusion_rule

# Create rule with factory function
rule = create_exclusion_rule(
    patterns=["**/node_modules/**", "**/cache/**"],
    extensions=["log", "tmp", "bak"],
    max_size="100MB"
)

# Check if a file should be excluded
if rule.should_exclude("/path/to/file.log"):
    print("File excluded")
```

---

### Scan Cache

KicomAV supports intelligent caching to skip unchanged files during rescans, significantly improving scan performance.

#### How It Works

- SQLite database stored at `~/.kicomav/cache.db`
- **Dual cache system**: Separate caches for regular files and archives
- Files are skipped if unchanged since last scan
- Cache invalidates when signature version changes
- Configurable expiration period (default: 7 days)

#### Cache Architecture

KicomAV uses a sophisticated dual-cache system:

| Cache Type | Purpose | Key |
|------------|---------|-----|
| **scan_cache** | Regular files | file_path |
| **archive_cache** | Archives (ZIP, RAR, 7z, etc.) | (archive_path, scan_mode) |

**Scan Mode Awareness**: The archive cache tracks whether `-r` (deep archive scan) option was used:
- `-I` and `-r -I` scans maintain separate cache entries
- Switching between scan modes produces consistent results
- Each mode's statistics (Files, Packed, Infected) are preserved independently

#### Archive Cache Features

- **Contents hash**: Archives identified by hash of internal file list
- **Infection tracking**: Cached results include infected file paths with malware names
- **Statistics preservation**: File count, packed count, and scan paths are cached
- **Smart revalidation**: Re-compressed archives with same files remain cache-valid

#### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--cache` | Enable scan cache | Enabled |
| `--no-cache` | Disable scan cache | - |
| `--cache-clear` | Clear all cache entries | - |
| `--cache-stats` | Show cache statistics | - |
| `--cache-expire=DAYS` | Set expiration (0=never) | 7 |

#### Examples

```bash
# Scan with cache (default behavior)
k2 /path/to/scan -r

# Disable cache for fresh scan
k2 /path/to/scan -r --no-cache

# View cache statistics
k2 --cache-stats

# Clear cache
k2 --cache-clear

# Set 30-day cache expiration
k2 /path/to/scan --cache-expire=30
```

#### Cache Statistics Output

```
Scan Cache Statistics
----------------------------------------
Cache path: ~/.kicomav/cache.db
Cache size: 1.2MB
Total entries: 5532 (files: 5432, archives: 100)
Clean files: 5410
Infected files: 22
Clean archives: 95
Infected archives: 5
Expired entries: 128
Expire days: 7
```

#### Cache Invalidation

The cache automatically invalidates when:

1. **File modified**: File size or modification time changed
2. **Signature updated**: Signature version differs from cached version
3. **Cache expired**: Entry older than expiration period
4. **File deleted**: Entry removed during maintenance
5. **Scan mode changed**: Archive scanned with different `-r` option (archive cache only)
6. **Contents changed**: Archive internal file list differs (archive cache only)

#### Performance Impact

Example scan times with caching enabled:

| Scan | Option | Time | Notes |
|------|--------|------|-------|
| First | `-r -I` | ~40s | Full scan, cache populated |
| Second | `-r -I` | ~2s | Cache hit |
| Third | `-I` | ~18s | Different mode, separate cache |
| Fourth | `-I` | ~0s | Cache hit |
| Fifth | `-r -I` | ~2s | Returns to cached `-r` results |

This ensures:
- Rescanning unchanged files/archives is nearly instant
- Different scan modes maintain independent, consistent results
- Infected entries from previous scans are reported from cache

#### Library Usage

```python
from kicomav.kavcore.k2cache import (
    ScanCache, compute_file_hash, compute_contents_hash, create_cache
)

# Create cache with custom expiration
cache = create_cache(expire_days=14)

# Check if file needs scanning
if cache.needs_scan("/path/to/file", signature_version="1.0"):
    file_hash = compute_file_hash("/path/to/file")
    cache.update("/path/to/file", file_hash, "clean", signature_version="1.0")
else:
    result = cache.get_cached_result("/path/to/file", "1.0")
    if result:
        scan_result, malware_name = result
        print(f"Cached result: {scan_result}")

# Archive cache usage
# Create contents hash from archive entries (filename, size, crc)
entries = [("file1.txt", 100, 12345), ("file2.txt", 200, 67890)]
contents_hash = compute_contents_hash(entries)

# opt_arc parameter controls cache separation:
# - opt_arc=False: -I option (partial archive scan)
# - opt_arc=True: -r -I option (full archive scan)
opt_arc = True  # Using -r option

# Check if archive needs scanning
if cache.needs_archive_scan("/path/to/archive.zip", contents_hash, "1.0", opt_arc):
    # Perform archive scan...
    # After scanning, update cache with results
    infected = [{"path": "malware.exe", "malware": "Trojan.Test"}]
    cache.update_archive(
        "/path/to/archive.zip",
        archive_hash="abc123",
        contents_hash=contents_hash,
        scan_result="infected",
        infected_entries=infected,
        signature_version="1.0",
        opt_arc=opt_arc  # Store scan mode
    )
else:
    # Use cached archive result
    result = cache.get_archive_cached_result(
        "/path/to/archive.zip", contents_hash, "1.0", opt_arc
    )
    if result:
        scan_result, infected_entries, total_files, total_packed, scanned_paths = result
        print(f"Archive result: {scan_result}")
        print(f"Files: {total_files}, Packed: {total_packed}")
        for entry in infected_entries:
            print(f"  Infected: {entry['path']} - {entry['malware']}")

# Get statistics
stats = cache.get_stats()
print(f"Total entries: {stats['total_entries']}")
print(f"File entries: {stats['file_entries']}")
print(f"Archive entries: {stats['archive_entries']}")

# Maintenance
cache.prune_expired()   # Remove expired entries
cache.prune_missing()   # Remove entries for deleted files
cache.vacuum()          # Compact database
cache.close()
```

---

### Parallel Scanning

Enable multi-threaded scanning for improved performance on multi-core systems.

```bash
# Auto-detect CPU count
k2 /path/to/scan --parallel

# Specify worker count
k2 /path/to/scan --parallel --workers=8
```

---

## Library Usage

KicomAV can be used as a Python library in your projects.

### Basic Scanning

```python
import kicomav

# Scan a single file
with kicomav.Scanner() as scanner:
    result = scanner.scan_file("/path/to/suspicious_file.exe")
    if result.infected:
        print(f"Malware detected: {result.malware_name}")
    else:
        print("File is clean")
```

### Directory Scanning

```python
import kicomav

# Scan an entire directory
with kicomav.Scanner() as scanner:
    results = scanner.scan_directory("/path/to/folder", recursive=True)

    infected_files = [r for r in results if r.infected]
    print(f"Scanned {len(results)} files, found {len(infected_files)} infected")

    for result in infected_files:
        print(f"  {result.path}: {result.malware_name}")
```

### Updating Signatures

```python
import kicomav

result = kicomav.update()

if result.package_update_available:
    print(f"New version available: {result.latest_version}")

if result.updated_files:
    print(f"Updated {len(result.updated_files)} signature files")
```

### Configuration Access

```python
import kicomav

config = kicomav.get_config()
print(f"System rules path: {config.system_rules_base}")
print(f"User rules path: {config.user_rules_base}")
```

### Suppress Warnings

```python
from kicomav.kavcore.config import suppress_warnings
suppress_warnings(True)

import kicomav  # No configuration warnings
```

### Archive Exploration

KicomAV provides high-level APIs for exploring and extracting archives.

```python
import kicomav

# List archive contents
with kicomav.Scanner() as scanner:
    info, entries = scanner.list_archive("/path/to/archive.zip")
    print(f"Format: {info.format_type}")
    for entry in entries:
        print(f"{'  '*entry.depth}{entry.path}")

# Extract archive to a folder
with kicomav.Scanner() as scanner:
    result = scanner.extract_archive(
        "/path/to/archive.zip",
        "/output/folder"
    )
    print(f"Extracted {result.extracted_count} files")
    print(f"Log file: {result.log_file}")

# Read a single file from archive into memory
with kicomav.Scanner() as scanner:
    data = scanner.read_archive("/path/to/archive.zip", "config.json")
    if data:
        import json
        config = json.loads(data.decode('utf-8'))
```

**Supported Formats:** ZIP, RAR, 7z, CAB, ALZ, EGG, TAR, GZ, BZ2, APK, OneNote, PyInstaller (PE/ELF)

**Exception Handling:**

```python
import kicomav

try:
    with kicomav.Scanner() as scanner:
        result = scanner.extract_archive("/path/to/archive.zip", "/output")
except kicomav.ArchiveNotFoundError:
    print("Archive file not found")
except kicomav.ArchiveFormatError:
    print("Unsupported or corrupted archive format")
except kicomav.ArchivePasswordError:
    print("Archive is password protected")
except kicomav.ArchiveSecurityError:
    print("Security issue detected (e.g., path traversal)")
except kicomav.ArchiveExtractionError as e:
    print(f"Extraction failed: {e}")
```

### Advanced: Direct Engine Access

```python
import kicomav

engine = kicomav.Engine(verbose=True)
engine.set_plugins("/path/to/plugins")

instance = engine.create_instance()
instance.init()

# Get engine information
info = instance.getinfo()
for plugin_info in info:
    print(f"Plugin: {plugin_info.get('title')}")

# Scan with callback
def on_detect(result, filename, malware_name, malware_id):
    print(f"Detected: {malware_name} in {filename}")

instance.scan("/path/to/file.exe", on_detect)
instance.uninit()
```

---

## Daemon Mode (k2d & k2c)

KicomAV can run as a daemon server, providing both REST API and clamd-compatible socket protocol.

### Server (k2d)

```bash
# Start both REST API and Socket server
k2d

# Start REST API only (port 8311)
k2d --http-only

# Start Socket server only (port 3311)
k2d --socket-only

# Generate API key for authentication
k2d --generate-key
```

#### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `K2D_HTTP_HOST` | `127.0.0.1` | HTTP bind address |
| `K2D_HTTP_PORT` | `8311` | HTTP port |
| `K2D_SOCKET_PORT` | `3311` | Socket port |
| `K2D_MAX_UPLOAD_SIZE` | `52428800` | Max upload size (50MB) |
| `K2D_MAX_WORKERS` | CPU count | Max concurrent workers |
| `K2D_API_KEY` | - | API key for authentication |
| `K2D_REQUIRE_AUTH` | `false` | Require authentication |

### Client (k2c)

k2c is a command-line client for communicating with the k2d daemon.

```bash
# Server status
k2c --ping                     # Check server connection
k2c --version                  # Get version info
k2c --stats                    # Get statistics

# Scan files
k2c /path/to/file              # Scan a file
k2c /path/to/folder            # Scan a directory
k2c --stream < suspicious.exe  # Scan from stdin

# Connection options
k2c --host 192.168.1.100       # Connect to remote server
k2c --socket                   # Use socket protocol
k2c --api-key YOUR_KEY         # Authentication

# Cache management
k2c --cache-stats              # View cache statistics
k2c --cache-clear              # Clear cache

# Output options
k2c --json                     # JSON output
k2c -q                         # Only show infected files
```

#### Example

```bash
$ k2c eicar.txt
============================================================
KicomAV Client (k2c) v0.41
============================================================

eicar.txt  infected : EICAR-Test-File (not a virus)

----------------------------------------
Files scanned: 1
Infected: 1
Errors: 0
```

### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ping` | Health check |
| GET | `/version` | Version and signature info |
| GET | `/stats` | Scan statistics |
| POST | `/scan/file` | Scan uploaded file |
| POST | `/scan/path` | Scan local path |
| POST | `/scan/stream` | Scan base64 encoded data |
| POST | `/reload` | Reload signatures |

**Examples:**

```bash
# Health check
curl http://127.0.0.1:8311/ping

# Scan a file
curl -X POST -F "file=@suspicious.exe" http://127.0.0.1:8311/scan/file

# Scan a directory
curl -X POST -H "Content-Type: application/json" \
  -d '{"path": "/path/to/scan", "recursive": true}' \
  http://127.0.0.1:8311/scan/path
```

### Socket Protocol (clamd-compatible)

| Command | Description |
|---------|-------------|
| `PING` | Health check (returns `PONG`) |
| `VERSION` | Get version info |
| `STATS` | Get statistics |
| `SCAN <path>` | Scan a file |
| `CONTSCAN <path>` | Scan directory recursively |
| `INSTREAM` | Scan streamed data |
| `RELOAD` | Reload signatures |

**Example (Python):**

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("127.0.0.1", 3311))

# PING test
sock.send(b"PING\n")
print(sock.recv(1024))  # b'PONG\n'

# Scan a file
sock.send(b"SCAN /path/to/file.exe\n")
print(sock.recv(1024))  # b'/path/to/file.exe: OK\n'

sock.close()
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Kei Choi**

- [http://www.hanul93.com](http://www.hanul93.com)
- [http://twitter.com/hanul93](http://twitter.com/hanul93)
- [http://facebook.com/hanul93](http://facebook.com/hanul93)
- [http://github.com/hanul93](http://github.com/hanul93)
