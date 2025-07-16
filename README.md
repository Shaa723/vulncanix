# Vulncanix - Web Vulnerability Scanner

A fast, concurrent web vulnerability scanner written in Rust that performs directory and file enumeration to discover hidden resources on web applications.

## Installation

### Prerequisites

- Rust (latest stable version)
- Cargo package manager

### Build from Source

```bash
git clone <repository-url>
cd vulncanix
cargo build --release
```

The binary will be available at `target/release/vulncanix`

## Usage

### Basic Usage

```bash
vulncanix -t https://example.com
```

### Advanced Usage

```bash
vulncanix -t https://example.com \
  -w /path/to/wordlist.txt \
  -c 50 \
  -T 15 \
  -e php,html,js \
  -o json \
  --status-codes 200,301,403 \
  --follow-redirects \
  -v
```

## Command Line Options

| Option | Short | Description | Default |
|--------|--------|-------------|---------|
| `--target` | `-t` | Target URL to scan | **Required** |
| `--concurrency` | `-c` | Number of concurrent requests | `10` |
| `--timeout` | `-T` | Request timeout in seconds | `10` |
| `--wordlist` | `-w` | Path to wordlist file or URL | `https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt` |
| `--output` | `-o` | Output format (txt, json) | `txt` |
| `--extensions` | `-e` | File extensions to append (comma-separated) | None |
| `--status-codes` | | Show only specific status codes (comma-separated) | All interesting codes |
| `--hide-status-codes` | | Hide specific status codes (comma-separated) | None |
| `--user-agent` | | Custom User-Agent string | `vulncanix/1.0` |
| `--follow-redirects` | | Follow HTTP redirects | `false` |
| `--verbose` | `-v` | Verbose output | `false` |

## Examples

### Basic Directory Enumeration

```bash
# Scan with default settings
vulncanix -t https://example.com

# Use custom wordlist
vulncanix -t https://example.com -w /usr/share/wordlists/dirb/common.txt
```

### High-Performance Scanning

```bash
# High concurrency scan
vulncanix -t https://example.com -c 100 -T 5

# Fast scan with specific extensions
vulncanix -t https://example.com -c 50 -e php,html,js,txt
```

### Filtered Results

```bash
# Show only successful responses
vulncanix -t https://example.com --status-codes 200,301

# Hide 404 and 403 responses
vulncanix -t https://example.com --hide-status-codes 404,403
```

### Output Options

```bash
# JSON output for automation
vulncanix -t https://example.com -o json > results.json

# Verbose mode for debugging
vulncanix -t https://example.com -v
```

### Using Remote Wordlists

```bash
# Use a wordlist from GitHub
vulncanix -t https://example.com -w https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```

## Understanding Output

### Text Output Format

```
200 https://example.com/admin/ (Size: 1234) [Admin Interface] [HIGH RISK]
403 https://example.com/config.php (Size: 0) [Access Forbidden, Configuration File] [HIGH RISK]
301 https://example.com/backup/ (Size: 0) -> https://example.com/backup [Backup File]
```

### JSON Output Format

```json
{
  "url": "https://example.com/admin/",
  "status_code": 200,
  "content_length": 1234,
  "response_time": 245,
  "server": "nginx/1.18.0",
  "location": null,
  "content_type": "text/html",
  "indicators": ["Admin Interface"],
  "risk_score": 8
}
```

## Risk Scoring

The scanner automatically calculates risk scores (0-10) based on:

- **Status Code** : 200-299 (5 points), 401 (8 points), 403 (7 points), 500-599 (6 points)
- **Path Content**: Admin/login paths (+3), Config files (+4), Backup files (+2)
- **Risk Levels** : HIGH (8 - 10), MEDIUM (6 - 7), LOW (0 - 5)

## Vulnerability Indicators

The scanner identifies various security indicators:

- **Authentication Required**: 401 responses
- **Access Forbidden**  : 403 responses  
- **Server Error**      : 500-599 responses
- **Admin Interface**   : Paths containing "admin" or "login"
- **Configuration File**: Paths containing "config" or ".env"
- **Backup File**       : Paths containing ".bak", ".backup", ".old", or "~"

## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have explicit permission before scanning any target. The authors are not responsible for any misuse of this tool.
