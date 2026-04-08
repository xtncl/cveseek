# cveseek

A fast, keyboard-driven terminal UI for searching and browsing CVE vulnerabilities using the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities).

<!-- TODO: add demo gif -->

## Features

- **Full-text search** against the NVD database
- **Two-pane layout** — CVE list + detailed preview, switchable with arrow keys
- **CPE product filter** with live fuzzy search (`f`)
- **CVSS scoring** with color-coded severity (CRITICAL / HIGH / MEDIUM / LOW)
- **CWE weaknesses**, affected products, references — all in the preview pane
- **Extra columns** (Published, Modified, Status) when preview is hidden
- **Interactive query input** — start without arguments and type your search
- **New search** without restarting the app (`s`)
- Zero external dependencies beyond `cargo`

## Installation

### Pre-built binaries (recommended)

Download the latest binary for your platform from the
[GitHub Releases page](https://github.com/xtncl/cveseek/releases/latest):

| Platform | File |
|----------|------|
| Linux x86_64 (static) | `cveseek-vX.Y.Z-linux-x64.tar.gz` |
| Linux ARM64 (static) | `cveseek-vX.Y.Z-linux-arm64.tar.gz` |
| macOS Intel | `cveseek-vX.Y.Z-macos-x64.tar.gz` |
| macOS Apple Silicon | `cveseek-vX.Y.Z-macos-arm64.tar.gz` |
| Windows x86_64 | `cveseek-vX.Y.Z-windows-x64.exe` |

Each archive contains a single self-contained binary — no runtime dependencies.
SHA-256 checksums are provided alongside every archive.

**Quick install on Linux/macOS:**
```bash
# Replace vX.Y.Z and the target triple with your platform
curl -LO https://github.com/xtncl/cveseek/releases/latest/download/cveseek-v0.1.0-linux-x64.tar.gz
tar xzf cveseek-v0.1.0-linux-x64.tar.gz
sudo mv cveseek /usr/local/bin/
```

### Via cargo

```bash
cargo install cveseek
```

### Build from source

```bash
git clone https://github.com/xtncl/cveseek
cd cveseek
cargo build --release
./target/release/cveseek -q "apache log4j"
```

## Usage

```bash
# Interactive mode (type your query in the TUI)
cveseek

# Direct search
cveseek -q "windows server 2022"

# With NVD API key (higher rate limits — free at https://nvd.nist.gov/developers/request-an-api-key)
cveseek -q "openssl" --key YOUR_API_KEY

# API key via environment variable
export NVD_API_KEY=your-key-here
cveseek -q "nginx"
```

## Key Bindings

### Navigation

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate CVE list |
| `→` | Focus preview pane |
| `←` | Focus back to list |
| `↑` / `↓` (preview focused) | Scroll preview |
| `PgUp` / `PgDn` | Jump 15 entries |
| `g` / `G` | First / last entry |
| `Ctrl+U` / `Ctrl+D` | Scroll preview fast |

### View

| Key | Action |
|-----|--------|
| `Enter` | Toggle preview pane |
| `s` | New search (keeps current results until submitted) |
| `f` | Open CPE product filter |
| `q` / `Esc` | Close active pane / overlay, or quit |
| `Ctrl+C` | Quit |

### CPE Filter (`f`)

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate |
| `PgUp` / `PgDn` | Jump 15 entries |
| `Ctrl+U` / `Ctrl+D` | Jump 8 entries |
| `Space` | Toggle selection (advances cursor) |
| `a` | Select all visible |
| `n` | Deselect all visible |
| `/` | Live search within products |
| `Tab` | Focus confirm button |
| `Enter` | Apply filter |
| `Esc` / `q` / `f` | Close without applying |

## API Key

Without an API key, the NVD API is rate-limited to ~5 requests per 30 seconds. For regular use, get a free key at:

https://nvd.nist.gov/developers/request-an-api-key

Set it via `--key` flag or `$NVD_API_KEY` environment variable.

## License

MIT — see [LICENSE](LICENSE)
