<p align="center">
<pre>
███████╗███████╗██████╗  ██████╗ ██╗  ██╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗
██╔════╝██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
█████╗  █████╗  ██████╔╝██║   ██║ ╚███╔╝ ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
██╔══╝  ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
██║     ███████╗██║  ██║╚██████╔╝██╔╝ ██╗██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
</pre>
</p>

<h4 align="center">An AI-powered content discovery tool for penetration testing</h4>

<p align="center">
  A fork of <a href="https://github.com/epi052/feroxbuster">feroxbuster</a> that uses Claude AI to generate intelligent, targeted wordlists based on reconnaissance data.
</p>

---

## Installation

### Homebrew (macOS/Linux)

```bash
brew tap pensarai/feroxagent
brew install feroxagent
```

### Quick Install (curl)

**macOS Apple Silicon (M1/M2/M3):**
```bash
curl -sL https://github.com/pensarai/feroxagent/releases/latest/download/aarch64-macos-feroxagent.tar.gz | tar xz -C /usr/local/bin
```

**macOS Intel:**
```bash
curl -sL https://github.com/pensarai/feroxagent/releases/latest/download/x86_64-macos-feroxagent.tar.gz | tar xz -C /usr/local/bin
```

**Linux x86_64:**
```bash
curl -sL https://github.com/pensarai/feroxagent/releases/latest/download/x86_64-linux-feroxagent.tar.gz | tar xz -C /usr/local/bin
```

**Linux ARM64:**
```bash
curl -sL https://github.com/pensarai/feroxagent/releases/latest/download/aarch64-linux-feroxagent.tar.gz | tar xz -C /usr/local/bin
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://github.com/pensarai/feroxagent/releases/latest/download/x86_64-windows-feroxagent.zip -OutFile feroxagent.zip; Expand-Archive feroxagent.zip -DestinationPath $env:USERPROFILE\bin
```

### Download Binary

Or download manually from [GitHub Releases](https://github.com/pensarai/feroxagent/releases):

| Platform | Download |
|----------|----------|
| macOS (Apple Silicon) | `aarch64-macos-feroxagent.tar.gz` |
| macOS (Intel) | `x86_64-macos-feroxagent.tar.gz` |
| Linux (x86_64) | `x86_64-linux-feroxagent.tar.gz` |
| Linux (ARM64) | `aarch64-linux-feroxagent.tar.gz` |
| Windows (x86_64) | `x86_64-windows-feroxagent.zip` |

### Build from Source

```bash
git clone https://github.com/pensarai/feroxagent.git
cd feroxagent
cargo build --release
```

---

## What is feroxagent?

`feroxagent` is an AI-enhanced web content discovery tool built on top of feroxbuster. Instead of using static wordlists, it analyzes reconnaissance data from tools like [katana](https://github.com/projectdiscovery/katana), [gospider](https://github.com/jaeles-project/gospider), or [hakrawler](https://github.com/hakluke/hakrawler) and uses Claude AI to generate targeted wordlists based on detected technologies and URL patterns.

### Key Features

- **Technology Detection**: Automatically detects frameworks like Next.js, React, Vue, Angular, Rails, Django, Laravel, WordPress, and more from URL patterns
- **AI-Powered Wordlists**: Uses Claude API to generate context-aware wordlists tailored to the target's tech stack
- **Optional HTTP Probing**: Gathers additional context from server headers for more accurate wordlist generation
- **Seamless Scanning**: Generated wordlists are automatically used for content discovery (or output separately)

## Quick Start

### Prerequisites

**Anthropic API Key**: Export your API key as an environment variable:
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### Basic Usage

Pipe reconnaissance data from your favorite crawler:

```bash
# Using katana
katana -u https://target.com -silent | feroxagent -u https://target.com

# Using gospider
gospider -s https://target.com -q | feroxagent -u https://target.com

# Using hakrawler
echo "https://target.com" | hakrawler -plain | feroxagent -u https://target.com
```

### Output Wordlist Only

Generate a wordlist without scanning:

```bash
katana -u https://target.com -silent | feroxagent -u https://target.com --wordlist-only
```

### JSON Output (for automation/agents)

Output structured JSON to stdout for piping to other tools or AI agents:

```bash
katana -u https://target.com -silent | feroxagent -u https://target.com --json | jq '.canonical_endpoints'
```

### Use a Recon File

Load reconnaissance data from a file instead of stdin:

```bash
feroxagent -u https://target.com --recon-file urls.txt
```

## Command Line Options

### feroxagent-specific Options

| Flag | Description |
|------|-------------|
| `--recon-file <FILE>` | Path to file containing reconnaissance URLs (alternative to stdin) |
| `--wordlist-only` | Output generated wordlist to stdout and exit (don't scan) |
| `--json` | Output structured JSON to stdout (canonical endpoints + token usage) |

### Inherited feroxbuster Options

feroxagent inherits most of feroxbuster's powerful options:

| Flag | Description |
|------|-------------|
| `-u, --url <URL>` | Target URL (required) |
| `-t, --threads <NUM>` | Number of concurrent threads (default: 50) |
| `-d, --depth <NUM>` | Maximum recursion depth (default: 4) |
| `-x, --extensions <EXT>` | File extensions to append (e.g., `-x php,html,js`) |
| `-s, --status-codes <CODES>` | Status codes to include (default: All valid codes) |
| `-o, --output <FILE>` | Output file for results |
| `--proxy <URL>` | Proxy to use for requests |
| `-H, --headers <HEADER>` | Custom headers |
| `-k, --insecure` | Disable TLS certificate validation |
| `--silent` | Only print discovered URLs |
| `-v, --verbosity` | Increase verbosity level |

For the complete list of options, run:
```bash
feroxagent --help
```

## How It Works

1. **Collect Recon Data**: Feed URLs from reconnaissance tools (katana, gospider, etc.) via stdin or `--recon-file`

2. **Analyze Patterns**: feroxagent analyzes URL patterns to detect:
   - Frameworks (Next.js, React, Rails, Django, etc.)
   - API endpoints and patterns
   - Static file structures
   - Route conventions

3. **HTTP Probing**: Automatically makes HEAD requests to gather:
   - Server headers
   - X-Powered-By information
   - Content types

4. **Attack Surface Report**: Generates an actionable report highlighting:
   - High-value endpoints to target
   - Potential vulnerabilities based on detected stack
   - Recommended attack vectors (prioritized)

5. **Generate Wordlist**: Creates a targeted wordlist based on the detected tech stack

6. **Scan Target**: Uses the generated wordlist to perform content discovery (or outputs the wordlist with `--wordlist-only`)

## Example Output

```
## Attack Surface Report

### Detected Stack
- Next.js 13 detected - check /_next/data/ for SSR data leaks
- GraphQL endpoint at /graphql - test for introspection

### High-Value Endpoints
- /api/v1/users - REST API, test for IDOR
- /api/admin - potential admin access
- /graphql - check introspection, batching attacks

### Recommended Attack Vectors
1. Test GraphQL introspection at /graphql
2. Enumerate /api/v1/ endpoints for IDOR
3. Check /_next/data/ for sensitive SSR payloads
```

### JSON Output (`--json`)

```json
{
  "target": "https://example.com",
  "canonical_endpoints": [
    {
      "path": "/api/users",
      "methods": ["GET", "POST"],
      "status": 200,
      "is_catch_all": false,
      "variant_count": 1
    },
    {
      "path": "/api/users/{id}",
      "methods": ["GET", "PUT", "DELETE"],
      "auth_required_methods": ["PUT", "DELETE"],
      "status": 401,
      "is_catch_all": true,
      "variant_count": 15,
      "observed_variants": ["1", "2", "me", "current"]
    }
  ],
  "token_usage": {
    "input_tokens": 12540,
    "output_tokens": 1892,
    "cache_read_input_tokens": 8192,
    "cache_creation_input_tokens": 0,
    "total_tokens": 14432
  },
  "stats": {
    "total_endpoints": 23,
    "parameterized_endpoints": 8,
    "catch_all_endpoints": 3
  }
}
```

## Example Workflow

```bash
# Step 1: Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Step 2: Run reconnaissance and scan
katana -u https://example.com -silent -d 3 | \
  feroxagent -u https://example.com -x php,js,html -o results.txt

# Or generate wordlist for use with other tools
katana -u https://example.com -silent | \
  feroxagent -u https://example.com --wordlist-only > custom-wordlist.txt
```

## Technology Detection

feroxagent can detect the following technologies from URL patterns:

| Technology | Detection Patterns |
|------------|-------------------|
| Next.js | `/_next/`, `.next/` |
| React | `/static/js/`, `bundle.js`, `chunk.js` |
| Vue.js | `/js/app.`, `/js/chunk-` |
| Angular | `/main.js`, `/polyfills.js`, `/runtime.js` |
| Ruby on Rails | `/assets/`, `.erb`, `/rails/` |
| Django | `/static/`, `/media/`, `csrftoken` |
| Laravel | `/storage/`, `/public/`, `laravel` |
| Express | `/api/`, `/node_modules/` |
| Spring | `/actuator/`, `.jsp`, `/spring/` |
| ASP.NET | `.aspx`, `.ashx`, `__VIEWSTATE` |
| WordPress | `/wp-content/`, `/wp-admin/`, `/wp-includes/` |
| Drupal | `/sites/default/`, `/modules/`, `/themes/` |
| GraphQL | `/graphql`, `query {`, `mutation {` |

## Credits

feroxagent is built on top of [feroxbuster](https://github.com/epi052/feroxbuster) by [@epi052](https://github.com/epi052).

Thanks to all the [feroxbuster contributors](https://github.com/epi052/feroxbuster#contributors-) for building such an excellent foundation.

## License

This project maintains the same license as feroxbuster (MIT).
