# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Feroxagent is an AI-powered content discovery tool that generates smart wordlists using LLM analysis of recon data, then scans targets with the generated wordlist. It's a fork of feroxbuster that replaces traditional wordlist-based scanning with intelligent, technology-aware path generation.

### How It Works

1. **Recon Input**: Receives URLs from recon tools (katana, gospider, etc.) via stdin or file
2. **Technology Detection**: Analyzes URL patterns to detect frameworks (Next.js, Rails, Django, etc.)
3. **Optional Probing**: Makes HTTP requests to gather headers/response context (`--probe`)
4. **LLM Wordlist Generation**: Calls Claude API to generate targeted paths based on detected tech
5. **Scanning**: Uses generated wordlist to discover hidden content (or outputs wordlist only)

## Build Commands

```bash
# Build (debug)
cargo build

# Build (release with LTO)
cargo build --release

# Run tests (requires cargo-nextest)
cargo nextest run --all-features --all-targets --run-ignored all --retries 4

# Run a single test
cargo nextest run test_name

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt --all

# Full check (format + lint + test)
cargo make check
```

## Usage

```bash
# Basic usage: pipe recon data, scan target
katana -u https://target.com | feroxagent -u https://target.com

# With HTTP probing for more context
katana -u https://target.com | feroxagent -u https://target.com --probe

# Output wordlist only (don't scan)
katana -u https://target.com | feroxagent -u https://target.com --wordlist-only > wordlist.txt

# Read recon from file instead of stdin
feroxagent -u https://target.com --recon-file recon.txt

# Set API key (required)
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Architecture

### Core Components

- **`src/smart_wordlist/`** - LLM-powered wordlist generation (NEW):
  - `analyzer.rs` - Technology detection from URL patterns
  - `llm.rs` - Claude API client for wordlist generation
  - `probe.rs` - HTTP probing for additional context
  - `generator.rs` - Orchestrates analysis, probing, and generation

- **`src/config/`** - Configuration handling via `Configuration` struct. Key fields:
  - `anthropic_key` - Claude API key (from `ANTHROPIC_API_KEY` env var)
  - `recon_file` - Path to recon file (alternative to stdin)
  - `probe` - Enable HTTP probing
  - `wordlist_only` - Output wordlist without scanning

- **`src/scanner/`** - Core scanning logic (inherited from feroxbuster)

- **`src/event_handlers/`** - Async event-driven architecture using tokio mpsc channels

- **`src/filters/`** - Response filtering system

- **`src/heuristics.rs`** - Pre-scan checks: connectivity testing, wildcard detection

### Key Patterns

- Heavy use of `Arc<T>` for shared state across async tasks
- `Handles` struct bundles all event handler channels
- `Command` enum with mpsc channels for inter-task communication
- Technology detection uses pattern matching on URL paths

### Entry Points

- `src/main.rs` - CLI entry point, generates wordlist via LLM then scans
- `src/lib.rs` - Library root, exports modules

## Environment Variables

- `ANTHROPIC_API_KEY` - Claude API key (required)

## Testing

Integration tests are in `tests/` directory. Many use `httpmock` for HTTP mocking.

The smart_wordlist module has unit tests for technology detection and URL parsing.

## Dependencies Note

Uses `cargo-make` for task automation (see `Makefile.toml`). Install with `cargo install cargo-make`.

Tests use `cargo-nextest`. Install with `cargo install cargo-nextest`.
