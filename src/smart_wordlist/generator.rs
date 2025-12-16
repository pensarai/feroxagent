//! Wordlist generation orchestration
//!
//! Coordinates the analysis, probing, and LLM-based wordlist generation.

use super::analyzer::{analyze_urls, TechAnalysis};
use super::llm::ClaudeClient;
use super::mutations::{expand_parameterized_paths, generate_mutations, MutationConfig};
use super::probe::{probe_urls, summarize_probe_results};
use anyhow::{Context, Result};
use reqwest::Client;
use std::collections::HashSet;
use std::io::{self, BufRead};

/// Configuration for wordlist generation
pub struct GeneratorConfig {
    pub target_url: String,
    pub anthropic_key: String,
    pub recon_file: Option<String>,
}

/// Result of the generation process including wordlist and attack surface report
pub struct GenerationResult {
    pub wordlist: Vec<String>,
    pub attack_report: String,
    pub recon_urls: Vec<String>,
    pub technologies: Vec<String>,
}

/// Generate a smart wordlist and attack surface report from recon data
pub async fn generate_wordlist(
    config: GeneratorConfig,
    http_client: &Client,
) -> Result<GenerationResult> {
    // Read recon URLs and filter out noise (node_modules, static assets, etc.)
    let raw_recon_urls = read_recon_urls(&config.recon_file)?;
    let recon_urls = filter_recon_urls(raw_recon_urls);

    if recon_urls.is_empty() {
        log::warn!("No recon URLs provided (or all filtered as noise). Generating generic wordlist based on target only.");
    }

    // Analyze URLs to detect technologies
    log::info!("Analyzing {} filtered recon URLs...", recon_urls.len());
    let analysis = analyze_urls(&recon_urls);

    // Log detected technologies
    if let Some((tech, confidence)) = analysis.primary_technology() {
        log::info!(
            "Primary technology detected: {} (confidence: {:.0}%)",
            tech.as_str(),
            confidence * 100.0
        );
    }

    // Always probe URLs for context (enabled by default now)
    log::info!("Probing URLs for additional context...");
    let probe_results = probe_urls(&recon_urls, http_client, 20).await?;
    let probe_summary = summarize_probe_results(&probe_results);

    // Build the full analysis summary for LLM
    let mut full_summary = analysis.summary();
    if !probe_summary.is_empty() {
        full_summary.push('\n');
        full_summary.push_str(&probe_summary);
    }

    // Generate wordlist and attack report using LLM
    log::info!("Generating wordlist and attack surface report using Claude API...");
    let claude = ClaudeClient::new(config.anthropic_key)?;

    // Generate attack surface report
    let attack_report = claude
        .generate_attack_report(&full_summary, &config.target_url, &analysis, &probe_results)
        .await
        .context("Failed to generate attack surface report")?;

    // Generate wordlist
    let llm_wordlist = claude
        .generate_wordlist(&full_summary, &config.target_url)
        .await
        .context("Failed to generate wordlist from LLM")?;

    log::info!("LLM generated {} paths", llm_wordlist.len());

    // Combine LLM wordlist with extracted paths
    let combined_wordlist = combine_wordlists(&analysis, llm_wordlist);

    log::info!(
        "Final wordlist contains {} unique paths",
        combined_wordlist.len()
    );

    // Extract technology names for the report
    let technologies: Vec<String> = analysis
        .technologies
        .iter()
        .map(|(tech, confidence)| format!("{} ({:.0}%)", tech.as_str(), confidence * 100.0))
        .collect();

    Ok(GenerationResult {
        wordlist: combined_wordlist,
        attack_report,
        recon_urls,
        technologies,
    })
}

/// Read recon URLs from file or stdin
fn read_recon_urls(recon_file: &Option<String>) -> Result<Vec<String>> {
    let lines: Vec<String> = if let Some(file_path) = recon_file {
        std::fs::read_to_string(file_path)
            .context(format!("Failed to read recon file: {}", file_path))?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        // Read from stdin
        let stdin = io::stdin();
        stdin
            .lock()
            .lines()
            .map_while(Result::ok)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    Ok(lines)
}

/// Filter out noise from recon URLs (node_modules, static assets, framework internals)
fn filter_recon_urls(urls: Vec<String>) -> Vec<String> {
    let original_count = urls.len();
    let filtered: Vec<String> = urls
        .into_iter()
        .filter(|url| !is_recon_noise(url))
        .collect();

    let removed = original_count - filtered.len();
    if removed > 0 {
        log::info!(
            "Filtered recon URLs: {} → {} ({} noise URLs removed)",
            original_count,
            filtered.len(),
            removed
        );
    }

    filtered
}

/// Check if a recon URL is noise that should be filtered out
fn is_recon_noise(url: &str) -> bool {
    let url_lower = url.to_lowercase();

    // Framework internals
    let framework_noise = [
        "/node_modules/",
        "/_next/static/chunks/",
        "/dist/compiled/",
        "/dist/client/",
        "/dist/server/",
        "/dist/build/",
        "/ext/static/chunks/",
        "/cjs/",
        "/esm/",
        "webpack-hmr",
        ".development.js",
        ".production.js",
        "/turbopack",
        "/.pnpm/",
    ];

    // Static file extensions - these are never API endpoints
    let static_extensions = [
        ".js", ".ts", ".jsx", ".tsx", ".css", ".scss", ".less", ".map", ".woff", ".woff2", ".ttf",
        ".eot", ".otf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".mp4", ".webm",
        ".mp3", ".wav", ".d.ts",
    ];

    // Check framework noise patterns
    if framework_noise.iter().any(|p| url_lower.contains(p)) {
        return true;
    }

    // Check static file extensions
    if static_extensions.iter().any(|ext| url_lower.ends_with(ext)) {
        return true;
    }

    false
}

/// Combine LLM-generated wordlist with paths extracted during analysis and mutations
fn combine_wordlists(analysis: &TechAnalysis, llm_wordlist: Vec<String>) -> Vec<String> {
    let mut combined: HashSet<String> = HashSet::new();

    // Expand parameterized paths from LLM output (e.g., /api/products/{id} -> /api/products/1, etc.)
    let expanded_llm = expand_parameterized_paths(llm_wordlist);
    for path in expanded_llm {
        combined.insert(path);
    }

    // Add paths extracted from recon URLs
    for path in &analysis.paths {
        combined.insert(path.clone());
    }

    // Add detected API endpoints
    for endpoint in &analysis.api_endpoints {
        combined.insert(endpoint.clone());
    }

    // Add variations of detected API endpoints (legacy, kept for backwards compat)
    for endpoint in &analysis.api_endpoints {
        if endpoint.contains("/api/") {
            let variations = generate_api_variations(endpoint);
            for var in variations {
                combined.insert(var);
            }
        }
    }

    // Generate comprehensive mutations based on discovered patterns
    let discovered_paths: Vec<String> = analysis.paths.iter().cloned().collect();
    let mutation_config = MutationConfig::default();
    let mutations =
        generate_mutations(&discovered_paths, &analysis.api_endpoints, &mutation_config);

    log::info!(
        "Mutation engine generated {} additional paths",
        mutations.len()
    );

    for mutation in mutations {
        combined.insert(mutation);
    }

    // Sort and return
    let mut result: Vec<String> = combined.into_iter().collect();
    result.sort();
    result
}

/// Generate variations of API endpoints
fn generate_api_variations(endpoint: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // If endpoint is /api/v1/users, generate /api/v2/users, etc.
    if endpoint.contains("/v1/") {
        variations.push(endpoint.replace("/v1/", "/v2/"));
        variations.push(endpoint.replace("/v1/", "/v3/"));
    } else if endpoint.contains("/v2/") {
        variations.push(endpoint.replace("/v2/", "/v1/"));
        variations.push(endpoint.replace("/v2/", "/v3/"));
    }

    // Add internal/admin variations
    if endpoint.contains("/api/") {
        variations.push(endpoint.replace("/api/", "/api/internal/"));
        variations.push(endpoint.replace("/api/", "/api/admin/"));
        variations.push(endpoint.replace("/api/", "/api/debug/"));
    }

    variations
}

/// Output wordlist to stdout (for --wordlist-only mode)
pub fn output_wordlist(wordlist: &[String]) {
    for path in wordlist {
        println!("{}", path);
    }
}

/// Output attack surface report to stderr
pub fn output_attack_report(report: &str) {
    eprintln!("\n{}", report);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_variations() {
        let variations = generate_api_variations("/api/v1/users");
        assert!(variations.contains(&"/api/v2/users".to_string()));
        assert!(variations.contains(&"/api/internal/v1/users".to_string()));
    }

    #[test]
    fn test_combine_wordlists() {
        let mut analysis = TechAnalysis::new();
        analysis.paths.insert("/existing/path".to_string());
        analysis.api_endpoints.push("/api/users".to_string());

        let llm_wordlist = vec!["/api/admin".to_string(), "/api/config".to_string()];

        let combined = combine_wordlists(&analysis, llm_wordlist);

        assert!(combined.contains(&"/existing/path".to_string()));
        assert!(combined.contains(&"/api/users".to_string()));
        assert!(combined.contains(&"/api/admin".to_string()));
    }
}
