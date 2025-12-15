//! Wordlist generation orchestration
//!
//! Coordinates the analysis, probing, and LLM-based wordlist generation.

use super::analyzer::{analyze_urls, TechAnalysis};
use super::llm::ClaudeClient;
use super::probe::{probe_urls, summarize_probe_results};
use anyhow::{Context, Result};
use reqwest::Client;
use std::collections::HashSet;
use std::io::{self, BufRead};

/// Configuration for wordlist generation
pub struct GeneratorConfig {
    pub target_url: String,
    pub anthropic_key: String,
    pub probe_enabled: bool,
    pub recon_file: Option<String>,
}

/// Generate a smart wordlist from recon data
pub async fn generate_wordlist(
    config: GeneratorConfig,
    http_client: &Client,
) -> Result<Vec<String>> {
    // Read recon URLs
    let recon_urls = read_recon_urls(&config.recon_file)?;

    if recon_urls.is_empty() {
        log::warn!("No recon URLs provided. Generating generic wordlist based on target only.");
    }

    // Analyze URLs to detect technologies
    log::info!("Analyzing {} recon URLs...", recon_urls.len());
    let analysis = analyze_urls(&recon_urls);

    // Log detected technologies
    if let Some((tech, confidence)) = analysis.primary_technology() {
        log::info!(
            "Primary technology detected: {} (confidence: {:.0}%)",
            tech.as_str(),
            confidence * 100.0
        );
    }

    // Optional: Probe URLs for more context
    let probe_summary = if config.probe_enabled {
        log::info!("Probing URLs for additional context...");
        let probe_results = probe_urls(&recon_urls, http_client, 20).await?;
        summarize_probe_results(&probe_results)
    } else {
        String::new()
    };

    // Build the full analysis summary for LLM
    let mut full_summary = analysis.summary();
    if !probe_summary.is_empty() {
        full_summary.push('\n');
        full_summary.push_str(&probe_summary);
    }

    // Generate wordlist using LLM
    log::info!("Generating wordlist using Claude API...");
    let claude = ClaudeClient::new(config.anthropic_key)?;
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

    Ok(combined_wordlist)
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

/// Combine LLM-generated wordlist with paths extracted during analysis
fn combine_wordlists(analysis: &TechAnalysis, llm_wordlist: Vec<String>) -> Vec<String> {
    let mut combined: HashSet<String> = HashSet::new();

    // Add LLM-generated paths
    for path in llm_wordlist {
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

    // Add variations of detected API endpoints
    for endpoint in &analysis.api_endpoints {
        // Add common variations
        if endpoint.contains("/api/") {
            // Version variations
            let variations = generate_api_variations(endpoint);
            for var in variations {
                combined.insert(var);
            }
        }
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
