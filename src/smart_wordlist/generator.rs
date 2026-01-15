//! Wordlist generation orchestration
//!
//! Coordinates the analysis, probing, and LLM-based wordlist generation.

use super::analyzer::{analyze_urls, TechAnalysis};
use super::auth_discovery::{
    attempt_authentication, discover_auth_endpoints, probe_single_auth_endpoint,
    AuthDiscoveryResult, AuthPlan, AuthResult,
};
use super::llm::{AggregatedUsage, ClaudeClient};
use super::mutations::{expand_parameterized_paths, generate_mutations, MutationConfig};
use super::probe::{probe_urls, summarize_probe_results};
use anyhow::{Context, Result};
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead};

/// Configuration for wordlist generation
pub struct GeneratorConfig {
    pub target_url: String,
    pub anthropic_key: String,
    pub recon_file: Option<String>,
    /// Manually specified authentication endpoint
    pub auth_endpoint: Option<String>,
    /// User-provided instructions for authentication
    pub auth_instructions: Option<String>,
    /// Whether to attempt auto-registration
    pub auto_register: bool,
    /// Whether to disable auth discovery
    pub no_discover_auth: bool,
    /// Whether to suppress progress output (JSON mode)
    pub json: bool,
}

/// Result of the generation process including wordlist and attack surface report
pub struct GenerationResult {
    pub wordlist: Vec<String>,
    pub attack_report: String,
    pub recon_urls: Vec<String>,
    pub technologies: Vec<String>,
    pub token_usage: AggregatedUsage,
    /// Authentication discovery and attempt results
    pub auth_result: Option<(AuthDiscoveryResult, AuthPlan, AuthResult)>,
}

/// Configuration for wordlist budgeting to enforce diversity
#[derive(Debug, Clone)]
pub struct BudgetConfig {
    /// Maximum candidates per prefix (e.g., /api/products/* capped at this)
    pub max_per_prefix: usize,
    /// Minimum candidates per discovered prefix from recon
    pub min_per_prefix: usize,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_per_prefix: 50,
            min_per_prefix: 5,
        }
    }
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
    let claude = ClaudeClient::new(config.anthropic_key.clone())?;

    // Track aggregated token usage
    let mut token_usage = AggregatedUsage::default();

    // === AUTH DISCOVERY PHASE ===
    let auth_result = if !config.no_discover_auth {
        if !config.json {
            eprintln!("[*] Discovering authentication endpoints...");
        }
        log::info!("Discovering authentication endpoints...");

        let discovery = if let Some(ref manual_endpoint) = config.auth_endpoint {
            // Manual endpoint provided - probe just that
            log::info!(
                "Using manually specified auth endpoint: {}",
                manual_endpoint
            );
            let full_url = if manual_endpoint.starts_with("http") {
                manual_endpoint.clone()
            } else {
                format!(
                    "{}{}",
                    config.target_url.trim_end_matches('/'),
                    manual_endpoint
                )
            };
            probe_single_auth_endpoint(&full_url, http_client).await?
        } else {
            // Auto-discover common auth paths
            discover_auth_endpoints(&config.target_url, &analysis, http_client).await?
        };

        if !discovery.endpoints.is_empty() {
            if !config.json {
                eprintln!(
                    "[+] Found {} auth endpoint(s): {}",
                    discovery.endpoints.len(),
                    discovery.summary()
                );
            }
            log::info!(
                "Auth discovery found {} endpoints: {}",
                discovery.endpoints.len(),
                discovery.summary()
            );

            // Generate auth plan using LLM
            if !config.json {
                eprintln!("[*] Generating authentication plan using LLM...");
            }
            let (auth_plan, auth_usage) = claude
                .generate_auth_plan(
                    &discovery,
                    config.auth_instructions.as_deref(),
                    &config.target_url,
                    &analysis,
                )
                .await
                .context("Failed to generate auth plan")?;
            token_usage.add(&auth_usage);

            log::info!("Auth plan: {}", auth_plan.summary);

            // Attempt authentication
            if !config.json {
                if config.auto_register && discovery.registration_available {
                    eprintln!("[*] Attempting registration and login...");
                } else {
                    eprintln!("[*] Attempting authentication...");
                }
            }
            let auth_attempt =
                attempt_authentication(&discovery, &auth_plan, http_client, config.auto_register)
                    .await?;

            if auth_attempt.success {
                if !config.json {
                    eprintln!(
                        "[+] Authentication successful! Token type: {:?}",
                        auth_attempt.token_type
                    );
                    if auth_attempt.user_created {
                        if let Some(ref creds) = auth_attempt.credentials_used {
                            eprintln!("[+] Created test user: {}", creds.email);
                        }
                    }
                }
                log::info!(
                    "Authentication successful! Token type: {:?}",
                    auth_attempt.token_type
                );
            } else {
                if !config.json {
                    eprintln!(
                        "[-] Authentication not completed: {}",
                        auth_attempt.error_message.as_deref().unwrap_or("unknown")
                    );
                }
                log::info!(
                    "Authentication not completed: {}",
                    auth_attempt.error_message.as_deref().unwrap_or("unknown")
                );
            }

            // Include auth summary in LLM context for better wordlist generation
            full_summary.push_str(&format!("\n\nAuthentication: {}", auth_plan.summary));

            Some((discovery, auth_plan, auth_attempt))
        } else {
            if !config.json {
                eprintln!("[-] No authentication endpoints discovered");
            }
            log::info!("No authentication endpoints discovered");
            None
        }
    } else {
        log::info!("Auth discovery disabled via --no-discover-auth");
        None
    };

    // Generate attack surface report
    let (attack_report, report_usage) = claude
        .generate_attack_report(&full_summary, &config.target_url, &analysis, &probe_results)
        .await
        .context("Failed to generate attack surface report")?;
    token_usage.add(&report_usage);

    // Generate wordlist
    let (llm_wordlist, wordlist_usage) = claude
        .generate_wordlist(&full_summary, &config.target_url)
        .await
        .context("Failed to generate wordlist from LLM")?;
    token_usage.add(&wordlist_usage);

    log::info!("LLM generated {} paths", llm_wordlist.len());
    log::info!(
        "Token usage: {} input, {} output, {} cached",
        token_usage.input_tokens,
        token_usage.output_tokens,
        token_usage.cache_read_input_tokens
    );

    // Combine LLM wordlist with extracted paths
    let combined_wordlist = combine_wordlists(&analysis, llm_wordlist);

    log::info!(
        "Combined wordlist contains {} unique paths",
        combined_wordlist.len()
    );

    // Extract discovered prefixes from recon for budgeting
    let discovered_prefixes: HashSet<String> = analysis
        .paths
        .iter()
        .chain(analysis.api_endpoints.iter())
        .map(|p| extract_prefix(p))
        .collect();

    // Apply wordlist budgeting to enforce diversity
    let budget_config = BudgetConfig::default();
    let budgeted_wordlist =
        budget_wordlist(combined_wordlist, &discovered_prefixes, &budget_config);

    log::info!(
        "Final wordlist contains {} paths after budgeting",
        budgeted_wordlist.len()
    );

    // Extract technology names for the report
    let technologies: Vec<String> = analysis
        .technologies
        .iter()
        .map(|(tech, confidence)| format!("{} ({:.0}%)", tech.as_str(), confidence * 100.0))
        .collect();

    Ok(GenerationResult {
        wordlist: budgeted_wordlist,
        attack_report,
        recon_urls,
        technologies,
        token_usage,
        auth_result,
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

/// Extract prefix from a path (first 2 segments)
/// e.g., "/api/products/123/reviews" -> "/api/products"
fn extract_prefix(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        format!("/{}/{}", parts[0], parts[1])
    } else if parts.len() == 1 {
        format!("/{}", parts[0])
    } else {
        "/".to_string()
    }
}

/// Budget wordlist to enforce diversity across prefixes
///
/// Groups candidates by their prefix (first 2 path segments) and:
/// - Caps each group at `max_per_prefix` to prevent over-representation
/// - Ensures discovered prefixes from recon have at least `min_per_prefix`
pub fn budget_wordlist(
    candidates: Vec<String>,
    discovered_prefixes: &HashSet<String>,
    config: &BudgetConfig,
) -> Vec<String> {
    // Group candidates by prefix
    let mut prefix_groups: HashMap<String, Vec<String>> = HashMap::new();

    for path in candidates {
        let prefix = extract_prefix(&path);
        prefix_groups.entry(prefix).or_default().push(path);
    }

    let mut result: Vec<String> = Vec::new();
    let mut prefix_stats: Vec<(String, usize, usize)> = Vec::new(); // (prefix, original, budgeted)

    for (prefix, mut paths) in prefix_groups {
        let original_count = paths.len();
        let is_discovered = discovered_prefixes.contains(&prefix);

        // Sort paths to ensure deterministic selection (shorter paths first, then alphabetical)
        paths.sort_by(|a, b| {
            let len_cmp = a.len().cmp(&b.len());
            if len_cmp == std::cmp::Ordering::Equal {
                a.cmp(b)
            } else {
                len_cmp
            }
        });

        // Apply cap
        let capped: Vec<String> = if paths.len() > config.max_per_prefix {
            paths.into_iter().take(config.max_per_prefix).collect()
        } else {
            paths
        };

        let budgeted_count = capped.len();

        // Track stats for logging
        if original_count > config.max_per_prefix || is_discovered {
            prefix_stats.push((prefix.clone(), original_count, budgeted_count));
        }

        // Warn if discovered prefix has fewer than minimum
        if is_discovered && budgeted_count < config.min_per_prefix {
            log::debug!(
                "Discovered prefix {} has only {} paths (minimum: {})",
                prefix,
                budgeted_count,
                config.min_per_prefix
            );
        }

        result.extend(capped);
    }

    // Log significant caps
    let capped_count: usize = prefix_stats
        .iter()
        .filter(|(_, orig, budgeted)| orig > budgeted)
        .count();

    if capped_count > 0 {
        log::info!(
            "Wordlist budgeting: capped {} prefix groups at {} paths each",
            capped_count,
            config.max_per_prefix
        );
    }

    // Sort final result
    result.sort();
    result
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

    #[test]
    fn test_extract_prefix() {
        assert_eq!(extract_prefix("/api/products/123"), "/api/products");
        assert_eq!(extract_prefix("/api/products/123/reviews"), "/api/products");
        assert_eq!(extract_prefix("/admin"), "/admin");
        assert_eq!(extract_prefix("/"), "/");
        assert_eq!(extract_prefix("/api/v1/users/456"), "/api/v1");
    }

    #[test]
    fn test_budget_wordlist_caps_at_max() {
        // Create 100 paths under /api/products
        let candidates: Vec<String> = (0..100).map(|i| format!("/api/products/{}", i)).collect();

        let discovered = HashSet::new();
        let config = BudgetConfig {
            max_per_prefix: 50,
            min_per_prefix: 5,
        };

        let budgeted = budget_wordlist(candidates, &discovered, &config);

        // Should be capped at 50
        assert_eq!(budgeted.len(), 50);
        // All should be from /api/products prefix
        assert!(budgeted.iter().all(|p| p.starts_with("/api/products/")));
    }

    #[test]
    fn test_budget_wordlist_preserves_under_cap() {
        // Create 30 paths under /api/products
        let candidates: Vec<String> = (0..30).map(|i| format!("/api/products/{}", i)).collect();

        let discovered = HashSet::new();
        let config = BudgetConfig {
            max_per_prefix: 50,
            min_per_prefix: 5,
        };

        let budgeted = budget_wordlist(candidates, &discovered, &config);

        // Should preserve all 30
        assert_eq!(budgeted.len(), 30);
    }

    #[test]
    fn test_budget_wordlist_multiple_prefixes() {
        // Create paths under different prefixes
        let mut candidates: Vec<String> = Vec::new();

        // 60 paths under /api/products (should be capped)
        for i in 0..60 {
            candidates.push(format!("/api/products/{}", i));
        }

        // 20 paths under /api/users (should be preserved)
        for i in 0..20 {
            candidates.push(format!("/api/users/{}", i));
        }

        // 10 paths under /admin (should be preserved)
        for i in 0..10 {
            candidates.push(format!("/admin/page{}", i));
        }

        let discovered = HashSet::new();
        let config = BudgetConfig {
            max_per_prefix: 50,
            min_per_prefix: 5,
        };

        let budgeted = budget_wordlist(candidates, &discovered, &config);

        // Should be: 50 (capped) + 20 + 10 = 80
        assert_eq!(budgeted.len(), 80);

        // Count by prefix
        let products_count = budgeted
            .iter()
            .filter(|p| p.starts_with("/api/products/"))
            .count();
        let users_count = budgeted
            .iter()
            .filter(|p| p.starts_with("/api/users/"))
            .count();
        let admin_count = budgeted.iter().filter(|p| p.starts_with("/admin/")).count();

        assert_eq!(products_count, 50);
        assert_eq!(users_count, 20);
        assert_eq!(admin_count, 10);
    }

    #[test]
    fn test_budget_wordlist_shorter_paths_preferred() {
        // Create paths with varying lengths
        let candidates = vec![
            "/api/products/123/reviews/456/comments".to_string(),
            "/api/products/1".to_string(),
            "/api/products/12/reviews".to_string(),
            "/api/products/123".to_string(),
        ];

        let discovered = HashSet::new();
        let config = BudgetConfig {
            max_per_prefix: 2,
            min_per_prefix: 1,
        };

        let budgeted = budget_wordlist(candidates, &discovered, &config);

        // Should only keep 2, preferring shorter paths
        assert_eq!(budgeted.len(), 2);
        assert!(budgeted.contains(&"/api/products/1".to_string()));
        assert!(budgeted.contains(&"/api/products/123".to_string()));
    }
}
