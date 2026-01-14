//! Comprehensive pentest report generation
//!
//! Combines recon input, attack surface analysis, and scan results
//! into an actionable pentesting report.
//!
//! Uses a signal-based scoring system to filter noise and surface
//! only high-value findings worth investigating.

use super::auth_discovery::{AuthDiscoveryResult, AuthPlan, AuthResult, AuthTokenType};
use super::llm::AggregatedUsage;
use console::style;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum pentest value score to be considered "interesting"
const MIN_INTERESTING_SCORE: i32 = 4;

/// Discovered endpoint from the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub status_code: u16,
    pub content_length: u64,
    pub content_type: Option<String>,
    pub interesting: bool,
    pub pentest_score: i32,
    pub notes: Vec<String>,
    /// If this endpoint appears to be parameterized (e.g., /api/products/123)
    pub is_parameterized: bool,
    /// The inferred parameter pattern (e.g., /api/products/{id})
    pub param_pattern: Option<String>,
}

/// Comprehensive pentest report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PentestReport {
    /// Target URL
    pub target: String,

    /// Original recon URLs (from katana/gospider/etc)
    pub recon_urls: Vec<String>,

    /// Detected technologies
    pub technologies: Vec<String>,

    /// Attack surface analysis from LLM
    pub attack_surface_report: String,

    /// Discovered endpoints from the scan
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,

    /// High-value findings (interesting status codes, sensitive paths)
    pub high_value_findings: Vec<DiscoveredEndpoint>,

    /// Canonical endpoint inventory (deduplicated, templated)
    pub canonical_endpoints: Vec<CanonicalEndpoint>,

    /// Summary statistics
    pub stats: ReportStats,
}

/// Statistics for the report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportStats {
    pub total_recon_urls: usize,
    pub total_paths_tested: usize,
    pub total_discovered: usize,
    pub total_filtered_noise: usize,
    pub status_code_breakdown: HashMap<u16, usize>,
}

/// JSON output structure for --json flag
#[derive(Debug, Serialize)]
pub struct JsonOutput {
    pub target: String,
    pub canonical_endpoints: Vec<CanonicalEndpointJson>,
    pub token_usage: JsonTokenUsage,
    pub stats: JsonStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_discovery: Option<JsonAuthDiscovery>,
}

/// Canonical endpoint in JSON output format
#[derive(Debug, Serialize)]
pub struct CanonicalEndpointJson {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_required_methods: Option<Vec<String>>,
    pub status: u16,
    pub is_catch_all: bool,
    pub variant_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observed_variants: Vec<String>,
}

/// Token usage in JSON output format
#[derive(Debug, Serialize)]
pub struct JsonTokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_read_input_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub total_tokens: u32,
}

/// Stats in JSON output format
#[derive(Debug, Serialize)]
pub struct JsonStats {
    pub total_paths_tested: usize,
    pub total_filtered_noise: usize,
}

/// Auth discovery in JSON output format
#[derive(Debug, Serialize)]
pub struct JsonAuthDiscovery {
    /// Whether auth discovery was attempted
    pub discovered: bool,
    /// Whether authentication was successful
    pub authenticated: bool,
    /// List of discovered auth endpoints
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<JsonAuthEndpoint>,
    /// Registration availability
    pub registration_available: bool,
    /// Login endpoint if found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_endpoint: Option<String>,
    /// Register endpoint if found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_endpoint: Option<String>,
    /// Type of authentication used (Bearer, Cookie, ApiKey, None)
    pub auth_type: String,
    /// Whether a new user was created during auth discovery
    pub user_created: bool,
    /// Summary of the auth flow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// The auth token obtained (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Session cookies obtained (if any)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<String>,
    /// Credentials used for authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<JsonCredentials>,
}

/// Credentials used for authentication
#[derive(Debug, Serialize)]
pub struct JsonCredentials {
    pub email: String,
    pub password: String,
}

/// Auth endpoint in JSON output format
#[derive(Debug, Serialize)]
pub struct JsonAuthEndpoint {
    pub url: String,
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub detected_fields: Vec<String>,
    /// Status code from auth attempt (or discovery if not attempted)
    pub status_code: u16,
}

impl PentestReport {
    /// Create a new report
    pub fn new(target: String) -> Self {
        Self {
            target,
            recon_urls: Vec::new(),
            technologies: Vec::new(),
            attack_surface_report: String::new(),
            discovered_endpoints: Vec::new(),
            high_value_findings: Vec::new(),
            canonical_endpoints: Vec::new(),
            stats: ReportStats::default(),
        }
    }

    /// Add recon URLs
    pub fn set_recon_urls(&mut self, urls: Vec<String>) {
        self.stats.total_recon_urls = urls.len();
        self.recon_urls = urls;
    }

    /// Set attack surface report
    pub fn set_attack_surface(&mut self, report: String) {
        self.attack_surface_report = report;
    }

    /// Set detected technologies
    pub fn set_technologies(&mut self, techs: Vec<String>) {
        self.technologies = techs;
    }

    /// Set canonical endpoint inventory
    pub fn set_canonical_endpoints(&mut self, endpoints: Vec<CanonicalEndpoint>) {
        self.canonical_endpoints = endpoints;
    }

    /// Convert report to JSON output format
    pub fn to_json_output(
        &self,
        token_usage: &AggregatedUsage,
        auth_result: Option<&(AuthDiscoveryResult, AuthPlan, AuthResult)>,
    ) -> JsonOutput {
        let canonical_endpoints: Vec<CanonicalEndpointJson> = self
            .canonical_endpoints
            .iter()
            .map(|e| CanonicalEndpointJson {
                path: e.path.clone(),
                methods: e.confirmed_methods.clone(),
                auth_required_methods: e.auth_required_methods.clone(),
                status: e.primary_status,
                is_catch_all: e.is_catch_all_param,
                variant_count: e.variant_count,
                observed_variants: e.observed_param_values.clone(),
            })
            .collect();

        // Convert auth discovery results if present
        let auth_discovery = auth_result.map(|(discovery, plan, result)| {
            JsonAuthDiscovery {
                discovered: true,
                authenticated: result.success,
                endpoints: discovery
                    .endpoints
                    .iter()
                    .map(|ep| {
                        // Use actual auth attempt status if available, otherwise discovery status
                        let status = match ep.endpoint_type {
                            super::auth_discovery::AuthEndpointType::Login => {
                                result.login_status.unwrap_or(ep.status_code)
                            }
                            super::auth_discovery::AuthEndpointType::Register => {
                                result.register_status.unwrap_or(ep.status_code)
                            }
                            _ => ep.status_code,
                        };
                        JsonAuthEndpoint {
                            url: ep.url.clone(),
                            endpoint_type: format!("{:?}", ep.endpoint_type),
                            method: ep.method.clone(),
                            content_type: ep.content_type.clone(),
                            detected_fields: ep.detected_fields.clone(),
                            status_code: status,
                        }
                    })
                    .collect(),
                registration_available: discovery.registration_available,
                login_endpoint: discovery.login_endpoint.as_ref().map(|e| e.url.clone()),
                register_endpoint: discovery.register_endpoint.as_ref().map(|e| e.url.clone()),
                auth_type: match result.token_type {
                    AuthTokenType::Bearer => "Bearer".to_string(),
                    AuthTokenType::Cookie => "Cookie".to_string(),
                    AuthTokenType::ApiKey => "ApiKey".to_string(),
                    AuthTokenType::None => "None".to_string(),
                },
                user_created: result.user_created,
                summary: Some(plan.summary.clone()),
                token: result.token.clone(),
                cookies: result.cookies.clone(),
                credentials: result.credentials_used.as_ref().map(|creds| JsonCredentials {
                    email: creds.email.clone(),
                    password: creds.password.clone(),
                }),
            }
        });

        JsonOutput {
            target: self.target.clone(),
            canonical_endpoints,
            token_usage: JsonTokenUsage {
                input_tokens: token_usage.input_tokens,
                output_tokens: token_usage.output_tokens,
                cache_read_input_tokens: token_usage.cache_read_input_tokens,
                cache_creation_input_tokens: token_usage.cache_creation_input_tokens,
                total_tokens: token_usage.total_tokens,
            },
            stats: JsonStats {
                total_paths_tested: self.stats.total_paths_tested,
                total_filtered_noise: self.stats.total_filtered_noise,
            },
            auth_discovery,
        }
    }

    /// Add a discovered endpoint
    pub fn add_endpoint(&mut self, endpoint: DiscoveredEndpoint) {
        // Track status code breakdown
        *self
            .stats
            .status_code_breakdown
            .entry(endpoint.status_code)
            .or_insert(0) += 1;

        // Check if high-value
        if endpoint.interesting {
            self.high_value_findings.push(endpoint.clone());
        }

        self.discovered_endpoints.push(endpoint);
        self.stats.total_discovered = self.discovered_endpoints.len();
    }

    /// Calculate pentest value score for an endpoint
    ///
    /// Scoring heuristic based on what matters for pentesting:
    /// - User input surfaces: +3
    /// - Non-200 response (indicates behavior): +2
    /// - Server-side execution potential: +3
    /// - Auth-related: +2
    /// - Dev/internal endpoint: +3
    /// - Static asset: -3
    ///
    /// Only endpoints with score >= 4 are worth investigating.
    pub fn calculate_pentest_score(
        url: &str,
        status_code: u16,
        content_type: Option<&str>,
    ) -> (i32, Vec<String>) {
        let mut score: i32 = 0;
        let mut notes = Vec::new();
        let url_lower = url.to_lowercase();

        // Static asset detection - heavily penalize noise
        if is_static_asset(&url_lower) {
            score -= 3;
            // Don't add notes for static assets - they're noise
            return (score, notes);
        }

        // User input surface - high value
        if accepts_user_input(&url_lower, status_code) {
            score += 3;
            notes.push(get_input_surface_note(&url_lower, status_code));
        }

        // Non-200 responses indicate behavior
        match status_code {
            400 => {
                score += 2;
                notes.push("400 Bad Request - endpoint expects parameters".to_string());
            }
            401 => {
                score += 2;
                notes.push("401 Unauthorized - test for auth bypass".to_string());
            }
            403 => {
                score += 2;
                notes.push("403 Forbidden - test path traversal, header manipulation".to_string());
            }
            405 => {
                score += 2;
                notes.push("405 Method Not Allowed - try GET/POST/PUT/DELETE/OPTIONS".to_string());
            }
            500 | 502 | 503 => {
                score += 2;
                notes.push("Server error - potential for info disclosure or injection".to_string());
            }
            201 | 202 | 204 => {
                score += 2;
                notes.push("Writable endpoint - test for unauthorized modifications".to_string());
            }
            _ => {}
        }

        // Server-side execution potential
        if has_server_execution_potential(&url_lower, content_type) {
            score += 3;
            notes.push(get_execution_note(&url_lower, content_type));
        }

        // Auth-related endpoints
        if is_auth_related(&url_lower) {
            score += 2;
            notes.push("Auth-related endpoint - test for bypass, session handling".to_string());
        }

        // Dev-only or internal endpoints - should never be in prod
        if is_dev_or_internal(&url_lower) {
            score += 3;
            notes.push(get_dev_internal_note(&url_lower));
        }

        // High-value sensitive paths
        if let Some(reason) = get_sensitive_path_reason(&url_lower) {
            score += 2;
            notes.push(reason);
        }

        // XML content - XXE potential
        if let Some(ct) = content_type {
            if ct.contains("xml") {
                score += 2;
                notes.push("XML endpoint - test for XXE injection".to_string());
            }
        }

        (score, notes)
    }

    /// Check if endpoint is interesting based on pentest score
    pub fn is_interesting(
        url: &str,
        status_code: u16,
        content_type: Option<&str>,
    ) -> (bool, i32, Vec<String>) {
        let (score, notes) = Self::calculate_pentest_score(url, status_code, content_type);
        (score >= MIN_INTERESTING_SCORE, score, notes)
    }

    /// Generate the final report output - attack surface with noise filtered
    /// Styled to match feroxbuster's pretty output format with colors
    pub fn generate_output(&self) -> String {
        let mut output = String::new();

        // Top divider
        output.push_str("─────────────────────────────────────────┬──────────────────────────────────────────\n");

        // Summary section - feroxbuster style: emoji + padded label + │ + value
        output.push_str(&format!(
            " 🎯  {:<22}│ {}\n",
            "Target",
            style(&self.target).cyan()
        ));
        output.push_str(&format!(
            " 📥  {:<22}│ {}\n",
            "Recon URLs",
            style(self.stats.total_recon_urls).green()
        ));
        output.push_str(&format!(
            " 🔍  {:<22}│ {}\n",
            "Paths Tested",
            style(self.stats.total_paths_tested).green()
        ));
        output.push_str(&format!(
            " ✅  {:<22}│ {}\n",
            "Endpoints Found",
            style(self.stats.total_discovered).green()
        ));
        output.push_str(&format!(
            " 🗑️   {:<22}│ {}\n",
            "Static Filtered",
            style(self.stats.total_filtered_noise).yellow()
        ));

        // Detected technologies
        if !self.technologies.is_empty() {
            for tech in &self.technologies {
                output.push_str(&format!(
                    " 🔧  {:<22}│ {}\n",
                    "Detected Tech",
                    style(tech).cyan()
                ));
            }
        }

        // Status code breakdown with colors
        if !self.stats.status_code_breakdown.is_empty() {
            let mut codes: Vec<_> = self.stats.status_code_breakdown.iter().collect();
            codes.sort_by_key(|(code, _)| *code);
            let status_summary: Vec<String> = codes
                .iter()
                .map(|(code, count)| {
                    let colored_code = colorize_status_code(**code);
                    format!("{}×{}", colored_code, count)
                })
                .collect();
            output.push_str(&format!(
                " 📊  {:<22}│ {}\n",
                "Status Codes",
                status_summary.join(", ")
            ));
        }

        // Bottom of config section
        output.push_str("─────────────────────────────────────────┴──────────────────────────────────────────\n");

        // Attack surface analysis from LLM
        if !self.attack_surface_report.is_empty()
            && self.attack_surface_report != "No notable findings."
        {
            output.push_str(&format!(" 🧠  {}\n", style("AI Analysis").bright().white()));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for line in self.attack_surface_report.lines() {
                output.push_str(&format!("  {}\n", line));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // DISCOVERED ROUTES - filter to only routes that EXIST
        // 404 = doesn't exist, all other status codes = route exists
        let existing_routes: Vec<_> = self
            .discovered_endpoints
            .iter()
            .filter(|e| is_existence_signal(e.status_code))
            .filter(|e| !is_framework_junk(&e.url))
            .collect();

        // Consolidate parameterized routes (collapse /api/products/1,2,3 -> /api/products/{id})
        let consolidated = consolidate_routes(&existing_routes);

        // Categorize by status meaning
        let categories = categorize_routes(consolidated);

        // Helper to format a route line
        let format_route = |route: &ConsolidatedRoute| -> String {
            let colored_status = colorize_status_code(route.status_code);
            let size_str = if route.content_length > 0 {
                format!("{}c", route.content_length)
            } else {
                String::new()
            };

            if route.variant_count > 1 {
                format!(
                    "{:<7} {:>9} {}  {}\n",
                    colored_status,
                    style(size_str).dim(),
                    style(&route.pattern).cyan(),
                    style(format!("({} variants)", route.variant_count)).dim()
                )
            } else {
                format!(
                    "{:<7} {:>9} {}\n",
                    colored_status,
                    style(size_str).dim(),
                    route.example_url
                )
            }
        };

        // Confirmed Routes (2xx)
        if !categories.confirmed.is_empty() {
            output.push_str(&format!(
                " ✅  {}\n",
                style("Confirmed Routes").bright().white()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in &categories.confirmed {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Auth Required (401, 403)
        if !categories.auth_required.is_empty() {
            output.push_str(&format!(
                " 🔐  {}\n",
                style("Auth Required").bright().white()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in &categories.auth_required {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Method Mismatch (405)
        if !categories.method_mismatch.is_empty() {
            output.push_str(&format!(
                " ⚡  {} {}\n",
                style("Method Mismatch").bright().white(),
                style("(route exists, try different HTTP methods)").dim()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in &categories.method_mismatch {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Server Errors (5xx)
        if !categories.server_error.is_empty() {
            output.push_str(&format!(
                " 💥  {} {}\n",
                style("Server Errors").bright().white(),
                style("(potential vulnerabilities)").dim()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in &categories.server_error {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Redirects (3xx) - only show if interesting
        let interesting_redirects: Vec<_> = categories
            .redirects
            .iter()
            .filter(|r| {
                // Only show redirects to interesting paths (admin, api, internal)
                r.pattern.contains("/admin")
                    || r.pattern.contains("/api")
                    || r.pattern.contains("/internal")
                    || r.pattern.contains("/private")
            })
            .collect();
        if !interesting_redirects.is_empty() {
            output.push_str(&format!(" ↪️   {}\n", style("Redirects").bright().white()));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in interesting_redirects {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // Other (400 etc.) - potential input surfaces
        if !categories.other.is_empty() {
            output.push_str(&format!(
                " 🔍  {} {}\n",
                style("Input Surfaces").bright().white(),
                style("(400 = expects parameters)").dim()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            for route in &categories.other {
                output.push_str(&format_route(route));
            }
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        // CANONICAL ENDPOINTS - deduplicated, templated list
        if !self.canonical_endpoints.is_empty() {
            output.push_str(&format!(
                " 📌  {}\n",
                style("Canonical Endpoints").bright().white()
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

            // Collect all observed param values for the variants section
            let mut all_observed_variants: Vec<(String, Vec<String>)> = Vec::new();

            for endpoint in &self.canonical_endpoints {
                let mut line = format!("     {}", endpoint.path);

                // Add methods and annotation info
                // Priority: confirmed methods > allow hint > annotation
                if let Some(ref confirmed) = endpoint.confirmed_methods {
                    // Show empirically confirmed methods
                    if !confirmed.is_empty() {
                        line.push_str(&format!(
                            " {}",
                            style(format!("(methods: {})", confirmed.join(", "))).green()
                        ));
                    }
                }

                // Show auth-required methods if any
                if let Some(ref auth_methods) = endpoint.auth_required_methods {
                    if !auth_methods.is_empty() {
                        line.push_str(&format!(
                            " {}",
                            style(format!("(auth: {})", auth_methods.join(", "))).yellow()
                        ));
                    }
                }

                // Show Allow header hint if no confirmed methods
                if endpoint.confirmed_methods.is_none() {
                    if let Some(ref hint) = endpoint.allow_hint {
                        if !hint.is_empty() {
                            line.push_str(&format!(
                                " {}",
                                style(format!("(Allow hint: {})", hint.join(", "))).dim()
                            ));
                        }
                    } else if let Some(ref annotation) = endpoint.annotation {
                        // Fall back to status annotation
                        line.push_str(&format!(" {}", style(annotation).dim()));
                    }
                }

                // Show catch-all param route indicator with variant count
                if endpoint.is_catch_all_param {
                    line.push_str(&format!(
                        " {}",
                        style(format!(
                            "(catch-all param; {} variants)",
                            endpoint.variant_count
                        ))
                        .cyan()
                    ));

                    // Collect observed variants for separate section
                    if !endpoint.observed_param_values.is_empty() {
                        all_observed_variants.push((
                            endpoint.path.clone(),
                            endpoint.observed_param_values.clone(),
                        ));
                    }
                } else if endpoint.variant_count > 1 {
                    // Regular variant count for non-catch-all
                    line.push_str(&format!(
                        " {}",
                        style(format!("({} variants)", endpoint.variant_count)).dim()
                    ));
                }

                output.push_str(&format!("{}\n", line));
            }

            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

            // OBSERVED PARAMETER VARIANTS section (for fuzzing reference)
            if !all_observed_variants.is_empty() {
                output.push_str(&format!(
                    " 🧪  {} {}\n",
                    style("Observed Parameter Variants").bright().white(),
                    style("(non-canonical, for fuzzing)").dim()
                ));
                output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

                for (path, variants) in &all_observed_variants {
                    // Truncate variants list if too long
                    let display_variants: Vec<_> = variants.iter().take(20).collect();
                    let truncated = variants.len() > 20;

                    output.push_str(&format!(
                        "     {} → {}{}\n",
                        style(path).dim(),
                        display_variants
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        if truncated {
                            format!(" (+{} more)", variants.len() - 20)
                        } else {
                            String::new()
                        }
                    ));
                }

                output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
            }
        }

        // Original recon URLs from katana/gospider/etc
        // Filter out noise before displaying
        if !self.recon_urls.is_empty() {
            let display_recon: Vec<_> = self
                .recon_urls
                .iter()
                .filter(|url| !is_recon_display_noise(url))
                .take(50) // Limit to 50 most relevant
                .collect();

            let filtered_count = self.recon_urls.len() - display_recon.len();
            let showing_count = display_recon.len();

            output.push_str(&format!(
                " 📡  {} ({} shown, {} filtered)\n",
                style("Recon URLs").bright().white(),
                showing_count,
                filtered_count
            ));
            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");

            for url in display_recon {
                output.push_str(&format!("     {}\n", style(url).dim()));
            }

            output.push_str("───────────────────────────────────────────────────────────────────────────────────\n");
        }

        output
    }

    /// Generate JSON output
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// =============================================================================
// STATIC ASSET DETECTION - Filter out noise
// =============================================================================

/// Check if URL is a static asset (noise)
fn is_static_asset(url: &str) -> bool {
    // File extensions that are static assets
    let static_extensions = [
        ".js", ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", // fonts & styles
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", // images
        ".mp4", ".webm", ".mp3", ".wav", // media
        ".map", ".d.ts", ".ts", // sourcemaps & type definitions (not executable server-side)
    ];

    // Path patterns that are framework internals / static
    let static_patterns = [
        "/_next/static/",
        "/_next/image", // Note: /_next/image with params IS interesting, handled separately
        "/static/js/",
        "/static/css/",
        "/static/media/",
        "/assets/",
        "/node_modules/",
        "/vendor/",
        "/dist/",
        "/build/static/",
        "/chunks/",
        "/__webpack",
        "/turbopack/",
        "/pnpm/",
        "/.pnpm/",
        "/fonts/",
        "/images/",
        "/img/",
    ];

    // Check extensions
    for ext in &static_extensions {
        if url.ends_with(ext) {
            return true;
        }
    }

    // Check patterns
    for pattern in &static_patterns {
        if url.contains(pattern) {
            // Exception: /_next/image endpoint IS interesting (SSRF potential)
            if url.contains("/_next/image") && !url.contains("/_next/image/") {
                return false;
            }
            return true;
        }
    }

    false
}

// =============================================================================
// USER INPUT DETECTION - Where does input cross trust boundaries?
// =============================================================================

/// Check if endpoint accepts user input
fn accepts_user_input(url: &str, status_code: u16) -> bool {
    // 400 Bad Request often means "you're missing required params"
    if status_code == 400 {
        return true;
    }

    // Known input-accepting endpoints
    let input_patterns = [
        "/_next/image", // accepts url param - SSRF potential
        "/graphql",     // accepts queries
        "/api/",        // REST APIs accept input
        "/search",      // search functionality
        "/upload",      // file uploads
        "/login",       // credentials
        "/register",    // user data
        "/reset",       // password reset
        "/callback",    // OAuth callbacks
        "/webhook",     // webhook endpoints
        "/import",      // data import
        "/export",      // may accept format params
        "/proxy",       // proxy endpoints - SSRF
        "/fetch",       // fetch endpoints - SSRF
        "/redirect",    // redirect endpoints - open redirect
        "/url",         // URL params - SSRF/redirect
        "/link",        // link params
    ];

    input_patterns.iter().any(|p| url.contains(p))
}

/// Get note about what kind of input the endpoint accepts
fn get_input_surface_note(url: &str, status_code: u16) -> String {
    if url.contains("/_next/image") {
        return "Next.js image loader - test SSRF: ?url=http://127.0.0.1&w=100&q=75".to_string();
    }
    if url.contains("/graphql") {
        return "GraphQL - test introspection query, batching attacks".to_string();
    }
    if url.contains("/proxy") || url.contains("/fetch") || url.contains("/url") {
        return "Potential SSRF - test with internal URLs".to_string();
    }
    if url.contains("/redirect") || url.contains("/link") {
        return "Potential open redirect - test with external URLs".to_string();
    }
    if url.contains("/upload") || url.contains("/import") {
        return "File handling - test for path traversal, unrestricted upload".to_string();
    }
    if status_code == 400 {
        return "400 response indicates missing/invalid parameters - fuzz inputs".to_string();
    }
    "Accepts user input - test for injection vulnerabilities".to_string()
}

// =============================================================================
// SERVER-SIDE EXECUTION DETECTION
// =============================================================================

/// Check if endpoint has server-side execution potential
fn has_server_execution_potential(url: &str, content_type: Option<&str>) -> bool {
    // Server-side patterns
    let server_patterns = [
        "/api/",
        "/graphql",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".do",
        ".action",
        "/cgi-bin/",
        "/servlet/",
        "/invoke/",
        "/execute/",
        "/run/",
        "/eval/",
        "/cmd/",
        "/shell/",
        "/rpc",
        "/jsonrpc",
        "/xmlrpc",
        "/soap",
    ];

    // Check URL patterns
    if server_patterns.iter().any(|p| url.contains(p)) {
        return true;
    }

    // Check content type for dynamic content
    if let Some(ct) = content_type {
        if ct.contains("json") || ct.contains("xml") || ct.contains("html") {
            // Only interesting if it's an API-like path
            if url.contains("/api") || url.contains("/v1") || url.contains("/v2") {
                return true;
            }
        }
    }

    false
}

/// Get note about server execution potential
fn get_execution_note(url: &str, content_type: Option<&str>) -> String {
    if url.contains("/graphql") {
        return "GraphQL endpoint - server-side query execution".to_string();
    }
    if url.contains(".php") {
        return "PHP endpoint - test for code injection, LFI".to_string();
    }
    if url.contains(".asp") || url.contains(".aspx") {
        return "ASP.NET endpoint - test for viewstate attacks".to_string();
    }
    if url.contains("/rpc") || url.contains("/jsonrpc") || url.contains("/xmlrpc") {
        return "RPC endpoint - test for method enumeration, injection".to_string();
    }
    if url.contains("/api/") {
        if let Some(ct) = content_type {
            if ct.contains("json") {
                return "JSON API - test for mass assignment, IDOR".to_string();
            }
        }
        return "API endpoint - test for auth bypass, IDOR".to_string();
    }
    "Server-side endpoint".to_string()
}

// =============================================================================
// AUTH-RELATED DETECTION
// =============================================================================

/// Check if endpoint is auth-related
fn is_auth_related(url: &str) -> bool {
    let auth_patterns = [
        "/auth",
        "/login",
        "/logout",
        "/signin",
        "/signout",
        "/signup",
        "/register",
        "/password",
        "/reset",
        "/forgot",
        "/token",
        "/oauth",
        "/sso",
        "/saml",
        "/cas/",
        "/session",
        "/jwt",
        "/verify",
        "/confirm",
        "/activate",
        "/.well-known/",
        "/openid",
        "/callback",
    ];

    auth_patterns.iter().any(|p| url.contains(p))
}

// =============================================================================
// DEV/INTERNAL ENDPOINT DETECTION - Should never be in production
// =============================================================================

/// Check if endpoint is dev-only or internal
fn is_dev_or_internal(url: &str) -> bool {
    let dev_patterns = [
        // Next.js dev endpoints
        "/__nextjs_",
        "/__next_",
        "/_next-dev",
        // General dev endpoints
        "/debug",
        "/__debug__",
        "/devtools",
        "/dev/",
        "/_dev/",
        "/trace",
        "/profiler",
        "/pprof",
        "/silk/", // Django Silk profiler
        "/phpinfo",
        "/info.php",
        "/test.php",
        // Internal endpoints
        "/internal/",
        "/private/",
        "/_internal/",
        "/_private/",
        // Infrastructure
        "/actuator",
        "/healthz",
        "/readyz",
        "/livez",
        "/metrics",
        "/prometheus",
        "/-/", // Prometheus/GitLab internal
        // Admin/management
        "/admin",
        "/manage",
        "/management",
        "/console",
        "/elmah",
        "/error_log",
        // Version control exposure - extremely sensitive
        "/.git",
        "/.svn",
        "/.hg",
        // Environment/secrets exposure
        "/.env",
        "/config.json",
        "/secrets",
    ];

    dev_patterns.iter().any(|p| url.contains(p))
}

/// Get note about why dev/internal endpoint is concerning
fn get_dev_internal_note(url: &str) -> String {
    if url.contains("/__nextjs_") {
        return "Next.js dev endpoint - should NOT be in production".to_string();
    }
    if url.contains("/actuator") {
        return "Spring Actuator - check /env, /heapdump, /mappings for secrets".to_string();
    }
    if url.contains("/pprof") || url.contains("/profiler") {
        return "Profiler endpoint - may leak memory contents".to_string();
    }
    if url.contains("/debug") || url.contains("/__debug__") {
        return "Debug endpoint - may expose internal state, RCE risk".to_string();
    }
    if url.contains("/healthz") || url.contains("/metrics") {
        return "Infrastructure endpoint - may leak internal info".to_string();
    }
    if url.contains("/internal/") || url.contains("/private/") {
        return "Internal endpoint - likely missing auth checks".to_string();
    }
    if url.contains("/admin") || url.contains("/console") {
        return "Admin interface - test for auth bypass".to_string();
    }
    if url.contains("/phpinfo") || url.contains("/info.php") {
        return "PHP info - exposes full server config".to_string();
    }
    if url.contains("/.git") {
        return "Git exposure - dump with git-dumper for source code".to_string();
    }
    if url.contains("/.svn") || url.contains("/.hg") {
        return "Version control exposure - may leak source code".to_string();
    }
    if url.contains("/.env") {
        return "Environment file - likely contains secrets/credentials".to_string();
    }
    if url.contains("/config.json") || url.contains("/secrets") {
        return "Config/secrets file - may contain credentials".to_string();
    }
    "Dev/internal endpoint exposed in production".to_string()
}

// =============================================================================
// SENSITIVE PATH DETECTION - High-value targets
// =============================================================================

/// Get reason why path is sensitive (returns None if not sensitive)
fn get_sensitive_path_reason(url: &str) -> Option<String> {
    // Version control - source code exposure
    if url.contains("/.git") {
        return Some("Git exposure - dump with git-dumper, may leak source".to_string());
    }
    if url.contains("/.svn") {
        return Some("SVN exposure - may leak source code".to_string());
    }
    if url.contains("/.hg") {
        return Some("Mercurial exposure - may leak source code".to_string());
    }

    // Environment/config files
    if url.contains("/.env") {
        return Some("Environment file - likely contains secrets/credentials".to_string());
    }
    if url.contains("/config")
        && (url.contains(".json") || url.contains(".yml") || url.contains(".yaml"))
    {
        return Some("Config file - may contain credentials, API keys".to_string());
    }
    if url.contains("/.aws") || url.contains("/credentials") {
        return Some("AWS credentials - immediate compromise risk".to_string());
    }
    if url.contains("/web.config") {
        return Some("IIS config - may contain connection strings".to_string());
    }
    if url.contains("/.htaccess") || url.contains("/.htpasswd") {
        return Some("Apache config - may expose auth or rewrite rules".to_string());
    }

    // Backups
    if url.contains(".bak") || url.contains(".backup") || url.contains(".old") || url.contains("~")
    {
        return Some("Backup file - may contain sensitive data or source".to_string());
    }
    if url.contains(".sql") || url.contains(".dump") {
        return Some("Database dump - likely contains all data".to_string());
    }

    // API documentation - attack surface mapping
    if url.contains("/swagger") || url.contains("/api-docs") || url.contains("/openapi") {
        return Some("API docs - maps full attack surface, auth requirements".to_string());
    }
    if url.contains("/graphiql") || url.contains("/playground") || url.contains("/altair") {
        return Some("GraphQL IDE - interactive query interface exposed".to_string());
    }

    // Heapdump / memory
    if url.contains("/heapdump") || url.contains("/dump") {
        return Some("Heap dump - contains in-memory secrets, session tokens".to_string());
    }

    None
}

/// Output report to stderr
pub fn output_report(report: &PentestReport) {
    eprintln!("{}", report.generate_output());
}

// =============================================================================
// PARAMETERIZED ENDPOINT DETECTION
// =============================================================================

/// Numeric ID values used in mutation testing that indicate parameterized endpoints
/// NOTE: Only numeric values - string values like "admin", "test" caused false positives
const PARAM_ID_VALUES: &[&str] = &["1", "2", "0", "100", "999", "1000", "-1"];

/// UUID patterns used in testing
const UUID_PATTERNS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
];

/// Known API resource/route names that should NOT be treated as IDs
/// These are legitimate URL path segments, not parameterized values
const KNOWN_RESOURCE_NAMES: &[&str] = &[
    // API structure
    "api",
    "v1",
    "v2",
    "v3",
    "internal",
    "external",
    "public",
    "private",
    // Auth
    "admin",
    "auth",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "signout",
    "session",
    "sessions",
    "token",
    "tokens",
    "oauth",
    "oauth2",
    "sso",
    "callback",
    "me",
    "self",
    "current",
    "profile",
    // Resources
    "users",
    "user",
    "products",
    "product",
    "orders",
    "order",
    "items",
    "item",
    "reviews",
    "review",
    "comments",
    "comment",
    "categories",
    "category",
    "cart",
    "carts",
    "checkout",
    "payments",
    "payment",
    // Operations
    "search",
    "filter",
    "find",
    "list",
    "all",
    "new",
    "create",
    "edit",
    "update",
    "delete",
    "export",
    "import",
    "bulk",
    "batch",
    "count",
    // System
    "health",
    "healthz",
    "status",
    "config",
    "settings",
    "debug",
    "metrics",
    "diagnostics",
    "logs",
    "audit",
    // Next.js / Framework
    "app",
    "image",
    "_next",
    "static",
    "chunks",
    "server",
];

/// Detect if a URL segment looks like an ID parameter
fn looks_like_id_segment(segment: &str) -> Option<&'static str> {
    let segment_lower = segment.to_lowercase();

    // First, exclude known resource names - these are NOT IDs
    if KNOWN_RESOURCE_NAMES.contains(&segment_lower.as_str()) {
        return None;
    }

    // Check for common numeric test IDs
    if PARAM_ID_VALUES.contains(&segment) {
        return Some("{id}");
    }

    // Check for UUID patterns
    if UUID_PATTERNS.contains(&segment) {
        return Some("{uuid}");
    }

    // Check for numeric ID
    if segment.parse::<i64>().is_ok() {
        return Some("{id}");
    }

    // Check for UUID format (8-4-4-4-12)
    if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Some("{uuid}");
        }
    }

    // Check for MongoDB ObjectId (24 hex chars)
    if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("{objectId}");
    }

    // Check for hash-like strings (long alphanumeric)
    if segment.len() > 16 && segment.chars().all(|c| c.is_alphanumeric()) {
        return Some("{hash}");
    }

    None
}

/// Detect if a URL is parameterized and return the pattern
pub fn detect_parameterized_endpoint(url: &str) -> (bool, Option<String>) {
    // Parse the path from the URL
    let path = if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            &after_scheme[path_idx..]
        } else {
            return (false, None);
        }
    } else if url.starts_with('/') {
        url
    } else {
        return (false, None);
    };

    // Remove query string if present
    let path = path.split('?').next().unwrap_or(path);

    // Split into segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return (false, None);
    }

    // Check each segment for parameterization
    let mut is_parameterized = false;
    let mut pattern_segments = Vec::new();

    for segment in segments {
        if let Some(param_type) = looks_like_id_segment(segment) {
            is_parameterized = true;
            pattern_segments.push(param_type.to_string());
        } else {
            pattern_segments.push(segment.to_string());
        }
    }

    if is_parameterized {
        let pattern = format!("/{}", pattern_segments.join("/"));
        (true, Some(pattern))
    } else {
        (false, None)
    }
}

// =============================================================================
// ROUTE EXISTENCE & CONSOLIDATION
// =============================================================================

/// Check if a status code indicates the route EXISTS (not just 200)
/// 404 = route does NOT exist, everything else = route exists
fn is_existence_signal(status: u16) -> bool {
    matches!(
        status,
        200..=204 | 301 | 302 | 307 | 308 | 400 | 401 | 403 | 405 | 500 | 502 | 503
    )
}

/// Check if URL is framework junk that should never appear in output
fn is_framework_junk(url: &str) -> bool {
    let junk_patterns = [
        "/_next/static/",
        "/node_modules/",
        "/chunks/",
        "/.next/",
        "/turbopack",
        "/favicon.ico",
        ".development.js",
        ".production.js",
        "/layout.tsx",
        "/_not-found",
        "/image/x-icon",
    ];
    let url_lower = url.to_lowercase();
    junk_patterns.iter().any(|p| url_lower.contains(p))
}

/// A consolidated route that groups parameterized variants
#[derive(Debug, Clone)]
struct ConsolidatedRoute {
    /// The templated pattern (e.g., "/api/products/{id}")
    pattern: String,
    /// Representative status code
    status_code: u16,
    /// Representative content length
    content_length: u64,
    /// How many concrete URLs matched this pattern
    variant_count: usize,
    /// One concrete example URL
    example_url: String,
}

/// Templatize a URL path - replace ID-like segments with placeholders
fn templatize_path(url: &str) -> String {
    // Extract just the path portion
    let path = if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            &after_scheme[path_idx..]
        } else {
            "/"
        }
    } else {
        url
    };

    // Remove query string
    let path = path.split('?').next().unwrap_or(path);

    // Split and templatize segments
    let segments: Vec<&str> = path.split('/').collect();
    let templated: Vec<String> = segments
        .iter()
        .map(|seg| {
            if seg.is_empty() {
                String::new()
            } else if seg.parse::<i64>().is_ok() {
                "{id}".to_string()
            } else if is_uuid_segment(seg) {
                "{uuid}".to_string()
            } else if is_objectid_segment(seg) {
                "{objectId}".to_string()
            } else {
                (*seg).to_string()
            }
        })
        .collect();

    templated.join("/")
}

fn is_uuid_segment(seg: &str) -> bool {
    if seg.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn is_objectid_segment(seg: &str) -> bool {
    seg.len() == 24 && seg.chars().all(|c| c.is_ascii_hexdigit())
}

/// Consolidate endpoints by their templated pattern
fn consolidate_routes(endpoints: &[&DiscoveredEndpoint]) -> Vec<ConsolidatedRoute> {
    let mut by_pattern: HashMap<(String, u16), Vec<&DiscoveredEndpoint>> = HashMap::new();

    for ep in endpoints {
        let pattern = templatize_path(&ep.url);
        // Group by pattern AND status code
        let key = (pattern, ep.status_code);
        by_pattern.entry(key).or_default().push(ep);
    }

    let mut result: Vec<ConsolidatedRoute> = by_pattern
        .into_iter()
        .map(|((pattern, status_code), eps)| ConsolidatedRoute {
            pattern,
            status_code,
            content_length: eps[0].content_length,
            variant_count: eps.len(),
            example_url: eps[0].url.clone(),
        })
        .collect();

    // Sort by status code, then by pattern
    result.sort_by(|a, b| {
        a.status_code
            .cmp(&b.status_code)
            .then_with(|| a.pattern.cmp(&b.pattern))
    });

    result
}

/// Categorize routes by their status meaning
#[derive(Default)]
struct CategorizedRoutes {
    confirmed: Vec<ConsolidatedRoute>,       // 2xx
    auth_required: Vec<ConsolidatedRoute>,   // 401, 403
    method_mismatch: Vec<ConsolidatedRoute>, // 405
    server_error: Vec<ConsolidatedRoute>,    // 5xx
    redirects: Vec<ConsolidatedRoute>,       // 3xx
    other: Vec<ConsolidatedRoute>,           // 400, etc.
}

/// Canonical endpoint with merged status codes and annotations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEndpoint {
    /// The templated path pattern (e.g., "/api/products/{id}")
    pub path: String,
    /// Annotation describing the endpoint status (e.g., "(auth required)")
    pub annotation: Option<String>,
    /// Confirmed methods via empirical probing (response != 404/405)
    pub confirmed_methods: Option<Vec<String>>,
    /// Allow header hint (not trusted as truth)
    pub allow_hint: Option<Vec<String>>,
    /// Methods that require auth (401/403)
    pub auth_required_methods: Option<Vec<String>>,
    /// All status codes seen for this endpoint
    pub status_seen: Vec<u16>,
    /// Primary status (strongest signal)
    pub primary_status: u16,
    /// Number of concrete URL variants collapsed into this pattern
    pub variant_count: usize,
    /// Whether this matches wildcard behavior (should be suppressed)
    pub is_wildcard: bool,
    /// Whether this is a catch-all param route under a wildcard prefix
    pub is_catch_all_param: bool,
    /// Observed parameter values that hit this route (for fuzzing reference)
    pub observed_param_values: Vec<String>,
}

/// Priority for status codes when merging (higher = stronger signal)
fn status_priority(status: u16) -> u8 {
    match status {
        200..=204 => 10,            // Confirmed exists
        301 | 302 | 307 | 308 => 8, // Redirects
        401 | 403 => 6,             // Auth required
        405 => 4,                   // Method mismatch
        500..=599 => 2,             // Server error
        400 => 1,                   // Client error (needs params)
        _ => 0,
    }
}

/// Get annotation for a status code
fn get_status_annotation(status: u16) -> Option<String> {
    match status {
        200..=204 => None, // No annotation needed for success
        301 | 302 | 307 | 308 => Some("(redirects)".to_string()),
        401 => Some("(auth required)".to_string()),
        403 => Some("(forbidden)".to_string()),
        405 => Some("(method mismatch)".to_string()),
        500..=599 => Some("(server error)".to_string()),
        400 => Some("(expects params)".to_string()),
        _ => None,
    }
}

/// Normalize a path (remove double slashes, trailing slashes for non-root)
fn normalize_path(path: &str) -> String {
    // Replace multiple slashes with single slash
    let mut normalized = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");

    // Ensure it starts with /
    if !normalized.starts_with('/') {
        normalized = format!("/{}", normalized);
    }

    // Remove trailing slash unless it's the root
    if normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }

    normalized
}

/// Check if a path is a canonical API path (not internal Next.js junk)
fn is_canonical_api_path(path: &str) -> bool {
    // Include explicit API paths and common UI routes
    let api_patterns = ["/api/", "/admin", "/auth", "/login", "/logout", "/graphql"];

    // Exclude Next.js internals and redirect artifacts
    let exclude_patterns = [
        "/_next/",
        "/app/",
        "/image/",
        "/__nextjs",
        "/static/chunks/",
        "/webpack",
    ];

    // Check exclusions first
    if exclude_patterns.iter().any(|p| path.contains(p)) {
        return false;
    }

    // Check if it's an API-like path
    api_patterns.iter().any(|p| path.contains(p)) || path == "/"
}

/// Extract the last path segment from a URL (the parameter value)
fn extract_last_segment(url: &str) -> Option<String> {
    let path = if let Some(idx) = url.find("://") {
        let after_scheme = &url[idx + 3..];
        if let Some(path_idx) = after_scheme.find('/') {
            &after_scheme[path_idx..]
        } else {
            return None;
        }
    } else if url.starts_with('/') {
        url
    } else {
        return None;
    };

    // Remove query string
    let path = path.split('?').next().unwrap_or(path);

    // Get last segment
    path.split('/')
        .rfind(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Check if a path segment is a fixed child (not a parameter placeholder)
fn is_fixed_child(segment: &str) -> bool {
    !segment.starts_with('{') && !segment.ends_with('}')
}

/// Generate canonical endpoint inventory from discovered endpoints
/// This version is wildcard-aware and suppresses fixed children under wildcard prefixes
pub fn generate_canonical_inventory(endpoints: &[DiscoveredEndpoint]) -> Vec<CanonicalEndpoint> {
    generate_canonical_inventory_with_wildcards(endpoints, &std::collections::HashSet::new())
}

/// Generate canonical endpoint inventory with wildcard prefix awareness
pub fn generate_canonical_inventory_with_wildcards(
    endpoints: &[DiscoveredEndpoint],
    wildcard_prefixes: &std::collections::HashSet<String>,
) -> Vec<CanonicalEndpoint> {
    // Filter to existence signals and non-junk
    let valid: Vec<_> = endpoints
        .iter()
        .filter(|e| is_existence_signal(e.status_code))
        .filter(|e| !is_framework_junk(&e.url))
        .collect();

    // Group by templated path pattern, also tracking original URLs for param extraction
    let mut by_pattern: HashMap<String, Vec<&DiscoveredEndpoint>> = HashMap::new();
    for ep in &valid {
        let pattern = templatize_path(&ep.url);
        let normalized = normalize_path(&pattern);
        by_pattern.entry(normalized).or_default().push(ep);
    }

    // Identify which patterns are under wildcard prefixes
    // A "fixed child" under a wildcard prefix should be suppressed
    // Only templated paths ({id}, {uuid}) should remain
    let mut result: Vec<CanonicalEndpoint> = Vec::new();

    for (pattern, eps) in by_pattern.into_iter() {
        // Skip non-API paths
        if !is_canonical_api_path(&pattern) {
            continue;
        }

        // Skip redirect-only entries
        if eps
            .iter()
            .all(|e| matches!(e.status_code, 301 | 302 | 307 | 308))
        {
            continue;
        }

        let variant_count = eps.len();

        // Check if this pattern is a fixed child under a wildcard prefix
        let mut is_fixed_under_wildcard = false;

        for prefix in wildcard_prefixes {
            // Check if pattern starts with this wildcard prefix
            if pattern.starts_with(prefix) && pattern.len() > prefix.len() {
                let suffix = &pattern[prefix.len()..];
                // Get the first segment after the prefix
                let first_seg = suffix
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("");

                // If it's a fixed segment (not {id}, {uuid}, etc.), it's a fixed child
                if is_fixed_child(first_seg) && !first_seg.is_empty() {
                    is_fixed_under_wildcard = true;
                    break;
                }
            }
        }

        // Skip fixed children under wildcard prefixes (e.g., /api/products/all, /api/products/search)
        if is_fixed_under_wildcard {
            continue;
        }

        // Check if this is a templated path under a wildcard prefix (catch-all param route)
        let is_catch_all = wildcard_prefixes.iter().any(|prefix| {
            if pattern.starts_with(prefix) && pattern.len() > prefix.len() {
                let suffix = &pattern[prefix.len()..];
                let first_seg = suffix
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("");
                // It's a catch-all if the first segment is a template like {id}
                first_seg.starts_with('{') && first_seg.ends_with('}')
            } else {
                false
            }
        });

        // Extract observed parameter values for templated paths
        let mut observed_param_values: Vec<String> = Vec::new();
        if pattern.contains("/{") {
            for ep in &eps {
                if let Some(last_seg) = extract_last_segment(&ep.url) {
                    // Don't include template placeholders or known resource names
                    if !last_seg.starts_with('{')
                        && !KNOWN_RESOURCE_NAMES.contains(&last_seg.to_lowercase().as_str())
                    {
                        observed_param_values.push(last_seg);
                    }
                }
            }
            observed_param_values.sort();
            observed_param_values.dedup();
        }

        // Collect all unique status codes
        let mut status_seen: Vec<u16> = eps.iter().map(|e| e.status_code).collect();
        status_seen.sort();
        status_seen.dedup();

        // Determine primary status (highest priority)
        let primary_status = status_seen
            .iter()
            .max_by_key(|&&s| status_priority(s))
            .copied()
            .unwrap_or(200);

        let annotation = get_status_annotation(primary_status);

        result.push(CanonicalEndpoint {
            path: pattern,
            annotation,
            confirmed_methods: None,
            allow_hint: None,
            auth_required_methods: None,
            status_seen,
            primary_status,
            variant_count,
            is_wildcard: false,
            is_catch_all_param: is_catch_all,
            observed_param_values,
        });
    }

    // Sort by path
    result.sort_by(|a, b| a.path.cmp(&b.path));

    result
}

fn categorize_routes(routes: Vec<ConsolidatedRoute>) -> CategorizedRoutes {
    let mut cat = CategorizedRoutes::default();

    for route in routes {
        match route.status_code {
            200..=204 => cat.confirmed.push(route),
            301 | 302 | 307 | 308 => cat.redirects.push(route),
            401 | 403 => cat.auth_required.push(route),
            405 => cat.method_mismatch.push(route),
            500..=599 => cat.server_error.push(route),
            _ => cat.other.push(route),
        }
    }

    cat
}

// =============================================================================
// RECON DISPLAY FILTERING
// =============================================================================

/// Check if a recon URL is noise that shouldn't be displayed
fn is_recon_display_noise(url: &str) -> bool {
    let url_lower = url.to_lowercase();

    // Framework internals - never useful for pentesting
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

    // Static file extensions - not API endpoints
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

/// Colorize status code matching feroxbuster's style
fn colorize_status_code(code: u16) -> String {
    let code_str = code.to_string();
    match code {
        100..=199 => style(code_str).blue().to_string(), // informational
        200..=299 => style(code_str).green().to_string(), // success
        300..=399 => style(code_str).yellow().to_string(), // redirects
        400..=499 => style(code_str).red().to_string(),  // client error
        500..=599 => style(code_str).red().to_string(),  // server error
        _ => code_str,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_templatize_path() {
        // Numeric IDs become {id}
        assert_eq!(templatize_path("/api/products/1"), "/api/products/{id}");
        assert_eq!(templatize_path("/api/products/123"), "/api/products/{id}");
        assert_eq!(
            templatize_path("http://localhost:3000/api/users/42"),
            "/api/users/{id}"
        );

        // UUIDs become {uuid}
        assert_eq!(
            templatize_path("/api/items/00000000-0000-0000-0000-000000000001"),
            "/api/items/{uuid}"
        );

        // Non-parameterized paths stay the same
        assert_eq!(templatize_path("/api/products"), "/api/products");
        assert_eq!(templatize_path("/api/admin/users"), "/api/admin/users");
    }

    #[test]
    fn test_is_existence_signal() {
        // 404 is NOT an existence signal
        assert!(!is_existence_signal(404));

        // These indicate route exists
        assert!(is_existence_signal(200));
        assert!(is_existence_signal(201));
        assert!(is_existence_signal(401));
        assert!(is_existence_signal(403));
        assert!(is_existence_signal(405));
        assert!(is_existence_signal(500));
        assert!(is_existence_signal(308));
    }

    #[test]
    fn test_is_framework_junk() {
        assert!(is_framework_junk("/_next/static/chunks/main.js"));
        assert!(is_framework_junk("/node_modules/react/index.js"));
        assert!(is_framework_junk(
            "/api/debug/auth/_next/static/chunks/something"
        ));
        assert!(!is_framework_junk("/api/products"));
        assert!(!is_framework_junk("/admin"));
    }

    #[test]
    fn test_consolidate_routes() {
        let endpoints = [
            DiscoveredEndpoint {
                url: "http://localhost/api/products/1".to_string(),
                status_code: 405,
                content_length: 0,
                content_type: None,
                interesting: true,
                pentest_score: 2,
                notes: vec![],
                is_parameterized: true,
                param_pattern: Some("/api/products/{id}".to_string()),
            },
            DiscoveredEndpoint {
                url: "http://localhost/api/products/2".to_string(),
                status_code: 405,
                content_length: 0,
                content_type: None,
                interesting: true,
                pentest_score: 2,
                notes: vec![],
                is_parameterized: true,
                param_pattern: Some("/api/products/{id}".to_string()),
            },
            DiscoveredEndpoint {
                url: "http://localhost/api/products/3".to_string(),
                status_code: 405,
                content_length: 0,
                content_type: None,
                interesting: true,
                pentest_score: 2,
                notes: vec![],
                is_parameterized: true,
                param_pattern: Some("/api/products/{id}".to_string()),
            },
        ];

        let refs: Vec<&DiscoveredEndpoint> = endpoints.iter().collect();
        let consolidated = consolidate_routes(&refs);

        // Should consolidate to 1 entry
        assert_eq!(consolidated.len(), 1);
        assert_eq!(consolidated[0].pattern, "/api/products/{id}");
        assert_eq!(consolidated[0].variant_count, 3);
    }

    #[test]
    fn test_pentest_scoring_high_value() {
        // API endpoint with 403 = high value (input + non-200 + server-side + admin)
        let (interesting, score, notes) = PentestReport::is_interesting("/api/admin", 403, None);
        assert!(interesting);
        assert!(score >= 4);
        assert!(!notes.is_empty());

        // Git config = high value
        let (interesting, score, _) = PentestReport::is_interesting("/.git/config", 200, None);
        assert!(interesting);
        assert!(score >= 4);

        // GraphQL endpoint = high value
        let (interesting, score, _) =
            PentestReport::is_interesting("/graphql", 200, Some("application/json"));
        assert!(interesting);
        assert!(score >= 4);

        // Next.js image loader with 400 = high value (SSRF potential)
        let (interesting, score, notes) = PentestReport::is_interesting("/_next/image", 400, None);
        assert!(interesting);
        assert!(score >= 4);
        assert!(notes.iter().any(|n| n.contains("SSRF")));
    }

    #[test]
    fn test_pentest_scoring_low_value() {
        // Normal 404 = not interesting
        let (interesting, score, _) = PentestReport::is_interesting("/normal/path", 404, None);
        assert!(!interesting);
        assert!(score < 4);

        // Static JS file = noise
        let (interesting, score, _) =
            PentestReport::is_interesting("/_next/static/chunks/main.js", 200, None);
        assert!(!interesting);
        assert!(score < 0); // Negative score for static assets
    }

    #[test]
    fn test_static_asset_filtering() {
        assert!(is_static_asset("/_next/static/chunks/main.js"));
        assert!(is_static_asset("/static/css/style.css"));
        assert!(is_static_asset("/fonts/roboto.woff2"));
        assert!(is_static_asset("/images/logo.png"));
        assert!(!is_static_asset("/api/users"));
        assert!(!is_static_asset("/graphql"));
        assert!(!is_static_asset("/admin"));
    }

    #[test]
    fn test_dev_internal_detection() {
        assert!(is_dev_or_internal("/__nextjs_original-stack-frame"));
        assert!(is_dev_or_internal("/actuator/env"));
        assert!(is_dev_or_internal("/debug/pprof"));
        assert!(is_dev_or_internal("/internal/api"));
        assert!(!is_dev_or_internal("/api/users"));
        assert!(!is_dev_or_internal("/public/data"));
    }

    #[test]
    fn test_auth_detection() {
        assert!(is_auth_related("/api/auth/login"));
        assert!(is_auth_related("/oauth/callback"));
        assert!(is_auth_related("/.well-known/openid-configuration"));
        assert!(!is_auth_related("/api/users"));
    }

    #[test]
    fn test_canonical_inventory_merges_status_codes() {
        let endpoints = vec![
            DiscoveredEndpoint {
                url: "http://localhost/api/products/1".to_string(),
                status_code: 405,
                content_length: 0,
                content_type: None,
                interesting: true,
                pentest_score: 2,
                notes: vec![],
                is_parameterized: true,
                param_pattern: Some("/api/products/{id}".to_string()),
            },
            DiscoveredEndpoint {
                url: "http://localhost/api/products/2".to_string(),
                status_code: 200,
                content_length: 100,
                content_type: None,
                interesting: true,
                pentest_score: 4,
                notes: vec![],
                is_parameterized: true,
                param_pattern: Some("/api/products/{id}".to_string()),
            },
        ];

        let inventory = generate_canonical_inventory(&endpoints);

        // Should consolidate to 1 entry with merged status codes
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].path, "/api/products/{id}");
        // Primary status should be 200 (highest priority)
        assert_eq!(inventory[0].primary_status, 200);
        // Both status codes should be recorded
        assert!(inventory[0].status_seen.contains(&200));
        assert!(inventory[0].status_seen.contains(&405));
        // No annotation for 200
        assert!(inventory[0].annotation.is_none());
        // Variant count should be 2
        assert_eq!(inventory[0].variant_count, 2);
    }

    #[test]
    fn test_canonical_inventory_annotation_auth_required() {
        let endpoints = vec![DiscoveredEndpoint {
            url: "http://localhost/api/orders".to_string(),
            status_code: 401,
            content_length: 0,
            content_type: None,
            interesting: true,
            pentest_score: 2,
            notes: vec![],
            is_parameterized: false,
            param_pattern: None,
        }];

        let inventory = generate_canonical_inventory(&endpoints);

        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].annotation, Some("(auth required)".to_string()));
    }

    #[test]
    fn test_canonical_inventory_annotation_method_mismatch() {
        let endpoints = vec![DiscoveredEndpoint {
            url: "http://localhost/api/login".to_string(),
            status_code: 405,
            content_length: 0,
            content_type: None,
            interesting: true,
            pentest_score: 2,
            notes: vec![],
            is_parameterized: false,
            param_pattern: None,
        }];

        let inventory = generate_canonical_inventory(&endpoints);

        assert_eq!(inventory.len(), 1);
        assert_eq!(
            inventory[0].annotation,
            Some("(method mismatch)".to_string())
        );
    }

    #[test]
    fn test_canonical_inventory_filters_404() {
        let endpoints = vec![
            DiscoveredEndpoint {
                url: "http://localhost/api/products".to_string(),
                status_code: 200,
                content_length: 100,
                content_type: None,
                interesting: true,
                pentest_score: 4,
                notes: vec![],
                is_parameterized: false,
                param_pattern: None,
            },
            DiscoveredEndpoint {
                url: "http://localhost/nonexistent".to_string(),
                status_code: 404,
                content_length: 0,
                content_type: None,
                interesting: false,
                pentest_score: 0,
                notes: vec![],
                is_parameterized: false,
                param_pattern: None,
            },
        ];

        let inventory = generate_canonical_inventory(&endpoints);

        // Should only include the 200 response, not the 404
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].path, "/api/products");
    }

    #[test]
    fn test_status_priority_ordering() {
        // 200 should have highest priority
        assert!(status_priority(200) > status_priority(401));
        assert!(status_priority(200) > status_priority(405));
        assert!(status_priority(200) > status_priority(500));

        // 401/403 > 405
        assert!(status_priority(401) > status_priority(405));
        assert!(status_priority(403) > status_priority(405));

        // 405 > 500
        assert!(status_priority(405) > status_priority(500));

        // Redirects are high priority
        assert!(status_priority(301) > status_priority(401));
    }
}
