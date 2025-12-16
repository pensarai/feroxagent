//! HTTP probing functionality for gathering additional context
//!
//! Makes requests to discovered URLs to gather more information
//! about the target application (headers, response patterns, etc.)
//!
//! Includes behavioral analysis through method variation and header mutation.

use anyhow::Result;
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::time::Duration;

/// Information gathered from probing a URL
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub url: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub content_type: Option<String>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub content_length: Option<u64>,
    /// Results from method variation testing (if performed)
    pub method_variations: Option<MethodVariations>,
    /// Results from header mutation testing (if performed)
    pub header_mutations: Option<HeaderMutationResults>,
}

/// Results of testing different HTTP methods on an endpoint
#[derive(Debug, Clone)]
pub struct MethodVariations {
    pub get_status: Option<u16>,
    pub post_status: Option<u16>,
    pub put_status: Option<u16>,
    pub delete_status: Option<u16>,
    pub options_status: Option<u16>,
    /// Methods that returned different status codes than HEAD
    pub interesting_methods: Vec<String>,
}

/// Results of header mutation testing
#[derive(Debug, Clone)]
pub struct HeaderMutationResults {
    /// Findings from header tests (header -> effect)
    pub findings: Vec<String>,
}

/// Probe a list of URLs to gather additional context
pub async fn probe_urls(
    urls: &[String],
    client: &Client,
    max_probes: usize,
) -> Result<Vec<ProbeResult>> {
    let mut results = Vec::new();

    // Select a diverse set of URLs to probe
    let urls_to_probe = select_urls_to_probe(urls, max_probes);

    for url in urls_to_probe {
        match probe_single_url(&url, client).await {
            Ok(result) => results.push(result),
            Err(e) => {
                log::debug!("Failed to probe {}: {}", url, e);
            }
        }
    }

    Ok(results)
}

/// Select a diverse set of URLs to probe (prioritize interesting endpoints)
fn select_urls_to_probe(urls: &[String], max_probes: usize) -> Vec<String> {
    let mut selected = Vec::new();
    let mut seen_patterns = std::collections::HashSet::new();

    // Priority 1: API endpoints
    for url in urls {
        if selected.len() >= max_probes {
            break;
        }
        if url.contains("/api/") || url.contains("/v1/") || url.contains("/v2/") {
            let pattern = extract_url_pattern(url);
            if seen_patterns.insert(pattern) {
                selected.push(url.clone());
            }
        }
    }

    // Priority 2: Root and common endpoints
    for url in urls {
        if selected.len() >= max_probes {
            break;
        }
        if let Ok(parsed) = url::Url::parse(url) {
            let path = parsed.path();
            if path == "/" || path == "/index.html" || path == "/robots.txt" {
                let pattern = extract_url_pattern(url);
                if seen_patterns.insert(pattern) {
                    selected.push(url.clone());
                }
            }
        }
    }

    // Priority 3: Any other unique patterns
    for url in urls {
        if selected.len() >= max_probes {
            break;
        }
        let pattern = extract_url_pattern(url);
        if seen_patterns.insert(pattern) {
            selected.push(url.clone());
        }
    }

    selected
}

/// Extract a pattern from URL for deduplication
fn extract_url_pattern(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        let path = parsed.path();
        // Replace numeric IDs with placeholder
        let pattern: String = path
            .split('/')
            .map(|part| {
                if part.parse::<u64>().is_ok() {
                    "{id}"
                } else if part.len() > 20 {
                    "{hash}"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join("/");
        format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or(""),
            pattern
        )
    } else {
        url.to_string()
    }
}

async fn probe_single_url(url: &str, client: &Client) -> Result<ProbeResult> {
    let response = client
        .head(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    let status_code = response.status().as_u16();
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let content_type = headers.get("content-type").cloned();
    let server = headers.get("server").cloned();
    let powered_by = headers.get("x-powered-by").cloned();
    let content_length = headers.get("content-length").and_then(|v| v.parse().ok());

    // Test method variations for interesting endpoints
    let method_variations = if should_test_methods(url, status_code) {
        test_method_variations(url, client, status_code).await.ok()
    } else {
        None
    };

    // Test header mutations for endpoints that might have auth/access control
    let header_mutations = if should_test_headers(url, status_code) {
        test_header_mutations(url, client, status_code).await.ok()
    } else {
        None
    };

    Ok(ProbeResult {
        url: url.to_string(),
        status_code,
        headers,
        content_type,
        server,
        powered_by,
        content_length,
        method_variations,
        header_mutations,
    })
}

/// Determine if we should test method variations on this URL
fn should_test_methods(url: &str, status_code: u16) -> bool {
    // Test methods on:
    // - API endpoints
    // - Endpoints that returned 405 (Method Not Allowed)
    // - Endpoints that returned 400 (may need different method)
    // - Auth endpoints
    let url_lower = url.to_lowercase();

    status_code == 405
        || status_code == 400
        || url_lower.contains("/api/")
        || url_lower.contains("/graphql")
        || url_lower.contains("/auth")
        || url_lower.contains("/login")
        || url_lower.contains("/upload")
        || url_lower.contains("/webhook")
}

/// Test different HTTP methods on an endpoint
async fn test_method_variations(
    url: &str,
    client: &Client,
    head_status: u16,
) -> Result<MethodVariations> {
    let timeout = Duration::from_secs(5);
    let mut interesting = Vec::new();

    // Test GET
    let get_status = client
        .get(url)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .ok();
    if let Some(status) = get_status {
        if status != head_status && is_interesting_status_diff(head_status, status) {
            interesting.push(format!("GET:{}", status));
        }
    }

    // Test POST
    let post_status = client
        .post(url)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .ok();
    if let Some(status) = post_status {
        if status != head_status && is_interesting_status_diff(head_status, status) {
            interesting.push(format!("POST:{}", status));
        }
    }

    // Test PUT
    let put_status = client
        .put(url)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .ok();
    if let Some(status) = put_status {
        if status != head_status && is_interesting_status_diff(head_status, status) {
            interesting.push(format!("PUT:{}", status));
        }
    }

    // Test DELETE
    let delete_status = client
        .delete(url)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .ok();
    if let Some(status) = delete_status {
        if status != head_status && is_interesting_status_diff(head_status, status) {
            interesting.push(format!("DELETE:{}", status));
        }
    }

    // Test OPTIONS (for CORS info)
    let options_status = client
        .request(Method::OPTIONS, url)
        .timeout(timeout)
        .send()
        .await
        .map(|r| r.status().as_u16())
        .ok();
    if let Some(status) = options_status {
        if status == 200 || status == 204 {
            interesting.push(format!("OPTIONS:{} (CORS)", status));
        }
    }

    Ok(MethodVariations {
        get_status,
        post_status,
        put_status,
        delete_status,
        options_status,
        interesting_methods: interesting,
    })
}

/// Check if a status code difference is interesting
fn is_interesting_status_diff(baseline: u16, new_status: u16) -> bool {
    // Interesting transitions:
    // - 405 -> 200/201/204 (method was wrong)
    // - 403 -> 200 (auth bypass via method)
    // - 404 -> 200 (endpoint exists with different method)
    // - Any -> 500 (potential injection point)

    match (baseline, new_status) {
        (405, 200 | 201 | 204 | 400 | 401) => true, // Method was correct, different response
        (403, 200 | 201 | 204) => true,             // Potential auth bypass
        (404, 200 | 201 | 204 | 400 | 401) => true, // Endpoint exists
        (_, 500 | 502 | 503) => true,               // Server error - potential vuln
        _ => false,
    }
}

// =============================================================================
// HEADER MUTATION TESTING
// =============================================================================

/// Determine if we should test header mutations on this URL
fn should_test_headers(url: &str, status_code: u16) -> bool {
    // Test headers on:
    // - 401/403 responses (auth bypass potential)
    // - Admin/internal paths
    // - API endpoints
    let url_lower = url.to_lowercase();

    status_code == 401
        || status_code == 403
        || url_lower.contains("/admin")
        || url_lower.contains("/internal")
        || url_lower.contains("/private")
        || url_lower.contains("/api/")
        || url_lower.contains("/manage")
}

/// Test different header mutations to detect access control issues
async fn test_header_mutations(
    url: &str,
    client: &Client,
    baseline_status: u16,
) -> Result<HeaderMutationResults> {
    let timeout = Duration::from_secs(5);
    let mut findings = Vec::new();

    // Headers commonly used in access control bypass
    let header_tests = [
        // Localhost/internal IP spoofing
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-For", "localhost"),
        ("X-Real-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Client-IP", "127.0.0.1"),
        // Host header attacks
        ("X-Forwarded-Host", "localhost"),
        // Misc bypass headers
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Original-URL", "/"),
        ("X-Rewrite-URL", "/"),
        // Admin bypass
        ("X-Forwarded-For", "10.0.0.1"),
        ("X-Forwarded-For", "192.168.1.1"),
    ];

    for (header_name, header_value) in &header_tests {
        let response = client
            .get(url)
            .header(*header_name, *header_value)
            .timeout(timeout)
            .send()
            .await;

        if let Ok(resp) = response {
            let new_status = resp.status().as_u16();
            // If status changed from 401/403 to 200, that's a finding
            if is_header_bypass(baseline_status, new_status) {
                findings.push(format!(
                    "{}: {} -> {} (potential bypass!)",
                    header_name, baseline_status, new_status
                ));
            }
        }
    }

    // Test path traversal via headers (X-Original-URL, X-Rewrite-URL)
    if baseline_status == 403 || baseline_status == 401 {
        // Try accessing root via header override
        let response = client
            .get(url)
            .header("X-Original-URL", "/admin")
            .timeout(timeout)
            .send()
            .await;

        if let Ok(resp) = response {
            let new_status = resp.status().as_u16();
            if new_status == 200 {
                findings.push("X-Original-URL header may allow path bypass".to_string());
            }
        }
    }

    Ok(HeaderMutationResults { findings })
}

/// Check if a status change indicates a header-based bypass
fn is_header_bypass(baseline: u16, new_status: u16) -> bool {
    match (baseline, new_status) {
        (401, 200) | (403, 200) => true, // Auth bypass
        (401, 302) | (403, 302) => true, // Redirect (might be to success page)
        (404, 200) => true,              // Hidden endpoint revealed
        _ => false,
    }
}

// =============================================================================
// OPTIONS METHOD DISCOVERY
// =============================================================================

/// Result of OPTIONS discovery for a single endpoint
#[derive(Debug, Clone)]
pub struct OptionsResult {
    /// The path pattern
    pub path: String,
    /// Allowed methods from the Allow header
    pub allowed_methods: Vec<String>,
    /// Whether the OPTIONS request succeeded
    pub success: bool,
}

/// Discover allowed HTTP methods for a list of endpoints using OPTIONS requests
///
/// This is used as a post-scan verification step for 405 Method Not Allowed responses.
/// The Allow header tells us which methods the server actually accepts.
pub async fn discover_methods(
    endpoints: &[String],
    base_url: &str,
    client: &Client,
    concurrency: usize,
) -> HashMap<String, Vec<String>> {
    use futures::stream::{self, StreamExt};

    let base = base_url.trim_end_matches('/').to_string();

    let results: Vec<_> = stream::iter(endpoints)
        .map(|path| {
            let base = base.clone();
            let path = path.clone();
            let client = client.clone();
            async move {
                let url = format!("{}{}", base, path);
                options_request(&url, &path, &client).await
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    // Build the map of path -> methods
    let mut method_map: HashMap<String, Vec<String>> = HashMap::new();

    for result in results.into_iter().flatten() {
        if result.success && !result.allowed_methods.is_empty() {
            method_map.insert(result.path, result.allowed_methods);
        }
    }

    if !method_map.is_empty() {
        log::info!(
            "OPTIONS discovery found methods for {} endpoints",
            method_map.len()
        );
    }

    method_map
}

/// Send an OPTIONS request and parse the Allow header
async fn options_request(url: &str, path: &str, client: &Client) -> Option<OptionsResult> {
    let timeout = Duration::from_secs(5);

    let response = client
        .request(Method::OPTIONS, url)
        .timeout(timeout)
        .send()
        .await
        .ok()?;

    let status = response.status().as_u16();

    // OPTIONS should return 200, 204, or 405 with Allow header
    if status != 200 && status != 204 && status != 405 {
        return Some(OptionsResult {
            path: path.to_string(),
            allowed_methods: vec![],
            success: false,
        });
    }

    // Parse the Allow header
    let allowed_methods = response
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .map(|header| {
            header
                .split(',')
                .map(|m| m.trim().to_uppercase())
                .filter(|m| !m.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(OptionsResult {
        path: path.to_string(),
        allowed_methods,
        success: true,
    })
}

/// Discover methods for endpoints that returned 405 (Method Not Allowed)
/// This is the main entry point for post-scan OPTIONS discovery
pub async fn discover_methods_for_405s(
    endpoints: &[super::report::CanonicalEndpoint],
    base_url: &str,
    client: &Client,
) -> HashMap<String, Vec<String>> {
    // Filter to only 405 endpoints
    let paths_405: Vec<String> = endpoints
        .iter()
        .filter(|e| e.status_seen.contains(&405))
        .map(|e| e.path.clone())
        .collect();

    if paths_405.is_empty() {
        return HashMap::new();
    }

    log::info!(
        "Running OPTIONS discovery on {} endpoints with 405 status",
        paths_405.len()
    );

    discover_methods(&paths_405, base_url, client, 10).await
}

// =============================================================================
// WILDCARD 405 FINGERPRINTING
// =============================================================================

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Fingerprint for detecting wildcard/catch-all router behavior
#[derive(Debug, Clone)]
pub struct WildcardFingerprint {
    /// The prefix being fingerprinted (e.g., "/api/products/")
    pub prefix: String,
    /// GET request fingerprint
    pub get_fingerprint: Option<ResponseFingerprint>,
    /// OPTIONS request fingerprint
    pub options_fingerprint: Option<ResponseFingerprint>,
}

/// Fingerprint of a single HTTP response
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseFingerprint {
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body_hash: u64,
    pub allow_header: Option<String>,
}

impl ResponseFingerprint {
    /// Check if two fingerprints match (indicating wildcard behavior)
    pub fn matches(&self, other: &ResponseFingerprint) -> bool {
        // Status must match
        if self.status != other.status {
            return false;
        }

        // If both have body hashes, they must match
        if self.body_hash != 0 && other.body_hash != 0 && self.body_hash != other.body_hash {
            return false;
        }

        // If both have content types, they should match
        if let (Some(ref ct1), Some(ref ct2)) = (&self.content_type, &other.content_type) {
            if ct1 != ct2 {
                return false;
            }
        }

        // If both have Allow headers (for OPTIONS), they must match
        if let (Some(ref a1), Some(ref a2)) = (&self.allow_header, &other.allow_header) {
            if a1 != a2 {
                return false;
            }
        }

        true
    }
}

/// Generate a canary path for fingerprinting
fn generate_canary_path(prefix: &str) -> String {
    let uuid = uuid::Uuid::new_v4();
    format!("{}.ferox_canary_{}", prefix.trim_end_matches('/'), uuid)
}

/// Hash the first N bytes of a body for fingerprinting
fn hash_body(body: &[u8], max_bytes: usize) -> u64 {
    let mut hasher = DefaultHasher::new();
    let slice = if body.len() > max_bytes {
        &body[..max_bytes]
    } else {
        body
    };
    slice.hash(&mut hasher);
    hasher.finish()
}

/// Fingerprint a prefix by probing a canary path
pub async fn fingerprint_wildcard_prefix(
    prefix: &str,
    base_url: &str,
    client: &Client,
) -> Option<WildcardFingerprint> {
    let timeout = Duration::from_secs(5);
    let canary_path = generate_canary_path(prefix);
    let url = format!("{}{}", base_url.trim_end_matches('/'), canary_path);

    // GET fingerprint
    let get_fingerprint = match client.get(&url).timeout(timeout).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let content_length = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());
            let body = resp.bytes().await.unwrap_or_default();
            let body_hash = hash_body(&body, 1024);

            Some(ResponseFingerprint {
                status,
                content_type,
                content_length,
                body_hash,
                allow_header: None,
            })
        }
        Err(_) => None,
    };

    // OPTIONS fingerprint
    let options_fingerprint = match client
        .request(Method::OPTIONS, &url)
        .timeout(timeout)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let allow_header = resp
                .headers()
                .get("allow")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let content_length = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok());

            Some(ResponseFingerprint {
                status,
                content_type,
                content_length,
                body_hash: 0, // OPTIONS usually has no body
                allow_header,
            })
        }
        Err(_) => None,
    };

    // Only return fingerprint if we got at least a GET response
    if get_fingerprint.is_some() {
        log::debug!(
            "Fingerprinted wildcard prefix {}: GET={:?}, OPTIONS={:?}",
            prefix,
            get_fingerprint.as_ref().map(|f| f.status),
            options_fingerprint.as_ref().map(|f| f.status)
        );

        Some(WildcardFingerprint {
            prefix: prefix.to_string(),
            get_fingerprint,
            options_fingerprint,
        })
    } else {
        None
    }
}

/// Fingerprint multiple API prefixes that might have wildcard behavior
pub async fn fingerprint_api_prefixes(
    base_url: &str,
    client: &Client,
    prefixes: &[&str],
) -> HashMap<String, WildcardFingerprint> {
    let mut fingerprints = HashMap::new();

    for prefix in prefixes {
        if let Some(fp) = fingerprint_wildcard_prefix(prefix, base_url, client).await {
            // Only keep fingerprints that look like wildcards (405 or 404 on GET)
            if let Some(ref get_fp) = fp.get_fingerprint {
                if get_fp.status == 404 || get_fp.status == 405 {
                    log::info!(
                        "Detected wildcard behavior at {} (canary returns {})",
                        prefix,
                        get_fp.status
                    );
                    fingerprints.insert(prefix.to_string(), fp);
                }
            }
        }
    }

    fingerprints
}

// =============================================================================
// EMPIRICAL METHOD CONFIRMATION
// =============================================================================

/// Confirmed methods for an endpoint based on actual probing
#[derive(Debug, Clone)]
pub struct MethodConfirmation {
    /// The path being tested
    pub path: String,
    /// Methods confirmed to work (response != 404/405)
    pub confirmed_methods: Vec<String>,
    /// Methods that returned auth required (401/403)
    pub auth_required_methods: Vec<String>,
    /// Allow header hint (if available)
    pub allow_hint: Option<Vec<String>>,
}

/// Check if a status code indicates the method is supported
fn method_supported(status: u16) -> bool {
    // 404 and 405 mean not supported
    // Everything else (including 401, 403, 400, 500) means the endpoint exists
    status != 404 && status != 405
}

/// Confirm which methods are actually supported by an endpoint
pub async fn confirm_methods(path: &str, base_url: &str, client: &Client) -> MethodConfirmation {
    let timeout = Duration::from_secs(5);
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);

    let mut confirmed = Vec::new();
    let mut auth_required = Vec::new();

    // Test GET
    if let Ok(resp) = client.get(&url).timeout(timeout).send().await {
        let status = resp.status().as_u16();
        if method_supported(status) {
            confirmed.push("GET".to_string());
            if status == 401 || status == 403 {
                auth_required.push("GET".to_string());
            }
        }
    }

    // Test POST with empty JSON body (safe)
    if let Ok(resp) = client
        .post(&url)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
    {
        let status = resp.status().as_u16();
        if method_supported(status) {
            confirmed.push("POST".to_string());
            if status == 401 || status == 403 {
                auth_required.push("POST".to_string());
            }
        }
    }

    // Test PUT with empty JSON body (safe)
    if let Ok(resp) = client
        .put(&url)
        .timeout(timeout)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
    {
        let status = resp.status().as_u16();
        if method_supported(status) {
            confirmed.push("PUT".to_string());
            if status == 401 || status == 403 {
                auth_required.push("PUT".to_string());
            }
        }
    }

    // Test DELETE
    if let Ok(resp) = client.delete(&url).timeout(timeout).send().await {
        let status = resp.status().as_u16();
        if method_supported(status) {
            confirmed.push("DELETE".to_string());
            if status == 401 || status == 403 {
                auth_required.push("DELETE".to_string());
            }
        }
    }

    // Get Allow header hint via OPTIONS
    let allow_hint = match client
        .request(Method::OPTIONS, &url)
        .timeout(timeout)
        .send()
        .await
    {
        Ok(resp) => resp
            .headers()
            .get("allow")
            .and_then(|v| v.to_str().ok())
            .map(|header| {
                header
                    .split(',')
                    .map(|m| m.trim().to_uppercase())
                    .filter(|m| !m.is_empty())
                    .collect()
            }),
        Err(_) => None,
    };

    MethodConfirmation {
        path: path.to_string(),
        confirmed_methods: confirmed,
        auth_required_methods: auth_required,
        allow_hint,
    }
}

/// Confirm methods for multiple endpoints
pub async fn confirm_methods_batch(
    paths: &[String],
    base_url: &str,
    client: &Client,
    concurrency: usize,
) -> HashMap<String, MethodConfirmation> {
    use futures::stream::{self, StreamExt};

    let base = base_url.trim_end_matches('/').to_string();

    let results: Vec<_> = stream::iter(paths)
        .map(|path| {
            let base = base.clone();
            let path = path.clone();
            let client = client.clone();
            async move {
                let confirmation = confirm_methods(&path, &base, &client).await;
                (path, confirmation)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    results.into_iter().collect()
}

/// Generate a summary of probe results for the LLM
pub fn summarize_probe_results(results: &[ProbeResult]) -> String {
    let mut summary = String::new();

    if results.is_empty() {
        return "No probe results available.".to_string();
    }

    summary.push_str("HTTP Probe Results:\n");

    // Server headers
    let servers: Vec<_> = results.iter().filter_map(|r| r.server.as_ref()).collect();
    if !servers.is_empty() {
        summary.push_str("\nServer headers detected:\n");
        let mut unique_servers: Vec<_> = servers
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        unique_servers.sort();
        for server in unique_servers {
            summary.push_str(&format!("  - {}\n", server));
        }
    }

    // X-Powered-By headers
    let powered_by: Vec<_> = results
        .iter()
        .filter_map(|r| r.powered_by.as_ref())
        .collect();
    if !powered_by.is_empty() {
        summary.push_str("\nX-Powered-By headers:\n");
        let mut unique: Vec<_> = powered_by
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        unique.sort();
        for header in unique {
            summary.push_str(&format!("  - {}\n", header));
        }
    }

    // Status code distribution
    let mut status_counts: HashMap<u16, usize> = HashMap::new();
    for result in results {
        *status_counts.entry(result.status_code).or_insert(0) += 1;
    }
    summary.push_str("\nStatus code distribution:\n");
    let mut status_vec: Vec<_> = status_counts.into_iter().collect();
    status_vec.sort_by_key(|(code, _)| *code);
    for (code, count) in status_vec {
        summary.push_str(&format!("  - {}: {} responses\n", code, count));
    }

    // METHOD VARIATION FINDINGS - behavioral analysis
    let method_findings: Vec<_> = results
        .iter()
        .filter_map(|r| {
            r.method_variations.as_ref().and_then(|mv| {
                if !mv.interesting_methods.is_empty() {
                    Some((r.url.clone(), mv.interesting_methods.clone()))
                } else {
                    None
                }
            })
        })
        .collect();

    if !method_findings.is_empty() {
        summary.push_str("\n** METHOD VARIATION FINDINGS (behavioral anomalies) **\n");
        for (url, methods) in &method_findings {
            summary.push_str(&format!("  {} -> {}\n", url, methods.join(", ")));
        }
        summary.push_str("  ^ These endpoints respond differently to different HTTP methods!\n");
    }

    // HEADER MUTATION FINDINGS - access control bypass attempts
    let header_findings: Vec<_> = results
        .iter()
        .filter_map(|r| {
            r.header_mutations.as_ref().and_then(|hm| {
                if !hm.findings.is_empty() {
                    Some((r.url.clone(), hm.findings.clone()))
                } else {
                    None
                }
            })
        })
        .collect();

    if !header_findings.is_empty() {
        summary.push_str("\n** HEADER MUTATION FINDINGS (potential access control bypass!) **\n");
        for (url, findings) in &header_findings {
            summary.push_str(&format!("  {}:\n", url));
            for finding in findings {
                summary.push_str(&format!("    - {}\n", finding));
            }
        }
        summary.push_str("  ^ CRITICAL: These may indicate authentication/authorization bypass!\n");
    }

    // Content types
    let content_types: Vec<_> = results
        .iter()
        .filter_map(|r| r.content_type.as_ref())
        .collect();
    if !content_types.is_empty() {
        summary.push_str("\nContent types:\n");
        let mut unique: Vec<_> = content_types
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        unique.sort();
        for ct in unique.iter().take(10) {
            summary.push_str(&format!("  - {}\n", ct));
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_url_pattern() {
        assert_eq!(
            extract_url_pattern("http://example.com/users/123"),
            "http://example.com/users/{id}"
        );
        assert_eq!(
            extract_url_pattern("http://example.com/api/v1/posts"),
            "http://example.com/api/v1/posts"
        );
    }

    #[test]
    fn test_select_urls_to_probe() {
        let urls = vec![
            "http://example.com/api/users".to_string(),
            "http://example.com/api/posts".to_string(),
            "http://example.com/static/main.js".to_string(),
            "http://example.com/".to_string(),
        ];
        let selected = select_urls_to_probe(&urls, 3);
        assert!(selected.len() <= 3);
        // API endpoints should be prioritized
        assert!(selected.iter().any(|u| u.contains("/api/")));
    }

    #[test]
    fn test_is_interesting_status_diff() {
        // 405 -> 200 should be interesting (found the right method)
        assert!(is_interesting_status_diff(405, 200));
        assert!(is_interesting_status_diff(405, 201));

        // 403 -> 200 should be interesting (auth bypass)
        assert!(is_interesting_status_diff(403, 200));

        // 404 -> 200 should be interesting (endpoint exists with different method)
        assert!(is_interesting_status_diff(404, 200));

        // Any -> 500 should be interesting (potential vuln)
        assert!(is_interesting_status_diff(200, 500));

        // Same status not interesting
        assert!(!is_interesting_status_diff(200, 200));
    }

    #[test]
    fn test_should_test_methods() {
        // 405 always tests methods
        assert!(should_test_methods("/anything", 405));

        // API endpoints test methods
        assert!(should_test_methods("/api/users", 200));
        assert!(should_test_methods("/graphql", 200));

        // Auth endpoints test methods
        assert!(should_test_methods("/auth/login", 200));
        assert!(should_test_methods("/login", 200));

        // Regular endpoint without interesting status doesn't test
        assert!(!should_test_methods("/about", 200));
    }

    #[test]
    fn test_should_test_headers() {
        // 401/403 always test headers
        assert!(should_test_headers("/anything", 401));
        assert!(should_test_headers("/anything", 403));

        // Admin/internal paths test headers
        assert!(should_test_headers("/admin/dashboard", 200));
        assert!(should_test_headers("/internal/api", 200));
        assert!(should_test_headers("/private/data", 200));

        // Regular endpoint doesn't test headers
        assert!(!should_test_headers("/about", 200));
    }

    #[test]
    fn test_is_header_bypass() {
        // 401/403 -> 200 is a bypass
        assert!(is_header_bypass(401, 200));
        assert!(is_header_bypass(403, 200));

        // 401/403 -> 302 could be bypass (redirect to success)
        assert!(is_header_bypass(401, 302));
        assert!(is_header_bypass(403, 302));

        // 404 -> 200 is interesting (hidden endpoint)
        assert!(is_header_bypass(404, 200));

        // Same status not a bypass
        assert!(!is_header_bypass(401, 401));
        assert!(!is_header_bypass(403, 403));
    }
}
