//! HTTP probing functionality for gathering additional context
//!
//! Makes requests to discovered URLs to gather more information
//! about the target application (headers, response patterns, etc.)

use anyhow::Result;
use reqwest::Client;
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
        format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), pattern)
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
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse().ok());

    Ok(ProbeResult {
        url: url.to_string(),
        status_code,
        headers,
        content_type,
        server,
        powered_by,
        content_length,
    })
}

/// Generate a summary of probe results for the LLM
pub fn summarize_probe_results(results: &[ProbeResult]) -> String {
    let mut summary = String::new();

    if results.is_empty() {
        return "No probe results available.".to_string();
    }

    summary.push_str("HTTP Probe Results:\n");

    // Server headers
    let servers: Vec<_> = results
        .iter()
        .filter_map(|r| r.server.as_ref())
        .collect();
    if !servers.is_empty() {
        summary.push_str("\nServer headers detected:\n");
        let mut unique_servers: Vec<_> = servers.into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect();
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
        let mut unique: Vec<_> = powered_by.into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect();
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

    // Content types
    let content_types: Vec<_> = results
        .iter()
        .filter_map(|r| r.content_type.as_ref())
        .collect();
    if !content_types.is_empty() {
        summary.push_str("\nContent types:\n");
        let mut unique: Vec<_> = content_types.into_iter().collect::<std::collections::HashSet<_>>().into_iter().collect();
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
}
