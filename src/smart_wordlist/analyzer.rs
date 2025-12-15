//! Technology detection and analysis from URL patterns
//!
//! Analyzes recon URLs to detect web frameworks, API patterns, and technologies.

use std::collections::{HashMap, HashSet};
use url::Url;

/// Detected technology/framework
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Technology {
    NextJs,
    React,
    Vue,
    Angular,
    Rails,
    Django,
    Laravel,
    Express,
    Spring,
    AspNet,
    WordPress,
    Drupal,
    GraphQL,
    RestApi,
    Unknown,
}

impl Technology {
    pub fn as_str(&self) -> &'static str {
        match self {
            Technology::NextJs => "Next.js",
            Technology::React => "React",
            Technology::Vue => "Vue.js",
            Technology::Angular => "Angular",
            Technology::Rails => "Ruby on Rails",
            Technology::Django => "Django",
            Technology::Laravel => "Laravel",
            Technology::Express => "Express.js",
            Technology::Spring => "Spring Boot",
            Technology::AspNet => "ASP.NET",
            Technology::WordPress => "WordPress",
            Technology::Drupal => "Drupal",
            Technology::GraphQL => "GraphQL",
            Technology::RestApi => "REST API",
            Technology::Unknown => "Unknown",
        }
    }
}

/// Analysis result containing detected technologies and patterns
#[derive(Debug, Clone)]
pub struct TechAnalysis {
    /// Detected technologies with confidence scores (0.0 - 1.0)
    pub technologies: HashMap<Technology, f32>,
    /// Detected API endpoints
    pub api_endpoints: Vec<String>,
    /// Detected static asset patterns
    pub static_patterns: Vec<String>,
    /// Detected route patterns (e.g., /users/:id)
    pub route_patterns: Vec<String>,
    /// Raw paths extracted from URLs
    pub paths: HashSet<String>,
    /// Base URL(s) from the recon data
    pub base_urls: HashSet<String>,
}

impl TechAnalysis {
    pub fn new() -> Self {
        Self {
            technologies: HashMap::new(),
            api_endpoints: Vec::new(),
            static_patterns: Vec::new(),
            route_patterns: Vec::new(),
            paths: HashSet::new(),
            base_urls: HashSet::new(),
        }
    }

    /// Get the primary (highest confidence) detected technology
    pub fn primary_technology(&self) -> Option<(&Technology, &f32)> {
        self.technologies
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Generate a summary for the LLM prompt
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        // Technologies
        if !self.technologies.is_empty() {
            summary.push_str("Detected Technologies:\n");
            let mut techs: Vec<_> = self.technologies.iter().collect();
            techs.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (tech, confidence) in techs {
                summary.push_str(&format!(
                    "  - {} (confidence: {:.0}%)\n",
                    tech.as_str(),
                    confidence * 100.0
                ));
            }
        }

        // API endpoints
        if !self.api_endpoints.is_empty() {
            summary.push_str("\nDiscovered API Endpoints:\n");
            for endpoint in self.api_endpoints.iter().take(20) {
                summary.push_str(&format!("  - {}\n", endpoint));
            }
            if self.api_endpoints.len() > 20 {
                summary.push_str(&format!(
                    "  ... and {} more\n",
                    self.api_endpoints.len() - 20
                ));
            }
        }

        // Route patterns
        if !self.route_patterns.is_empty() {
            summary.push_str("\nRoute Patterns:\n");
            for pattern in self.route_patterns.iter().take(10) {
                summary.push_str(&format!("  - {}\n", pattern));
            }
        }

        // Static patterns
        if !self.static_patterns.is_empty() {
            summary.push_str("\nStatic Asset Patterns:\n");
            for pattern in self.static_patterns.iter().take(5) {
                summary.push_str(&format!("  - {}\n", pattern));
            }
        }

        summary
    }
}

impl Default for TechAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Analyze a list of URLs to detect technologies and patterns
pub fn analyze_urls(urls: &[String]) -> TechAnalysis {
    let mut analysis = TechAnalysis::new();

    for url_str in urls {
        if let Ok(url) = Url::parse(url_str) {
            // Extract base URL
            if let Some(host) = url.host_str() {
                let base = format!(
                    "{}://{}{}",
                    url.scheme(),
                    host,
                    url.port().map(|p| format!(":{}", p)).unwrap_or_default()
                );
                analysis.base_urls.insert(base);
            }

            // Extract path
            let path = url.path().to_string();
            if !path.is_empty() && path != "/" {
                analysis.paths.insert(path.clone());
            }

            // Detect technologies from URL patterns
            detect_technologies(&path, &mut analysis);

            // Extract API endpoints
            if is_api_endpoint(&path) {
                analysis.api_endpoints.push(path.clone());
            }

            // Detect route patterns
            detect_route_patterns(&path, &mut analysis);
        }
    }

    // Deduplicate API endpoints
    analysis.api_endpoints.sort();
    analysis.api_endpoints.dedup();

    // Deduplicate route patterns
    analysis.route_patterns.sort();
    analysis.route_patterns.dedup();

    analysis
}

fn detect_technologies(path: &str, analysis: &mut TechAnalysis) {
    let path_lower = path.to_lowercase();

    // Next.js detection
    if path_lower.contains("/_next/")
        || path_lower.contains("/_next/static")
        || path_lower.contains("node_modules/next/")
    {
        *analysis.technologies.entry(Technology::NextJs).or_insert(0.0) += 0.3;
        analysis.static_patterns.push("/_next/static/".to_string());
    }

    // React detection (generic)
    if path_lower.contains("/static/js/")
        || path_lower.contains("react")
        || path_lower.contains("/bundle.js")
    {
        *analysis.technologies.entry(Technology::React).or_insert(0.0) += 0.2;
    }

    // Vue.js detection
    if path_lower.contains("/js/chunk-")
        || path_lower.contains("vue")
        || path_lower.contains("/_nuxt/")
    {
        *analysis.technologies.entry(Technology::Vue).or_insert(0.0) += 0.3;
    }

    // Angular detection
    if path_lower.contains("/main.")
        && (path_lower.contains(".js") || path_lower.contains(".bundle"))
        || path_lower.contains("angular")
    {
        *analysis.technologies.entry(Technology::Angular).or_insert(0.0) += 0.2;
    }

    // Rails detection
    if path_lower.contains("/assets/") && path_lower.contains("-")
        || path_lower.contains("/packs/")
        || path_lower.contains("/rails/")
    {
        *analysis.technologies.entry(Technology::Rails).or_insert(0.0) += 0.3;
    }

    // Django detection
    if path_lower.contains("/static/") && path_lower.contains("/admin/")
        || path_lower.contains("/django")
        || path_lower.contains("/__debug__/")
    {
        *analysis.technologies.entry(Technology::Django).or_insert(0.0) += 0.3;
    }

    // Laravel detection
    if path_lower.contains("/storage/")
        || path_lower.contains("/vendor/")
        || path_lower.contains("/livewire/")
    {
        *analysis.technologies.entry(Technology::Laravel).or_insert(0.0) += 0.3;
    }

    // WordPress detection
    if path_lower.contains("/wp-content/")
        || path_lower.contains("/wp-admin/")
        || path_lower.contains("/wp-includes/")
    {
        *analysis.technologies.entry(Technology::WordPress).or_insert(0.0) += 0.5;
    }

    // GraphQL detection
    if path_lower.contains("/graphql") || path_lower.contains("/gql") {
        *analysis.technologies.entry(Technology::GraphQL).or_insert(0.0) += 0.4;
        analysis.api_endpoints.push("/graphql".to_string());
    }

    // REST API detection
    if path_lower.contains("/api/")
        || path_lower.starts_with("/v1/")
        || path_lower.starts_with("/v2/")
    {
        *analysis.technologies.entry(Technology::RestApi).or_insert(0.0) += 0.2;
    }

    // ASP.NET detection
    if path_lower.contains(".aspx")
        || path_lower.contains(".ashx")
        || path_lower.contains("/_vti_bin/")
    {
        *analysis.technologies.entry(Technology::AspNet).or_insert(0.0) += 0.4;
    }

    // Spring detection
    if path_lower.contains("/actuator/")
        || path_lower.contains("/swagger-ui")
        || path_lower.contains("/v2/api-docs")
    {
        *analysis.technologies.entry(Technology::Spring).or_insert(0.0) += 0.4;
    }

    // Normalize confidence scores (cap at 1.0)
    for confidence in analysis.technologies.values_mut() {
        if *confidence > 1.0 {
            *confidence = 1.0;
        }
    }
}

fn is_api_endpoint(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.contains("/api/")
        || path_lower.starts_with("/v1/")
        || path_lower.starts_with("/v2/")
        || path_lower.starts_with("/v3/")
        || path_lower.contains("/graphql")
        || path_lower.contains("/rest/")
        || path_lower.contains("/services/")
}

fn detect_route_patterns(path: &str, analysis: &mut TechAnalysis) {
    // Look for patterns like /users/123 -> /users/:id
    let parts: Vec<&str> = path.split('/').collect();

    let mut pattern_parts = Vec::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }

        // Check if this part looks like an ID (numeric, UUID, etc.)
        if part.parse::<u64>().is_ok() {
            pattern_parts.push(":id");
        } else if is_uuid(part) {
            pattern_parts.push(":uuid");
        } else if part.len() > 20 && part.chars().all(|c| c.is_alphanumeric()) {
            pattern_parts.push(":hash");
        } else {
            pattern_parts.push(part);
        }
    }

    if !pattern_parts.is_empty() {
        let pattern = format!("/{}", pattern_parts.join("/"));
        if pattern.contains(':') {
            analysis.route_patterns.push(pattern);
        }
    }
}

fn is_uuid(s: &str) -> bool {
    // Simple UUID check (8-4-4-4-12 format)
    if s.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && parts
            .iter()
            .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nextjs_detection() {
        let urls = vec![
            "http://localhost:3000/_next/static/chunks/app_page.js".to_string(),
            "http://localhost:3000/_next/static/css/main.css".to_string(),
        ];
        let analysis = analyze_urls(&urls);
        assert!(analysis.technologies.contains_key(&Technology::NextJs));
    }

    #[test]
    fn test_api_endpoint_detection() {
        let urls = vec![
            "http://localhost:3000/api/users".to_string(),
            "http://localhost:3000/api/auth/login".to_string(),
            "http://localhost:3000/v1/products".to_string(),
        ];
        let analysis = analyze_urls(&urls);
        assert!(!analysis.api_endpoints.is_empty());
        assert!(analysis.technologies.contains_key(&Technology::RestApi));
    }

    #[test]
    fn test_route_pattern_detection() {
        let urls = vec![
            "http://localhost:3000/users/123".to_string(),
            "http://localhost:3000/posts/456/comments".to_string(),
        ];
        let analysis = analyze_urls(&urls);
        assert!(analysis.route_patterns.contains(&"/users/:id".to_string()));
    }
}
