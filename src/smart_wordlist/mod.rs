//! Smart wordlist generation module for feroxagent
//!
//! This module provides AI-powered wordlist generation based on recon data.
//! It analyzes URLs from tools like katana/gospider, detects technologies,
//! and uses Claude API to generate targeted wordlists.
//!
//! Key features:
//! - Pentest value scoring to filter noise and surface high-signal findings
//! - HTTP method variation testing to detect behavioral anomalies
//! - Static asset filtering to reduce false positives

mod analyzer;
mod auth_discovery;
mod generator;
mod llm;
mod mutations;
mod probe;
mod report;

pub use analyzer::TechAnalysis;
pub use auth_discovery::{
    attempt_authentication, discover_auth_endpoints, generate_test_credentials,
    probe_single_auth_endpoint, AuthAction, AuthDiscoveryResult, AuthEndpoint, AuthEndpointType,
    AuthPlan, AuthResult, AuthTokenType, TestCredentials, TokenLocation,
};
pub use generator::{
    budget_wordlist, generate_wordlist, output_attack_report, output_wordlist, BudgetConfig,
    GenerationResult, GeneratorConfig,
};
pub use llm::{AggregatedUsage, ClaudeClient, UsageMetrics};
pub use mutations::{expand_parameterized_paths, generate_mutations, Framework, MutationConfig};
pub use probe::{
    confirm_methods, confirm_methods_batch, discover_methods, discover_methods_for_405s,
    fingerprint_api_prefixes, fingerprint_wildcard_prefix, probe_urls, HeaderMutationResults,
    MethodConfirmation, MethodVariations, OptionsResult, ProbeResult, ResponseFingerprint,
    WildcardFingerprint,
};
pub use report::{
    detect_parameterized_endpoint, generate_canonical_inventory,
    generate_canonical_inventory_with_wildcards, output_report, CanonicalEndpoint,
    DiscoveredEndpoint, JsonOutput, PentestReport, ReportStats,
};
