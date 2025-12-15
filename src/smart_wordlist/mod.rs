//! Smart wordlist generation module for feroxagent
//!
//! This module provides AI-powered wordlist generation based on recon data.
//! It analyzes URLs from tools like katana/gospider, detects technologies,
//! and uses Claude API to generate targeted wordlists.

mod analyzer;
mod generator;
mod llm;
mod probe;

pub use analyzer::TechAnalysis;
pub use generator::{generate_wordlist, output_wordlist, GeneratorConfig};
pub use llm::ClaudeClient;
pub use probe::probe_urls;
