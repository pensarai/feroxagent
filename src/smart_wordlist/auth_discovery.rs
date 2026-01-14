//! Authentication endpoint discovery and authentication attempt functionality
//!
//! This module discovers authentication endpoints (login, register, etc.) and
//! attempts to authenticate using LLM-guided credential generation.

use anyhow::Result;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::analyzer::TechAnalysis;

/// Information about a discovered authentication endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEndpoint {
    pub url: String,
    pub endpoint_type: AuthEndpointType,
    pub method: String,
    pub content_type: Option<String>,
    pub detected_fields: Vec<String>,
    pub status_code: u16,
}

/// Types of authentication endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthEndpointType {
    Login,
    Register,
    Logout,
    PasswordReset,
    TokenRefresh,
    OAuth,
    Session,
    Unknown,
}

impl std::fmt::Display for AuthEndpointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthEndpointType::Login => write!(f, "login"),
            AuthEndpointType::Register => write!(f, "register"),
            AuthEndpointType::Logout => write!(f, "logout"),
            AuthEndpointType::PasswordReset => write!(f, "password_reset"),
            AuthEndpointType::TokenRefresh => write!(f, "token_refresh"),
            AuthEndpointType::OAuth => write!(f, "oauth"),
            AuthEndpointType::Session => write!(f, "session"),
            AuthEndpointType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Results of auth endpoint discovery
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthDiscoveryResult {
    pub endpoints: Vec<AuthEndpoint>,
    pub registration_available: bool,
    pub login_endpoint: Option<AuthEndpoint>,
    pub register_endpoint: Option<AuthEndpoint>,
}

/// Result of an authentication attempt
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub token: Option<String>,
    pub cookies: Vec<String>,
    pub token_type: AuthTokenType,
    pub user_created: bool,
    pub credentials_used: Option<TestCredentials>,
    pub error_message: Option<String>,
    /// Status code from registration attempt (if attempted)
    pub register_status: Option<u16>,
    /// Status code from login attempt (if attempted)
    pub login_status: Option<u16>,
}

/// Types of authentication tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthTokenType {
    Bearer,
    Cookie,
    ApiKey,
    #[default]
    None,
}

/// Test credentials generated for registration/login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCredentials {
    pub email: String,
    pub password: String,
}

/// LLM-generated authentication plan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthPlan {
    pub registration: Option<AuthAction>,
    pub login: Option<AuthAction>,
    pub token_location: TokenLocation,
    pub summary: String,
}

/// Action to perform for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthAction {
    pub endpoint: String,
    pub method: String,
    pub content_type: String,
    pub body_template: String,
    pub required_fields: Vec<String>,
}

/// Where the auth token appears in the response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", content = "field")]
pub enum TokenLocation {
    ResponseBodyField(String),
    SetCookieHeader,
    AuthorizationHeader,
    #[default]
    Unknown,
}

/// Common authentication paths to probe
const AUTH_PATHS: &[(&str, AuthEndpointType)] = &[
    // Login endpoints
    ("/login", AuthEndpointType::Login),
    ("/signin", AuthEndpointType::Login),
    ("/auth/login", AuthEndpointType::Login),
    ("/api/auth/login", AuthEndpointType::Login),
    ("/api/login", AuthEndpointType::Login),
    ("/api/v1/auth/login", AuthEndpointType::Login),
    ("/api/v1/login", AuthEndpointType::Login),
    ("/users/sign_in", AuthEndpointType::Login), // Rails/Devise
    ("/accounts/login", AuthEndpointType::Login), // Django
    ("/api/auth/signin", AuthEndpointType::Login), // NextAuth
    // Register endpoints
    ("/register", AuthEndpointType::Register),
    ("/signup", AuthEndpointType::Register),
    ("/auth/register", AuthEndpointType::Register),
    ("/api/auth/register", AuthEndpointType::Register),
    ("/api/register", AuthEndpointType::Register),
    ("/api/v1/auth/register", AuthEndpointType::Register),
    ("/api/v1/register", AuthEndpointType::Register),
    ("/users/sign_up", AuthEndpointType::Register), // Rails/Devise
    ("/accounts/signup", AuthEndpointType::Register), // Django
    // Token/Session endpoints
    ("/token", AuthEndpointType::TokenRefresh),
    ("/api/token", AuthEndpointType::TokenRefresh),
    ("/oauth/token", AuthEndpointType::OAuth),
    ("/api/auth/session", AuthEndpointType::Session), // NextAuth
    ("/api/auth/csrf", AuthEndpointType::Session), // NextAuth
    // Logout
    ("/logout", AuthEndpointType::Logout),
    ("/signout", AuthEndpointType::Logout),
    ("/api/auth/logout", AuthEndpointType::Logout),
    ("/api/logout", AuthEndpointType::Logout),
    // Password reset
    ("/forgot-password", AuthEndpointType::PasswordReset),
    ("/password/reset", AuthEndpointType::PasswordReset),
    ("/api/auth/forgot-password", AuthEndpointType::PasswordReset),
];

/// Discover authentication endpoints by probing common paths
pub async fn discover_auth_endpoints(
    base_url: &str,
    _analysis: &TechAnalysis,
    client: &Client,
) -> Result<AuthDiscoveryResult> {
    log::info!("Discovering authentication endpoints for {}", base_url);

    let mut result = AuthDiscoveryResult::default();
    let base = base_url.trim_end_matches('/');

    for (path, endpoint_type) in AUTH_PATHS {
        let url = format!("{}{}", base, path);

        match probe_auth_endpoint(&url, *endpoint_type, client).await {
            Ok(Some(endpoint)) => {
                log::info!(
                    "Found {} endpoint: {} (status: {})",
                    endpoint.endpoint_type,
                    endpoint.url,
                    endpoint.status_code
                );

                // Track specific endpoint types
                match endpoint.endpoint_type {
                    AuthEndpointType::Login => {
                        if result.login_endpoint.is_none() {
                            result.login_endpoint = Some(endpoint.clone());
                        }
                    }
                    AuthEndpointType::Register => {
                        result.registration_available = true;
                        if result.register_endpoint.is_none() {
                            result.register_endpoint = Some(endpoint.clone());
                        }
                    }
                    _ => {}
                }

                result.endpoints.push(endpoint);
            }
            Ok(None) => {
                log::debug!("No auth endpoint at {}", url);
            }
            Err(e) => {
                log::debug!("Error probing {}: {}", url, e);
            }
        }
    }

    log::info!(
        "Auth discovery complete: {} endpoints found, registration={}",
        result.endpoints.len(),
        result.registration_available
    );

    Ok(result)
}

/// Probe a single URL to determine if it's an auth endpoint
async fn probe_auth_endpoint(
    url: &str,
    endpoint_type: AuthEndpointType,
    client: &Client,
) -> Result<Option<AuthEndpoint>> {
    // Try GET first
    let get_response = client
        .get(url)
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    let (status_code, content_type, is_auth_endpoint) = match get_response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            // Auth endpoints typically return:
            // - 200: Login form or API info
            // - 401: Requires authentication
            // - 405: Method not allowed (expects POST)
            // - 400: Bad request (expects body)
            let is_auth = matches!(status, 200 | 401 | 405 | 400 | 422);

            (status, ct, is_auth)
        }
        Err(e) => {
            // Connection errors are not auth endpoints
            if e.is_timeout() || e.is_connect() {
                return Ok(None);
            }
            // Other errors might indicate an endpoint
            log::debug!("GET {} error: {}", url, e);
            return Ok(None);
        }
    };

    if !is_auth_endpoint {
        return Ok(None);
    }

    // If 405, try OPTIONS to confirm POST is allowed
    let method = if status_code == 405 {
        // Try OPTIONS
        if let Ok(opt_resp) = client
            .request(Method::OPTIONS, url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            if let Some(allow) = opt_resp.headers().get("allow") {
                if let Ok(allow_str) = allow.to_str() {
                    if allow_str.contains("POST") {
                        "POST".to_string()
                    } else {
                        "GET".to_string()
                    }
                } else {
                    "POST".to_string() // Assume POST for 405
                }
            } else {
                "POST".to_string() // Assume POST for 405
            }
        } else {
            "POST".to_string() // Assume POST for 405
        }
    } else {
        "GET".to_string()
    };

    // Detect fields from common patterns
    let detected_fields = detect_auth_fields(endpoint_type);

    Ok(Some(AuthEndpoint {
        url: url.to_string(),
        endpoint_type,
        method,
        content_type,
        detected_fields,
        status_code,
    }))
}

/// Probe a single manually-specified auth endpoint
pub async fn probe_single_auth_endpoint(
    url: &str,
    client: &Client,
) -> Result<AuthDiscoveryResult> {
    let endpoint_type = infer_endpoint_type(url);

    let mut result = AuthDiscoveryResult::default();

    if let Some(endpoint) = probe_auth_endpoint(url, endpoint_type, client).await? {
        match endpoint.endpoint_type {
            AuthEndpointType::Login => {
                result.login_endpoint = Some(endpoint.clone());
            }
            AuthEndpointType::Register => {
                result.registration_available = true;
                result.register_endpoint = Some(endpoint.clone());
            }
            _ => {}
        }
        result.endpoints.push(endpoint);
    }

    Ok(result)
}

/// Infer the endpoint type from URL patterns
fn infer_endpoint_type(url: &str) -> AuthEndpointType {
    let url_lower = url.to_lowercase();

    if url_lower.contains("login") || url_lower.contains("signin") {
        AuthEndpointType::Login
    } else if url_lower.contains("register") || url_lower.contains("signup") {
        AuthEndpointType::Register
    } else if url_lower.contains("logout") || url_lower.contains("signout") {
        AuthEndpointType::Logout
    } else if url_lower.contains("token") {
        AuthEndpointType::TokenRefresh
    } else if url_lower.contains("oauth") {
        AuthEndpointType::OAuth
    } else if url_lower.contains("password") || url_lower.contains("forgot") {
        AuthEndpointType::PasswordReset
    } else if url_lower.contains("session") {
        AuthEndpointType::Session
    } else {
        AuthEndpointType::Unknown
    }
}

/// Detect likely auth fields based on endpoint type
fn detect_auth_fields(endpoint_type: AuthEndpointType) -> Vec<String> {
    match endpoint_type {
        AuthEndpointType::Login => vec!["email".to_string(), "password".to_string()],
        AuthEndpointType::Register => vec![
            "email".to_string(),
            "password".to_string(),
            "username".to_string(),
        ],
        AuthEndpointType::PasswordReset => vec!["email".to_string()],
        AuthEndpointType::TokenRefresh => vec!["refresh_token".to_string()],
        _ => vec![],
    }
}

/// Generate test credentials for registration
pub fn generate_test_credentials() -> TestCredentials {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let random_suffix = timestamp % 100000;

    TestCredentials {
        email: format!("feroxtest_{}@example.com", random_suffix),
        password: "FeroxTest123!".to_string(),
    }
}

/// Attempt to authenticate using the auth plan
pub async fn attempt_authentication(
    discovery: &AuthDiscoveryResult,
    auth_plan: &AuthPlan,
    client: &Client,
    auto_register: bool,
) -> Result<AuthResult> {
    let mut result = AuthResult::default();

    // Step 1: Try registration if available and auto_register is enabled
    if auto_register && discovery.registration_available {
        if let Some(ref register_action) = auth_plan.registration {
            log::info!("Attempting auto-registration...");

            let creds = generate_test_credentials();
            match try_register(register_action, &creds, client, &auth_plan.token_location).await {
                Ok((reg_result, reg_status)) => {
                    // Store the registration status code
                    result.register_status = Some(reg_status);

                    if reg_result.success {
                        log::info!(
                            "Registration successful for {} (status: {})",
                            creds.email,
                            reg_status
                        );
                        result.success = reg_result.success;
                        result.token = reg_result.token;
                        result.cookies = reg_result.cookies;
                        result.token_type = reg_result.token_type;
                        result.credentials_used = Some(creds.clone());
                        result.user_created = true;

                        // If we got a token from registration, we're done
                        if result.token.is_some() || !result.cookies.is_empty() {
                            return Ok(result);
                        }

                        // Otherwise, try to login with the new credentials
                        if let Some(ref login_action) = auth_plan.login {
                            log::info!(
                                "No token from registration, attempting login at {}",
                                login_action.endpoint
                            );
                            match try_login(login_action, &creds, client, &auth_plan.token_location)
                                .await
                            {
                                Ok((login_result, login_status)) => {
                                    // Store the login status code
                                    result.login_status = Some(login_status);

                                    if login_result.success {
                                        log::info!(
                                            "Login successful after registration (status: {})",
                                            login_status
                                        );
                                        result.success = true;
                                        result.token = login_result.token;
                                        result.cookies = login_result.cookies;
                                        result.token_type = login_result.token_type;
                                    } else {
                                        log::warn!(
                                            "Login returned non-success status {}: {}",
                                            login_status,
                                            login_result.error_message.as_deref().unwrap_or("unknown")
                                        );
                                        // Still keep the registration success and credentials
                                        result.error_message = login_result.error_message;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Login after registration failed: {}", e);
                                    result.error_message = Some(format!("Login error: {}", e));
                                }
                            }
                        } else {
                            log::warn!("No login action in auth plan, cannot login after registration");
                            result.error_message =
                                Some("Registration succeeded but no login endpoint available".to_string());
                        }

                        return Ok(result);
                    } else {
                        log::warn!(
                            "Registration failed (status {}): {}",
                            reg_status,
                            reg_result.error_message.unwrap_or_default()
                        );
                    }
                }
                Err(e) => {
                    log::warn!("Registration attempt error: {}", e);
                }
            }
        }
    }

    // Step 2: Try login without credentials (will likely fail, but reports endpoint info)
    if let Some(ref login_action) = auth_plan.login {
        log::info!("Login endpoint available at {}", login_action.endpoint);
        result.error_message = Some("Login requires valid credentials".to_string());
    }

    Ok(result)
}

/// Attempt registration with given credentials
/// Returns (AuthResult, status_code)
async fn try_register(
    action: &AuthAction,
    creds: &TestCredentials,
    client: &Client,
    token_location: &TokenLocation,
) -> Result<(AuthResult, u16)> {
    let body = action
        .body_template
        .replace("{email}", &creds.email)
        .replace("{password}", &creds.password)
        .replace("{username}", creds.email.split('@').next().unwrap_or("feroxtest"));

    log::debug!(
        "Attempting registration: {} {} Content-Type: {}",
        action.method,
        action.endpoint,
        action.content_type
    );
    log::debug!("Registration body: {}", body);

    let response = client
        .request(
            Method::from_bytes(action.method.as_bytes()).unwrap_or(Method::POST),
            &action.endpoint,
        )
        .header("Content-Type", &action.content_type)
        .body(body)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    let status_code = response.status().as_u16();
    log::debug!("Registration response status: {}", status_code);

    let result = parse_auth_response(response, token_location).await?;
    Ok((result, status_code))
}

/// Attempt login with given credentials
/// Returns (AuthResult, status_code)
async fn try_login(
    action: &AuthAction,
    creds: &TestCredentials,
    client: &Client,
    token_location: &TokenLocation,
) -> Result<(AuthResult, u16)> {
    // Handle both {email} and {username} placeholders
    let username = creds.email.split('@').next().unwrap_or("feroxtest");
    let body = action
        .body_template
        .replace("{email}", &creds.email)
        .replace("{password}", &creds.password)
        .replace("{username}", username);

    log::debug!(
        "Attempting login: {} {} Content-Type: {}",
        action.method,
        action.endpoint,
        action.content_type
    );
    log::debug!("Login body: {}", body);

    let response = client
        .request(
            Method::from_bytes(action.method.as_bytes()).unwrap_or(Method::POST),
            &action.endpoint,
        )
        .header("Content-Type", &action.content_type)
        .body(body)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    let status_code = response.status().as_u16();
    log::debug!("Login response status: {}", status_code);

    let result = parse_auth_response(response, token_location).await?;
    Ok((result, status_code))
}

/// Parse the auth response to extract token/cookies
async fn parse_auth_response(
    response: reqwest::Response,
    token_location: &TokenLocation,
) -> Result<AuthResult> {
    let mut result = AuthResult::default();

    let status = response.status();
    result.success = status.is_success();

    // Extract cookies from Set-Cookie headers
    for value in response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = value.to_str() {
            // Extract just the cookie name=value part (before any ;)
            let cookie_value = cookie_str.split(';').next().unwrap_or(cookie_str);
            result.cookies.push(cookie_value.to_string());
        }
    }

    // Extract token based on expected location
    match token_location {
        TokenLocation::SetCookieHeader => {
            if !result.cookies.is_empty() {
                result.token_type = AuthTokenType::Cookie;
            }
        }
        TokenLocation::ResponseBodyField(field) => {
            if let Ok(body) = response.text().await {
                // Try to parse as JSON and extract the field
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(token) = json.get(field).and_then(|v| v.as_str()) {
                        result.token = Some(token.to_string());
                        result.token_type = AuthTokenType::Bearer;
                    }
                    // Also check nested paths like data.token or user.token
                    if result.token.is_none() {
                        for key in ["data", "user", "result", "response"] {
                            if let Some(nested) = json.get(key) {
                                if let Some(token) = nested.get(field).and_then(|v| v.as_str()) {
                                    result.token = Some(token.to_string());
                                    result.token_type = AuthTokenType::Bearer;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        TokenLocation::AuthorizationHeader => {
            // Token would be in response header (rare)
            if let Some(auth) = response.headers().get("authorization") {
                if let Ok(auth_str) = auth.to_str() {
                    result.token = Some(auth_str.replace("Bearer ", ""));
                    result.token_type = AuthTokenType::Bearer;
                }
            }
        }
        TokenLocation::Unknown => {
            // Try common patterns
            if let Ok(body) = response.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    // Try common token field names
                    for field in ["token", "access_token", "accessToken", "jwt", "authToken"] {
                        if let Some(token) = json.get(field).and_then(|v| v.as_str()) {
                            result.token = Some(token.to_string());
                            result.token_type = AuthTokenType::Bearer;
                            break;
                        }
                    }
                }
            }

            // Fall back to cookies if no token found
            if result.token.is_none() && !result.cookies.is_empty() {
                result.token_type = AuthTokenType::Cookie;
            }
        }
    }

    if !result.success {
        result.error_message = Some(format!("Auth request returned status {}", status));
    }

    Ok(result)
}

impl AuthDiscoveryResult {
    /// Generate a summary string for logging/display
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref login) = self.login_endpoint {
            parts.push(format!("login={}", login.url));
        }

        if let Some(ref register) = self.register_endpoint {
            parts.push(format!("register={}", register.url));
        }

        if parts.is_empty() {
            "No auth endpoints discovered".to_string()
        } else {
            parts.join(", ")
        }
    }
}

impl AuthResult {
    /// Check if we have usable authentication
    pub fn has_auth(&self) -> bool {
        self.success && (self.token.is_some() || !self.cookies.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_credentials() {
        let creds = generate_test_credentials();
        assert!(creds.email.starts_with("feroxtest_"));
        assert!(creds.email.ends_with("@example.com"));
        assert_eq!(creds.password, "FeroxTest123!");
    }

    #[test]
    fn test_infer_endpoint_type() {
        assert_eq!(
            infer_endpoint_type("/api/auth/login"),
            AuthEndpointType::Login
        );
        assert_eq!(
            infer_endpoint_type("/api/auth/register"),
            AuthEndpointType::Register
        );
        assert_eq!(
            infer_endpoint_type("/oauth/token"),
            AuthEndpointType::OAuth
        );
        assert_eq!(
            infer_endpoint_type("/forgot-password"),
            AuthEndpointType::PasswordReset
        );
    }

    #[test]
    fn test_auth_endpoint_type_display() {
        assert_eq!(format!("{}", AuthEndpointType::Login), "login");
        assert_eq!(format!("{}", AuthEndpointType::Register), "register");
    }
}
