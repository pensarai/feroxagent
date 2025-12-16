//! Mutation engine for generating wordlist variations
//!
//! This module provides efficient, deterministic mutation generation
//! based on discovered patterns. It complements LLM generation by
//! systematically expanding patterns the LLM might miss.

use std::collections::HashSet;

/// Common REST API resource names that should be tried when API patterns are detected
const COMMON_API_RESOURCES: &[&str] = &[
    // User & Auth
    "users",
    "user",
    "auth",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "session",
    "sessions",
    "me",
    "profile",
    "account",
    "accounts",
    "password",
    "passwords",
    "token",
    "tokens",
    "refresh",
    "verify",
    "confirm",
    "activate",
    "reset",
    "forgot",
    "oauth",
    "oauth2",
    "sso",
    "saml",
    "callback",
    // Admin
    "admin",
    "administrator",
    "management",
    "manage",
    "dashboard",
    "console",
    "control",
    "panel",
    "settings",
    "config",
    "configuration",
    "preferences",
    "options",
    // CRUD Resources
    "products",
    "product",
    "items",
    "item",
    "orders",
    "order",
    "cart",
    "carts",
    "checkout",
    "payment",
    "payments",
    "invoices",
    "invoice",
    "transactions",
    "transaction",
    "subscriptions",
    "subscription",
    // Content
    "posts",
    "post",
    "articles",
    "article",
    "pages",
    "page",
    "comments",
    "comment",
    "reviews",
    "review",
    "ratings",
    "rating",
    "feedback",
    "messages",
    "message",
    "notifications",
    "notification",
    // Data & Files
    "files",
    "file",
    "uploads",
    "upload",
    "images",
    "image",
    "media",
    "documents",
    "document",
    "attachments",
    "attachment",
    "exports",
    "export",
    "imports",
    "import",
    "reports",
    "report",
    // System
    "health",
    "healthz",
    "status",
    "version",
    "info",
    "ping",
    "metrics",
    "stats",
    "statistics",
    "analytics",
    "logs",
    "log",
    "events",
    "event",
    "audit",
    "debug",
    "trace",
    "diagnostics",
    // Search & Query
    "search",
    "query",
    "filter",
    "find",
    "lookup",
    "suggest",
    "autocomplete",
    "typeahead",
    // Relationships
    "groups",
    "group",
    "teams",
    "team",
    "organizations",
    "organization",
    "org",
    "orgs",
    "roles",
    "role",
    "permissions",
    "permission",
    "members",
    "member",
    "followers",
    "following",
    "friends",
    "contacts",
    "categories",
    "category",
    "tags",
    "tag",
    // Misc
    "internal",
    "private",
    "public",
    "external",
    "webhook",
    "webhooks",
    "hooks",
    "hook",
    "callbacks",
    "batch",
    "bulk",
    "async",
    "sync",
    "queue",
    "jobs",
    "job",
    "tasks",
    "task",
    "workers",
    "worker",
];

/// Common auth-related endpoint suffixes
const AUTH_ENDPOINTS: &[&str] = &[
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "signout",
    "me",
    "current",
    "profile",
    "session",
    "token",
    "refresh",
    "verify",
    "confirm",
    "activate",
    "reset-password",
    "forgot-password",
    "change-password",
    "update-password",
    "2fa",
    "mfa",
    "otp",
    "magic-link",
    "passwordless",
];

/// Common admin-related endpoint suffixes
const ADMIN_ENDPOINTS: &[&str] = &[
    "users",
    "roles",
    "permissions",
    "settings",
    "config",
    "diagnostics",
    "logs",
    "audit",
    "stats",
    "metrics",
    "reports",
    "dashboard",
    "system",
    "backup",
    "restore",
    "import",
    "export",
    "cache",
    "jobs",
    "queues",
    "health",
];

/// CRUD action suffixes for resources
const CRUD_SUFFIXES: &[&str] = &[
    "",       // base resource
    "new",    // create form
    "create", // create action
    "edit",   // edit form
    "update", // update action
    "delete", // delete action
    "list",   // list view
    "all",    // get all
    "search", // search
    "find",   // find
    "filter", // filter
    "count",  // count
    "export", // export
    "import", // import
    "bulk",   // bulk operations
    "batch",  // batch operations
];

/// Common ID values to test for parameterized endpoints
/// NOTE: Only numeric values - string values like "admin", "user" etc. cause false positives
/// where /api/admin/users becomes /api/{id}/users incorrectly
const COMMON_IDS: &[&str] = &["1", "2", "0", "100", "999", "1000", "-1"];

/// Common UUID patterns to test
const COMMON_UUIDS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
];

/// Next.js specific paths
const NEXTJS_PATHS: &[&str] = &[
    "/_next/data",
    "/_next/image",
    "/_next/static",
    "/__nextjs_original-stack-frame",
    "/api",
    "/api/auth/[...nextauth]",
    "/api/auth/callback",
    "/api/auth/csrf",
    "/api/auth/error",
    "/api/auth/providers",
    "/api/auth/session",
    "/api/auth/signin",
    "/api/auth/signout",
    "/api/preview",
    "/api/revalidate",
];

/// Rails specific paths
const RAILS_PATHS: &[&str] = &[
    "/rails/info",
    "/rails/info/properties",
    "/rails/info/routes",
    "/rails/mailers",
    "/rails/conductor/action_mailbox/inbound_emails",
    "/sidekiq",
    "/sidekiq/busy",
    "/sidekiq/queues",
    "/sidekiq/retries",
    "/sidekiq/scheduled",
    "/sidekiq/dead",
    "/admin",
    "/admin/dashboard",
    "/users/sign_in",
    "/users/sign_up",
    "/users/password/new",
    "/users/confirmation/new",
];

/// Django specific paths
const DJANGO_PATHS: &[&str] = &[
    "/admin/",
    "/admin/login/",
    "/admin/logout/",
    "/admin/password_change/",
    "/__debug__/",
    "/static/admin/",
    "/accounts/login/",
    "/accounts/logout/",
    "/accounts/signup/",
    "/api-auth/",
    "/api-auth/login/",
    "/api-token-auth/",
    "/rest-auth/",
    "/dj-rest-auth/",
    "/silk/",
    "/silk/requests/",
];

/// Spring Boot specific paths
const SPRING_PATHS: &[&str] = &[
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/prometheus",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/actuator/scheduledtasks",
    "/actuator/httptrace",
    "/actuator/caches",
    "/actuator/shutdown",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/webjars/",
    "/h2-console",
    "/h2-console/",
];

/// Laravel specific paths
const LARAVEL_PATHS: &[&str] = &[
    "/login",
    "/logout",
    "/register",
    "/password/reset",
    "/password/email",
    "/email/verify",
    "/sanctum/csrf-cookie",
    "/api/user",
    "/horizon",
    "/horizon/api",
    "/telescope",
    "/telescope/requests",
    "/nova",
    "/nova/login",
    "/_debugbar",
    "/storage",
    "/storage/logs",
];

/// Express.js / Node.js specific paths
const EXPRESS_PATHS: &[&str] = &[
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/live",
    "/livez",
    "/metrics",
    "/api/health",
    "/api/status",
    "/graphql",
    "/graphiql",
    "/playground",
    "/socket.io",
    "/socket.io/socket.io.js",
    "/.well-known",
    "/api-docs",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
];

/// ASP.NET specific paths
const ASPNET_PATHS: &[&str] = &[
    "/elmah.axd",
    "/trace.axd",
    "/webresource.axd",
    "/scriptresource.axd",
    "/_vti_bin/",
    "/web.config",
    "/applicationhost.config",
    "/api/values",
    "/swagger",
    "/swagger/index.html",
    "/swagger/v1/swagger.json",
    "/health",
    "/healthcheck",
    "/hangfire",
    "/hangfire/dashboard",
];

/// WordPress specific paths
const WORDPRESS_PATHS: &[&str] = &[
    "/wp-admin/",
    "/wp-admin/admin-ajax.php",
    "/wp-admin/post.php",
    "/wp-admin/users.php",
    "/wp-admin/options-general.php",
    "/wp-admin/plugins.php",
    "/wp-admin/theme-editor.php",
    "/wp-login.php",
    "/wp-json/",
    "/wp-json/wp/v2/",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/posts",
    "/wp-json/wp/v2/pages",
    "/wp-content/uploads/",
    "/wp-content/plugins/",
    "/wp-content/themes/",
    "/wp-includes/",
    "/xmlrpc.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.wp-config.php.swp",
];

/// GraphQL specific paths
const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/graphiql",
    "/playground",
    "/altair",
    "/voyager",
    "/graphql/schema",
    "/graphql/console",
    "/api/graphql",
    "/v1/graphql",
    "/.well-known/apollo/server-health",
];

/// Generic sensitive paths that should always be checked
const SENSITIVE_PATHS: &[&str] = &[
    // Git exposure
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.gitattributes",
    // Environment files
    "/.env",
    "/.env.local",
    "/.env.development",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.example",
    // Config files
    "/config.json",
    "/config.yml",
    "/config.yaml",
    "/settings.json",
    "/settings.yml",
    "/secrets.json",
    "/secrets.yml",
    "/credentials.json",
    // Package files
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/composer.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    // Docker
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/Dockerfile",
    "/.dockerignore",
    // CI/CD
    "/.gitlab-ci.yml",
    "/.travis.yml",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/.github/workflows",
    // IDE
    "/.vscode/settings.json",
    "/.idea/workspace.xml",
    // Debug & Info
    "/debug",
    "/trace",
    "/info",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/server-status",
    "/server-info",
    // Backups
    "/backup",
    "/backup.sql",
    "/backup.zip",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/.htaccess",
    "/.htpasswd",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    // Security
    "/security.txt",
    "/.well-known/security.txt",
    // API documentation
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/docs",
    "/documentation",
    "/redoc",
];

/// Detected framework for targeted mutations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Framework {
    NextJs,
    Rails,
    Django,
    Spring,
    Laravel,
    Express,
    AspNet,
    WordPress,
    GraphQL,
}

/// Mutation engine configuration
#[derive(Debug, Clone)]
pub struct MutationConfig {
    /// Generate ID variations for parameterized paths
    pub expand_ids: bool,
    /// Generate common API resource mutations
    pub expand_resources: bool,
    /// Generate auth endpoint variations
    pub expand_auth: bool,
    /// Generate admin endpoint variations
    pub expand_admin: bool,
    /// Generate CRUD suffix variations
    pub expand_crud: bool,
    /// Include framework-specific paths
    pub include_framework_paths: bool,
    /// Include generic sensitive paths
    pub include_sensitive_paths: bool,
    /// Detected frameworks (empty = auto-detect)
    pub frameworks: Vec<Framework>,
    /// Maximum mutations to generate (0 = unlimited)
    pub max_mutations: usize,
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            expand_ids: true,
            expand_resources: true,
            expand_auth: true,
            expand_admin: true,
            expand_crud: true,
            include_framework_paths: true,
            include_sensitive_paths: true,
            frameworks: Vec::new(), // Auto-detect
            max_mutations: 5000,    // Reasonable limit to avoid explosion
        }
    }
}

/// Generate mutations based on discovered API patterns
pub fn generate_mutations(
    discovered_paths: &[String],
    api_endpoints: &[String],
    config: &MutationConfig,
) -> Vec<String> {
    let mut mutations: HashSet<String> = HashSet::new();

    // Detect if we have API patterns
    let has_api = api_endpoints.iter().any(|e| e.contains("/api/"))
        || discovered_paths.iter().any(|p| p.contains("/api/"));

    // Detect API prefix patterns
    let api_prefixes = detect_api_prefixes(discovered_paths, api_endpoints);

    // Generate base API resource mutations
    if config.expand_resources && has_api {
        for prefix in &api_prefixes {
            add_resource_mutations(&mut mutations, prefix, config);
        }
    }

    // Generate auth endpoint mutations
    if config.expand_auth {
        for prefix in &api_prefixes {
            add_auth_mutations(&mut mutations, prefix);
        }
        // Also try common auth paths without API prefix
        add_auth_mutations(&mut mutations, "");
    }

    // Generate admin endpoint mutations
    if config.expand_admin {
        for prefix in &api_prefixes {
            add_admin_mutations(&mut mutations, prefix);
        }
        // Also try admin paths at root
        add_standalone_admin_mutations(&mut mutations);
    }

    // Generate mutations from discovered patterns
    for path in discovered_paths.iter().chain(api_endpoints.iter()) {
        add_path_mutations(&mut mutations, path, config);
    }

    // Generate ID variations for parameterized patterns
    if config.expand_ids {
        let param_patterns = extract_parameterized_patterns(discovered_paths, api_endpoints);
        for pattern in param_patterns {
            add_id_mutations(&mut mutations, &pattern);
        }
    }

    // Add framework-specific paths
    if config.include_framework_paths {
        let frameworks = if config.frameworks.is_empty() {
            detect_frameworks(discovered_paths, api_endpoints)
        } else {
            config.frameworks.clone()
        };

        for framework in &frameworks {
            add_framework_paths(&mut mutations, framework);
        }
    }

    // Add generic sensitive paths
    if config.include_sensitive_paths {
        for path in SENSITIVE_PATHS {
            mutations.insert(path.to_string());
        }
    }

    // Convert to vec and enforce limit
    let mut result: Vec<String> = mutations.into_iter().collect();
    result.sort();

    if config.max_mutations > 0 && result.len() > config.max_mutations {
        result.truncate(config.max_mutations);
    }

    result
}

/// Detect frameworks from discovered paths
fn detect_frameworks(discovered_paths: &[String], api_endpoints: &[String]) -> Vec<Framework> {
    let mut frameworks: HashSet<Framework> = HashSet::new();

    let all_paths: Vec<&str> = discovered_paths
        .iter()
        .chain(api_endpoints.iter())
        .map(|s| s.as_str())
        .collect();

    for path in &all_paths {
        let lower = path.to_lowercase();

        // Next.js detection
        if lower.contains("/_next/") || lower.contains("__nextjs") {
            frameworks.insert(Framework::NextJs);
        }

        // Rails detection
        if lower.contains("/rails/")
            || lower.contains("/sidekiq")
            || lower.contains("/packs/")
            || lower.contains("/assets/") && lower.contains("-")
        {
            frameworks.insert(Framework::Rails);
        }

        // Django detection
        if lower.contains("/__debug__/")
            || lower.contains("/django")
            || (lower.contains("/static/") && lower.contains("/admin/"))
        {
            frameworks.insert(Framework::Django);
        }

        // Spring detection
        if lower.contains("/actuator/")
            || lower.contains("/swagger-ui")
            || lower.contains("/v2/api-docs")
            || lower.contains("/v3/api-docs")
        {
            frameworks.insert(Framework::Spring);
        }

        // Laravel detection
        if lower.contains("/livewire/")
            || lower.contains("/horizon")
            || lower.contains("/telescope")
            || lower.contains("/nova")
            || lower.contains("/sanctum/")
        {
            frameworks.insert(Framework::Laravel);
        }

        // Express/Node detection
        if lower.contains("/socket.io") || lower.contains("/graphql") || lower.contains("/graphiql")
        {
            frameworks.insert(Framework::Express);
        }

        // ASP.NET detection
        if lower.contains(".aspx")
            || lower.contains(".ashx")
            || lower.contains("/_vti_bin/")
            || lower.contains("/elmah")
        {
            frameworks.insert(Framework::AspNet);
        }

        // WordPress detection
        if lower.contains("/wp-admin/")
            || lower.contains("/wp-content/")
            || lower.contains("/wp-json/")
            || lower.contains("/wp-includes/")
        {
            frameworks.insert(Framework::WordPress);
        }

        // GraphQL detection
        if lower.contains("/graphql") || lower.contains("/graphiql") || lower.contains("/gql") {
            frameworks.insert(Framework::GraphQL);
        }
    }

    frameworks.into_iter().collect()
}

/// Add framework-specific paths
fn add_framework_paths(mutations: &mut HashSet<String>, framework: &Framework) {
    let paths: &[&str] = match framework {
        Framework::NextJs => NEXTJS_PATHS,
        Framework::Rails => RAILS_PATHS,
        Framework::Django => DJANGO_PATHS,
        Framework::Spring => SPRING_PATHS,
        Framework::Laravel => LARAVEL_PATHS,
        Framework::Express => EXPRESS_PATHS,
        Framework::AspNet => ASPNET_PATHS,
        Framework::WordPress => WORDPRESS_PATHS,
        Framework::GraphQL => GRAPHQL_PATHS,
    };

    for path in paths {
        mutations.insert(path.to_string());
    }
}

/// Detect API prefixes from discovered paths (e.g., /api, /api/v1, /v1)
fn detect_api_prefixes(discovered_paths: &[String], api_endpoints: &[String]) -> Vec<String> {
    let mut prefixes: HashSet<String> = HashSet::new();

    // Always include common prefixes
    prefixes.insert("/api".to_string());

    for path in discovered_paths.iter().chain(api_endpoints.iter()) {
        // Match /api/vN/ pattern
        if let Some(idx) = path.find("/api/v") {
            if let Some(end) = path[idx + 6..].find('/') {
                let prefix = &path[..idx + 6 + end];
                prefixes.insert(prefix.to_string());
            } else if path.len() > idx + 6 {
                // e.g., /api/v1 without trailing content
                let version_char = path.chars().nth(idx + 6);
                if let Some(c) = version_char {
                    if c.is_ascii_digit() {
                        prefixes.insert(format!("/api/v{}", c));
                    }
                }
            }
        }

        // Match bare /api/ pattern
        if path.starts_with("/api/") && !path.starts_with("/api/v") {
            prefixes.insert("/api".to_string());
        }

        // Match /vN/ pattern at root
        if path.starts_with("/v1/") || path.starts_with("/v2/") || path.starts_with("/v3/") {
            prefixes.insert(path[..3].to_string());
        }
    }

    prefixes.into_iter().collect()
}

/// Add resource mutations for an API prefix
/// NOTE: Only adds base resource paths - CRUD suffixes are only added for discovered resources
fn add_resource_mutations(mutations: &mut HashSet<String>, prefix: &str, _config: &MutationConfig) {
    for resource in COMMON_API_RESOURCES {
        let base = if prefix.is_empty() {
            format!("/{}", resource)
        } else {
            format!("{}/{}", prefix, resource)
        };
        // Only add the base resource path - don't speculatively add CRUD suffixes
        // CRUD suffixes will be added by add_path_mutations() for paths we actually discovered
        mutations.insert(base);
    }
}

/// Add auth endpoint mutations
fn add_auth_mutations(mutations: &mut HashSet<String>, prefix: &str) {
    let auth_base = if prefix.is_empty() {
        "/auth".to_string()
    } else {
        format!("{}/auth", prefix)
    };

    mutations.insert(auth_base.clone());

    for endpoint in AUTH_ENDPOINTS {
        mutations.insert(format!("{}/{}", auth_base, endpoint));
    }

    // Also add direct login/logout at prefix level
    if !prefix.is_empty() {
        mutations.insert(format!("{}/login", prefix));
        mutations.insert(format!("{}/logout", prefix));
        mutations.insert(format!("{}/register", prefix));
        mutations.insert(format!("{}/me", prefix));
    }
}

/// Add admin endpoint mutations
fn add_admin_mutations(mutations: &mut HashSet<String>, prefix: &str) {
    let admin_base = if prefix.is_empty() {
        "/admin".to_string()
    } else {
        format!("{}/admin", prefix)
    };

    mutations.insert(admin_base.clone());

    for endpoint in ADMIN_ENDPOINTS {
        mutations.insert(format!("{}/{}", admin_base, endpoint));
    }
}

/// Add standalone admin paths
fn add_standalone_admin_mutations(mutations: &mut HashSet<String>) {
    // Root admin paths
    mutations.insert("/admin".to_string());
    mutations.insert("/admin/login".to_string());
    mutations.insert("/admin/dashboard".to_string());
    mutations.insert("/administrator".to_string());
    mutations.insert("/manage".to_string());
    mutations.insert("/management".to_string());
    mutations.insert("/portal".to_string());
    mutations.insert("/console".to_string());
    mutations.insert("/cpanel".to_string());

    // CMS-specific admin paths
    mutations.insert("/wp-admin".to_string());
    mutations.insert("/wp-login.php".to_string());
    mutations.insert("/user/login".to_string());
    mutations.insert("/users/sign_in".to_string());
}

/// Add mutations based on a discovered path pattern
fn add_path_mutations(mutations: &mut HashSet<String>, path: &str, config: &MutationConfig) {
    // Skip static assets
    if is_static_asset(path) {
        return;
    }

    // Add the path itself
    mutations.insert(path.to_string());

    // Parse path segments
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segments.is_empty() {
        return;
    }

    // If this looks like /api/resource, generate related resources
    if segments.len() >= 2 && segments[0] == "api" {
        let resource = segments[1];
        let prefix = "/api";

        // Generate related resource mutations
        if let Some(related) = get_related_resources(resource) {
            for rel in related {
                mutations.insert(format!("{}/{}", prefix, rel));
            }
        }

        // Generate CRUD suffixes for the resource
        if config.expand_crud {
            for suffix in CRUD_SUFFIXES {
                if !suffix.is_empty() {
                    mutations.insert(format!("{}/{}/{}", prefix, resource, suffix));
                }
            }
        }
    }

    // If path has ID-like segments, generate ID variations
    for (i, segment) in segments.iter().enumerate() {
        if looks_like_id(segment) && config.expand_ids {
            // Build base path up to the ID segment
            let base: String = format!("/{}", segments[..i].join("/"));
            if !base.is_empty() && base != "/" {
                add_id_mutations(mutations, &base);
            }
        }
    }
}

/// Add ID mutations for a base path
fn add_id_mutations(mutations: &mut HashSet<String>, base_path: &str) {
    for id in COMMON_IDS {
        mutations.insert(format!("{}/{}", base_path, id));
    }

    for uuid in COMMON_UUIDS {
        mutations.insert(format!("{}/{}", base_path, uuid));
    }
}

/// Extract paths that look parameterized (contain ID-like segments)
fn extract_parameterized_patterns(
    discovered_paths: &[String],
    api_endpoints: &[String],
) -> Vec<String> {
    let mut patterns: HashSet<String> = HashSet::new();

    for path in discovered_paths.iter().chain(api_endpoints.iter()) {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        for (i, segment) in segments.iter().enumerate() {
            if looks_like_id(segment) {
                // This segment looks like an ID, extract the pattern
                let pattern_base: String = format!("/{}", segments[..i].join("/"));
                if !pattern_base.is_empty() && pattern_base != "/" {
                    patterns.insert(pattern_base);
                }
            }
        }
    }

    patterns.into_iter().collect()
}

/// Check if a segment looks like an ID (numeric, UUID, hash, etc.)
fn looks_like_id(segment: &str) -> bool {
    // Numeric ID
    if segment.parse::<u64>().is_ok() {
        return true;
    }

    // UUID pattern (rough check)
    if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
        return true;
    }

    // Hash-like (long alphanumeric string)
    if segment.len() > 16 && segment.chars().all(|c| c.is_alphanumeric()) {
        return true;
    }

    // MongoDB ObjectId (24 hex chars)
    if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    false
}

/// Check if a path is a static asset
fn is_static_asset(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/_next/static")
        || lower.contains("/static/")
        || lower.ends_with(".js")
        || lower.ends_with(".css")
        || lower.ends_with(".map")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".ico")
}

/// Get related resources based on a discovered resource name
fn get_related_resources(resource: &str) -> Option<Vec<&'static str>> {
    match resource {
        "users" | "user" => Some(vec![
            "auth",
            "roles",
            "permissions",
            "groups",
            "teams",
            "profiles",
            "sessions",
        ]),
        "products" | "product" => Some(vec![
            "categories",
            "orders",
            "reviews",
            "ratings",
            "inventory",
            "cart",
            "wishlist",
        ]),
        "orders" | "order" => Some(vec![
            "products", "payments", "shipping", "invoices", "refunds", "cart",
        ]),
        "posts" | "post" => Some(vec![
            "comments",
            "categories",
            "tags",
            "authors",
            "likes",
            "shares",
        ]),
        "auth" => Some(vec![
            "users",
            "sessions",
            "tokens",
            "roles",
            "permissions",
            "oauth",
        ]),
        "admin" => Some(vec![
            "users",
            "roles",
            "settings",
            "config",
            "logs",
            "diagnostics",
            "reports",
        ]),
        _ => None,
    }
}

/// Expand parameterized paths in LLM output (e.g., /api/products/{id} -> /api/products/1, etc.)
pub fn expand_parameterized_paths(paths: Vec<String>) -> Vec<String> {
    let mut expanded: HashSet<String> = HashSet::new();

    for path in paths {
        if path.contains("{id}") || path.contains("{{id}}") {
            // Add numeric IDs
            for id in COMMON_IDS {
                let expanded_path = path.replace("{{id}}", id).replace("{id}", id);
                expanded.insert(expanded_path);
            }

            // Add UUIDs
            for uuid in COMMON_UUIDS {
                let expanded_path = path.replace("{{id}}", uuid).replace("{id}", uuid);
                expanded.insert(expanded_path);
            }

            // Also add the base path without the ID segment
            let base = path
                .replace("{{id}}", "")
                .replace("{id}", "")
                .trim_end_matches('/')
                .to_string();
            if !base.is_empty() {
                expanded.insert(base);
            }
        } else {
            expanded.insert(path);
        }
    }

    let mut result: Vec<String> = expanded.into_iter().collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_api_prefixes() {
        let paths = vec![
            "/api/users".to_string(),
            "/api/v1/products".to_string(),
            "/api/v2/orders".to_string(),
        ];
        let prefixes = detect_api_prefixes(&paths, &[]);

        assert!(prefixes.contains(&"/api".to_string()));
        assert!(prefixes.contains(&"/api/v1".to_string()));
        assert!(prefixes.contains(&"/api/v2".to_string()));
    }

    #[test]
    fn test_generate_mutations_includes_common_resources() {
        let paths = vec!["/api/users".to_string()];
        let config = MutationConfig::default();
        let mutations = generate_mutations(&paths, &[], &config);

        // Should include auth endpoints
        assert!(mutations.contains(&"/api/auth/login".to_string()));
        assert!(mutations.contains(&"/api/auth/me".to_string()));
        assert!(mutations.contains(&"/api/auth/register".to_string()));

        // Should include admin endpoints
        assert!(mutations.contains(&"/api/admin".to_string()));
        assert!(mutations.contains(&"/api/admin/users".to_string()));
        assert!(mutations.contains(&"/api/admin/diagnostics".to_string()));

        // Should include common resources
        assert!(mutations.contains(&"/api/products".to_string()));
        assert!(mutations.contains(&"/api/orders".to_string()));
        assert!(mutations.contains(&"/api/reviews".to_string()));
    }

    #[test]
    fn test_looks_like_id() {
        assert!(looks_like_id("123"));
        assert!(looks_like_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(looks_like_id("507f1f77bcf86cd799439011")); // MongoDB ObjectId
        assert!(!looks_like_id("users"));
        assert!(!looks_like_id("api"));
    }

    #[test]
    fn test_expand_parameterized_paths() {
        let paths = vec!["/api/products/{id}".to_string(), "/api/users".to_string()];
        let expanded = expand_parameterized_paths(paths);

        assert!(expanded.contains(&"/api/products/1".to_string()));
        assert!(expanded.contains(&"/api/products/100".to_string()));
        assert!(expanded.contains(&"/api/users".to_string()));
        // Base path should be included
        assert!(expanded.contains(&"/api/products".to_string()));
        // Should NOT contain string values that cause false positives
        assert!(!expanded.contains(&"/api/products/admin".to_string()));
    }

    #[test]
    fn test_related_resources() {
        let related = get_related_resources("products").unwrap();
        assert!(related.contains(&"reviews"));
        assert!(related.contains(&"orders"));
        assert!(related.contains(&"categories"));
    }
}
