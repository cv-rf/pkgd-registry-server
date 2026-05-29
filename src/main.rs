mod error;
mod models;
mod state;
mod utils;
mod handlers;

use axum::{
    routing::{get, post},
    Router,
    extract::DefaultBodyLimit,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::sync::RwLock;
use tera::Tera;
use tower_http::trace::TraceLayer;
use std::net::SocketAddr;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer, key_extractor::SmartIpKeyExtractor};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::state::AppState;
use crate::utils::{build_initial_index, migrate_storage};
use crate::handlers::{
    auth::{login_handler, logout_handler, register_handler},
    package::{
        download_handler, package_latest_api_handler, package_version_api_handler,
        publish_handler, search_api_handler,
    },
    web::{
        home_handler, login_page_handler, package_latest_web_handler,
        package_version_web_handler, register_page_handler, user_profile_web_handler,
        dashboard_page_handler,
    },
    admin::{
        api_dashboard_handler, api_list_users_handler, toggle_verify_handler,
        upgrade_user_handler,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pkgd_registry_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args: Vec<String> = std::env::args().collect();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/pkgd_registry".to_string());

    tracing::info!("Connecting to database: {}", database_url);

    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to database at {}: {}", database_url, e);
            e
        })?;
    
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'member',
            bio TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            token TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS package_owners (
            package_name TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS packages (
            name TEXT PRIMARY KEY,
            downloads BIGINT DEFAULT 0,
            is_verified BOOLEAN DEFAULT FALSE,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"
    )
    .execute(&db_pool)
    .await?;

    let check_col = sqlx::query("SELECT updated_at FROM packages LIMIT 1")
        .fetch_optional(&db_pool)
        .await;
    
    if check_col.is_err() {
        info!("Adding updated_at column to packages table...");
        let _ = sqlx::query("ALTER TABLE packages ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            .execute(&db_pool)
            .await;
    }

    migrate_storage();

    if args.len() >= 4 && args[1] == "admin-upgrade" {
        let username = &args[2];
        let tier = &args[3];
        
        let valid_tiers = ["member", "supporter", "partner", "verified", "staff"];
        if !valid_tiers.contains(&tier.as_str()) {
            eprintln!("Invalid tier: {}. Valid tiers: {:?}", tier, valid_tiers);
            return Ok(());
        }

        let result = sqlx::query("UPDATE users SET tier = $1 WHERE username = $2")
            .bind(tier)
            .bind(username)
            .execute(&db_pool)
            .await?;

        if result.rows_affected() == 0 {
            eprintln!("User '{}' not found.", username);
        } else {
            println!("User '{}' upgraded to tier '{}'.", username, tier);
        }
        return Ok(());
    }

    let mut tera = Tera::new("templates/**/*").expect("Failed to compile templates");
    tera.autoescape_on(vec!["html", "xml"]);
    let initial_index = build_initial_index();

    let shared_state = Arc::new(AppState { 
        tera,
        package_index: RwLock::new(initial_index),
        db: db_pool,
    });

    let auth_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(2)
            .burst_size(5)
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/", get(home_handler))

        .route("/register", get(register_page_handler))
        .route("/login", get(login_page_handler))

        .route("/users/{username}", get(user_profile_web_handler))
        .route("/dashboard", get(dashboard_page_handler))

        .route("/api/register", post(register_handler).layer(GovernorLayer { config: auth_governor_conf.clone() }))
        .route("/api/login", post(login_handler).layer(GovernorLayer { config: auth_governor_conf }))
        .route("/api/logout", post(logout_handler))
        .route("/api/admin/dashboard", get(api_dashboard_handler))
        .route("/api/admin/users", get(api_list_users_handler))
        .route("/api/admin/verify", post(toggle_verify_handler))
        .route("/api/admin/upgrade-user", post(upgrade_user_handler))

        .route("/packages/{name}", get(package_latest_web_handler))
        .route("/packages/{name}/{version}", get(package_version_web_handler))
        
        .route("/api/search", get(search_api_handler))
        .route("/api/packages/{name}", get(package_latest_api_handler))
        .route("/api/packages/{name}/{version}", get(package_version_api_handler))

        .route("/api/publish", post(publish_handler).layer(DefaultBodyLimit::max(50 * 1024 * 1024)))
        .route("/download/{file}", get(download_handler))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9999").await?;
    info!("Registry Server running on http://0.0.0.0:9999");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
