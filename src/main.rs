mod error;
mod models;
mod state;
mod utils;
mod handlers;
mod scanner;

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
    auth::{
        login_handler, logout_handler, register_handler, get_profile_handler, 
        update_bio_handler, regenerate_token_handler, update_profile_handler,
        update_password_handler, list_tokens_handler, create_token_handler, revoke_token_handler,
        list_public_keys_handler, add_public_key_handler, delete_public_key_handler
    },

    package::{
        download_handler, publish_handler, search_api_handler, 
        package_api_handler,
        get_author_keys_handler
    },
    web::{
        home_handler, login_page_handler, register_page_handler, user_profile_web_handler,
        dashboard_page_handler, profile_edit_page_handler, package_web_handler,
        install_sh_handler, tos_handler, privacy_handler,
    },
    admin::{
        api_dashboard_handler, api_list_users_handler, toggle_verify_handler,
        upgrade_user_handler, admin_delete_package_handler, toggle_user_verify_handler,
        toggle_safety_handler, toggle_suspension_handler
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

    tracing::info!("Starting initialization sequence...");
    tracing::info!("Connecting to database: {}", database_url);

    let mut db_pool = None;
    for i in 1..=30 {
        match PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&database_url)
            .await
        {
            Ok(pool) => {
                db_pool = Some(pool);
                tracing::info!("Successfully connected to database on attempt {}", i);
                break;
            }
            Err(e) => {
                if i == 30 {
                    tracing::error!("CRITICAL: Failed to connect to database after 30 attempts: {}", e);
                    return Err(e.into());
                }
                tracing::warn!("Database connection attempt {} failed: {}. Retrying in 2s...", i, e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
    let db_pool = db_pool.unwrap();
    
    tracing::info!("Ensuring database tables exist...");
    let tables = [
        "CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tier TEXT NOT NULL DEFAULT 'member',
            bio TEXT DEFAULT '',
            avatar_url TEXT,
            github_url TEXT,
            twitter_url TEXT,
            website_url TEXT,
            is_verified BOOLEAN DEFAULT FALSE,
            is_suspended BOOLEAN DEFAULT FALSE
        )",
        "CREATE TABLE IF NOT EXISTS api_tokens (
            token TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id),
            name TEXT DEFAULT 'Default Token',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS package_owners (
            package_name TEXT NOT NULL,
            namespace TEXT NOT NULL DEFAULT '@global',
            user_id BIGINT NOT NULL REFERENCES users(id),
            PRIMARY KEY (package_name, namespace)
        )",
        "CREATE TABLE IF NOT EXISTS packages (
            name TEXT PRIMARY KEY,
            namespace TEXT DEFAULT '@global',
            package_name TEXT,
            downloads BIGINT DEFAULT 0,
            is_verified BOOLEAN DEFAULT FALSE,
            safety_status TEXT DEFAULT 'safe',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        "CREATE TABLE IF NOT EXISTS user_public_keys (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id),
            key_name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"
        ];

    for table_query in tables {
        sqlx::query(table_query)
            .execute(&db_pool)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create table: {}", e);
                e
            })?;
    }

    // Migration for new user and token columns - simplified and robust
    tracing::info!("Checking for schema migrations...");
    let migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS github_url TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS twitter_url TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS website_url TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN DEFAULT FALSE",
        "ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS name TEXT DEFAULT 'Default Token'",
        "ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "ALTER TABLE packages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        "ALTER TABLE packages ADD COLUMN IF NOT EXISTS safety_status TEXT DEFAULT 'safe'",
        "ALTER TABLE packages ADD COLUMN IF NOT EXISTS namespace TEXT DEFAULT '@global'",
        "ALTER TABLE packages ADD COLUMN IF NOT EXISTS package_name TEXT",
        "ALTER TABLE package_owners ADD COLUMN IF NOT EXISTS namespace TEXT DEFAULT '@global'",
        // Fix for primary key in package_owners to support namespacing
        "DO $$ 
         BEGIN 
            IF EXISTS (SELECT 1 FROM information_schema.table_constraints WHERE constraint_name = 'package_owners_pkey' AND table_name = 'package_owners') THEN
                -- Check if the PK is already composite (includes namespace)
                IF (SELECT count(*) FROM information_schema.key_column_usage WHERE table_name = 'package_owners' AND constraint_name = 'package_owners_pkey') = 1 THEN
                    ALTER TABLE package_owners DROP CONSTRAINT package_owners_pkey;
                    ALTER TABLE package_owners ADD PRIMARY KEY (package_name, namespace);
                END IF;
            END IF;
         END $$;",
    ];

    for q in migrations {
        if let Err(e) = sqlx::query(q).execute(&db_pool).await {
            tracing::warn!("Migration query '{}' failed (possibly already applied): {}", q, e);
        }
    }

    tracing::info!("Migrating local storage...");
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
            eprintln!("User \"{}\" not found.", username);
        } else {
            println!("User \"{}\" upgraded to tier \"{}\".", username, tier);
        }
        return Ok(());
    }

    tracing::info!("Compiling templates and indexing packages...");
    let mut tera = Tera::new("templates/**/*").expect("Failed to compile templates");
    tera.autoescape_on(vec!["html", "xml"]);
    let mut initial_file_map = std::collections::HashMap::new();
    let initial_index = build_initial_index(&mut initial_file_map);

    let shared_state = Arc::new(AppState { 
        tera,
        package_index: RwLock::new(initial_index),
        file_map: RwLock::new(initial_file_map),
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
        .route("/settings", get(profile_edit_page_handler))

        .route("/api/register", post(register_handler).layer(GovernorLayer { config: auth_governor_conf.clone() }))
        .route("/api/login", post(login_handler).layer(GovernorLayer { config: auth_governor_conf }))
        .route("/api/logout", post(logout_handler))
        .route("/api/profile", get(get_profile_handler))
        .route("/api/profile/bio", post(update_bio_handler))
        .route("/api/profile/token", post(regenerate_token_handler))
        .route("/api/profile/update", post(update_profile_handler))
        .route("/api/profile/password", post(update_password_handler))
        .route("/api/profile/tokens", get(list_tokens_handler).post(create_token_handler))
        .route("/api/profile/tokens/{token}", axum::routing::delete(revoke_token_handler))
        .route("/api/profile/keys", get(list_public_keys_handler).post(add_public_key_handler))
        .route("/api/profile/keys/{key}", axum::routing::delete(delete_public_key_handler))
        .route("/api/authors/{author_name}/keys", get(get_author_keys_handler))
        .route("/api/admin/dashboard", get(api_dashboard_handler))
        .route("/api/admin/users", get(api_list_users_handler))
        .route("/api/admin/verify", post(toggle_verify_handler))
        .route("/api/admin/verify-user", post(toggle_user_verify_handler))
        .route("/api/admin/safety", post(toggle_safety_handler))
        .route("/api/admin/suspend", post(toggle_suspension_handler))
        .route("/api/admin/upgrade-user", post(upgrade_user_handler))
        .route("/api/admin/packages/{*name}", axum::routing::delete(admin_delete_package_handler))

        .route("/packages/{*path}", get(package_web_handler))
        .route("/install.sh", get(install_sh_handler))
        .route("/tos", get(tos_handler))
        .route("/privacy", get(privacy_handler))
        
        .route("/api/search", get(search_api_handler))
        .route("/api/packages/{*path}", 
            get(package_api_handler)
            .delete(package_api_handler)
        )

        .route("/api/publish", post(publish_handler).layer(DefaultBodyLimit::max(50 * 1024 * 1024)))
        .route("/download/{*file}", get(download_handler))
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9999").await?;
    info!("Registry Server running on http://0.0.0.0:9999");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
