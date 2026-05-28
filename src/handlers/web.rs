use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response, Redirect},
};
use std::sync::Arc;
use tera::Context;
use tracing::error;
use crate::state::AppState;
use crate::error::AppError;
use crate::models::{PackageDisplay, PackageManifest, ProfilePackage};
use crate::utils::get_latest_version;

pub async fn home_handler(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let index = state.package_index.read().await;
    let mut packages = Vec::new();
    
    // Try to get 10 recent packages from DB
    let recent_result = sqlx::query_as::<_, (String, i64, bool)>("SELECT name, downloads, is_verified FROM packages ORDER BY updated_at DESC LIMIT 10")
        .fetch_all(&state.db)
        .await;

    match recent_result {
        Ok(recent_packages) => {
            for (name, downloads, is_verified) in recent_packages {
                if let Some(pkg) = index.get(&name) {
                    // Fetch author's tier to determine if they are verified
                    let author_tier: String = sqlx::query_scalar("SELECT tier FROM users WHERE username = ?")
                        .bind(&pkg.author)
                        .fetch_optional(&state.db)
                        .await
                        .unwrap_or(None)
                        .unwrap_or_else(|| "member".to_string());

                    let is_author_verified = author_tier == "verified" || author_tier == "staff";

                    packages.push(PackageDisplay {
                        name: pkg.name.clone(),
                        version: pkg.version.clone(),
                        description: pkg.description.clone(),
                        author: pkg.author.clone(),
                        downloads,
                        is_verified,
                        is_author_verified,
                    });
                }
            }
        },
        Err(e) => {
            error!("Database error in home_handler: {}", e);
            // Fallback: show any 10 packages from the index
            for pkg in index.values().take(10) {
                packages.push(PackageDisplay {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    description: pkg.description.clone(),
                    author: pkg.author.clone(),
                    downloads: 0,
                    is_verified: false,
                    is_author_verified: false,
                });
            }
        }
    }

    let mut context = Context::new();
    context.insert("packages", &packages);
    let html_content = state.tera.render("index.html", &context)?;
    Ok(Html(html_content))
}

pub async fn register_page_handler(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let context = Context::new();
    let html_content = state.tera.render("register.html", &context)?;
    Ok(Html(html_content))
}

pub async fn login_page_handler(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let context = Context::new();
    let html_content = state.tera.render("login.html", &context)?;
    Ok(Html(html_content))
}

pub async fn user_profile_web_handler(
    Path(username): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let user_record = sqlx::query!(
        "SELECT id, username, tier, bio FROM users WHERE username = ?",
        username
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|_| AppError::InternalError("Database error".to_string()))?;

    let user = match user_record {
        Some(u) => u,
        None => return Ok(AppError::NotFound.into_response()),
    };

    let mut packages = Vec::new();
    let package_names = sqlx::query_scalar!(
        "SELECT package_name FROM package_owners WHERE user_id = ?",
        user.id
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for name in package_names {
        if let Some(pkg_name) = name {
            let downloads: i64 = sqlx::query_scalar("SELECT downloads FROM packages WHERE name = ?")
                .bind(&pkg_name)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?
                .unwrap_or(0);
            
            packages.push(ProfilePackage { name: pkg_name, downloads });
        }
    }

    let mut context = Context::new();
    context.insert("username", &user.username);
    context.insert("tier", &user.tier);
    context.insert("bio", &user.bio);
    context.insert("packages", &packages);

    let html_content = state.tera.render("profile.html", &context)?;
    Ok(Html(html_content).into_response())
}

pub async fn dashboard_page_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppError> {
    let context = Context::new();
    let html_content = state.tera.render("dashboard.html", &context)?;
    Ok(Html(html_content))
}

pub async fn package_latest_web_handler(Path(name): Path<String>) -> Result<Response, AppError> {
    let latest = get_latest_version(&name).ok_or(AppError::NotFound)?;
    
    let redirect_url = format!("/packages/{}/{}", name, latest);
    Ok(Redirect::temporary(&redirect_url).into_response())
}

pub async fn package_version_web_handler(
    Path((name, version)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/packages/{}/{}/package.json", name, version);

    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;

    let db_pkg: (i64, bool) = sqlx::query_as("SELECT downloads, is_verified FROM packages WHERE name = ?")
        .bind(&name)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?
        .unwrap_or((0, false));

    let mut context = Context::new();
    context.insert("manifest", &manifest);
    context.insert("raw_json", &raw_json);
    context.insert("downloads", &db_pkg.0);
    context.insert("is_verified", &db_pkg.1);

    let html_content = state.tera.render("package.html", &context)?;
    Ok(Html(html_content).into_response())
}
