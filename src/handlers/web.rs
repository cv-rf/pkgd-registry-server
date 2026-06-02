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
use crate::utils::{get_latest_version, get_all_versions, split_package_name};
use md5;

pub async fn home_handler(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let mut packages = Vec::new();
    
    let recent_result = sqlx::query_as::<_, (String, i64, bool, String)>("SELECT name, downloads, is_verified, safety_status FROM packages ORDER BY updated_at DESC LIMIT 10")
        .fetch_all(&state.db)
        .await;

    match recent_result {
        Ok(recent_packages) => {
            let index = state.package_index.read().await;
            for (name, downloads, is_verified, safety_status) in recent_packages {
                if let Some(pkg) = index.get(&name) {
                    
                    let is_author_verified: bool = sqlx::query_scalar("SELECT is_verified FROM users WHERE username = $1")
                        .bind(&pkg.author)
                        .fetch_optional(&state.db)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(false);

                    let (namespace, package_name) = split_package_name(&pkg.name);
                    packages.push(PackageDisplay {
                        name: pkg.name.clone(),
                        namespace,
                        package_name,
                        version: pkg.version.clone(),
                        description: pkg.description.clone(),
                        author: pkg.author.clone(),
                        downloads,
                        is_verified,
                        is_author_verified,
                        safety_status,
                    });
                }
            }
        },
        Err(e) => {
            error!("Database error in home_handler: {}", e);
            let index = state.package_index.read().await;
            for pkg in index.values().take(10) {
                let (namespace, package_name) = split_package_name(&pkg.name);
                packages.push(PackageDisplay {
                    name: pkg.name.clone(),
                    namespace,
                    package_name,
                    version: pkg.version.clone(),
                    description: pkg.description.clone(),
                    author: pkg.author.clone(),
                    downloads: 0,
                    is_verified: false,
                    is_author_verified: false,
                    safety_status: "safe".to_string(),
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
    let user_record: Option<(i64, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>, bool, bool)> = sqlx::query_as(
        "SELECT id, username, tier, bio, avatar_url, github_url, twitter_url, website_url, is_verified, is_suspended FROM users WHERE username = $1"
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| AppError::InternalError("Database error".to_string()))?;

    let (user_id, user_username, user_tier, user_bio, avatar_url, github_url, twitter_url, website_url, is_verified, is_suspended) = match user_record {
        Some(u) => u,
        None => return Ok(AppError::NotFound.into_response()),
    };

    let mut packages = Vec::new();
    let mut total_downloads: i64 = 0;
    
    let package_names: Vec<String> = sqlx::query_scalar(
        "SELECT package_name FROM package_owners WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    for pkg_name in package_names {
        let pkg_data: (i64, bool, String) = sqlx::query_as("SELECT downloads, is_verified, safety_status FROM packages WHERE name = $1")
            .bind(&pkg_name)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?
            .unwrap_or((0, false, "safe".to_string()));
        
        let (namespace, package_name) = split_package_name(&pkg_name);
        total_downloads += pkg_data.0;
        packages.push(ProfilePackage { 
            name: pkg_name, 
            namespace,
            package_name,
            downloads: pkg_data.0,
            is_verified: pkg_data.1,
            safety_status: pkg_data.2,
        });
    }

    let mut context = Context::new();
    context.insert("username", &user_username);
    context.insert("tier", &user_tier);
    context.insert("bio", &user_bio);
    context.insert("avatar_url", &avatar_url.unwrap_or_else(|| format!("https://www.gravatar.com/avatar/{:x}?d=identicon", md5::compute(user_username.to_lowercase()))));
    context.insert("github_url", &github_url);
    context.insert("twitter_url", &twitter_url);
    context.insert("website_url", &website_url);
    context.insert("is_verified", &is_verified);
    context.insert("is_suspended", &is_suspended);
    context.insert("packages", &packages);
    context.insert("total_downloads", &total_downloads);

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

pub async fn profile_edit_page_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppError> {
    let context = Context::new();
    let html_content = state.tera.render("profile_edit.html", &context)?;
    Ok(Html(html_content))
}

pub async fn package_web_handler(
    Path(path): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    // path can be:
    // "@cvrf/router" -> latest
    // "@cvrf/router/1.0.0" -> specific version
    // "router" -> latest (@global)
    // "router/1.0.0" -> specific version (@global)

    // Check if the last part is a version
    let (name, version) = if let Some(idx) = path.rfind('/') {
        let potential_version = &path[idx+1..];
        // If it starts with @ and only has one slash, it's just the name (e.g. @cvrf/router)
        if path.starts_with('@') && path.chars().filter(|&c| c == '/').count() == 1 {
            (path.as_str(), None)
        } else if !path.starts_with('@') && path.chars().filter(|&c| c == '/').count() == 0 {
            // Should not happen with rfind, but for safety
            (path.as_str(), None)
        } else {
            // It has enough slashes to potentially have a version
            if semver::Version::parse(potential_version).is_ok() {
                (&path[..idx], Some(potential_version))
            } else {
                (path.as_str(), None)
            }
        }
    } else {
        (path.as_str(), None)
    };

    let version = match version {
        Some(v) => v.to_string(),
        None => get_latest_version(name).ok_or(AppError::NotFound)?,
    };

    let (namespace, pkg_name) = split_package_name(name);
    let manifest_path = format!("./storage/packages/{}/{}/{}/package.json", namespace, pkg_name, version);

    if !std::path::Path::new(&manifest_path).exists() {
         return Err(AppError::NotFound);
    }

    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;

    let db_pkg: (i64, bool, String) = sqlx::query_as("SELECT downloads, is_verified, safety_status FROM packages WHERE name = $1")
        .bind(name)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?
        .unwrap_or((0, false, "safe".to_string()));

    let versions = get_all_versions(name);

    let mut context = Context::new();
    context.insert("manifest", &manifest);
    context.insert("raw_json", &raw_json);
    context.insert("downloads", &db_pkg.0);
    context.insert("is_verified", &db_pkg.1);
    context.insert("safety_status", &db_pkg.2);
    context.insert("versions", &versions);

    let html_content = state.tera.render("package.html", &context)?;
    Ok(Html(html_content).into_response())
}
