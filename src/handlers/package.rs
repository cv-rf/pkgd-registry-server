use axum::{
    extract::{Multipart, Path, State, Query},
    http::{StatusCode, Method},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser, OptionalAuthenticatedUser};
use crate::models::{PackageManifest, SearchParams, AuthorKeysResponse, PublicKeyEntry};
use crate::error::AppError;
use crate::utils::{compute_checksum, get_latest_version, get_all_versions, split_package_name};
use crate::scanner::scan_package;

pub async fn package_api_handler(
    State(state): State<Arc<AppState>>,
    method: Method,
    OptionalAuthenticatedUser(user): OptionalAuthenticatedUser,
    Path(path): Path<String>,
) -> Result<Response, AppError> {
    // Dispatch based on path and method
    
    // 1. Download: "@cvrf/router/1.0.0/download" or "router/1.0.0/download"
    if path.ends_with("/download") {
        let trimmed_path = &path[..path.len() - 9]; // Remove "/download"
        if let Some(idx) = trimmed_path.rfind('/') {
             let name = &trimmed_path[..idx];
             let version = &trimmed_path[idx+1..];
             
             return package_version_download_handler(State(state), Path((name.to_string(), version.to_string()))).await;
        }
    }

    // 2. Versions: "@cvrf/router/versions" or "router/versions"
    if path.ends_with("/versions") {
        let name = &path[..path.len() - 9]; // Remove "/versions"
        return package_versions_list_api_handler(Path(name.to_string())).await.map(|j| j.into_response());
    }

    // 3. Delete: DELETE "@cvrf/router" or "router"
    if method == Method::DELETE {
        let user = user.ok_or(AppError::InternalError("Unauthorized: Missing or invalid token".to_string()))?; 
        return delete_package_handler(State(state), user, Path(path)).await.map(|r| r.into_response());
    }

    // 4. Specific Version Manifest: "@cvrf/router/1.0.0" or "router/1.0.0"
    if let Some(idx) = path.rfind('/') {
        let potential_version = &path[idx+1..];
        let is_namespaced_only = path.starts_with('@') && path.chars().filter(|&c| c == '/').count() == 1;
        
        if !is_namespaced_only && semver::Version::parse(potential_version).is_ok() {
            let name = &path[..idx];
            return package_version_api_handler(Path((name.to_string(), potential_version.to_string()))).await;
        }
    }

    // 5. Latest Manifest: "@cvrf/router" or "router"
    package_latest_api_handler(Path(path)).await
}

pub async fn package_versions_list_api_handler(Path(name): Path<String>) -> Result<Json<Vec<String>>, AppError> {
    let versions = get_all_versions(&name);
    if versions.is_empty() {
        return Err(AppError::NotFound);
    }
    Ok(Json(versions))
}


pub async fn package_version_download_handler(
    State(state): State<Arc<AppState>>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let (namespace, pkg_name) = split_package_name(&name);
    let safety: Option<String> = sqlx::query_scalar("SELECT safety_status FROM packages WHERE name = $1")
        .bind(&name)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    if let Some(status) = safety {
        if status == "malware" {
            return Err(AppError::InternalError("This package has been blocked due to malware detection.".to_string()));
        }
    }

    let pkg_path = format!("./storage/packages/{}/{}/{}/package.tar.gz", namespace, pkg_name, version);
    if !std::path::Path::new(&pkg_path).exists() {
        return Err(AppError::NotFound);
    }

    let file_bytes = std::fs::read(pkg_path)?;

    sqlx::query("INSERT INTO packages (name, namespace, package_name, downloads) VALUES ($1, $2, $3, 1) ON CONFLICT(name) DO UPDATE SET downloads = packages.downloads + 1")
        .bind(&name)
        .bind(&namespace)
        .bind(&pkg_name)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    let display_name = name.replace('/', "-");
    let filename = format!("{}-{}.tar.gz", display_name, version);
    let headers = [
        ("content-type", "application/gzip"),
        ("content-disposition", &format!("attachment; filename=\"{}\"", filename)),
    ];

    Ok((headers, file_bytes).into_response())
}

pub async fn publish_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, StatusCode> {
    tracing::info!("User {} is attempting to publish...", user.username);

    let mut manifest_json = None;
    let mut file_bytes = None;

    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let name = field.name().unwrap_or("").to_string();

        if name == "manifest" {
            let text = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            manifest_json = Some(text);
        } else if name == "tarball" {
            let data = field.bytes().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            file_bytes = Some(data);
        }
    }

    if let (Some(manifest_str), Some(bytes)) = (manifest_json, file_bytes) {
        let mut manifest: PackageManifest = serde_json::from_str(&manifest_str)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let (namespace, pkg_name) = split_package_name(&manifest.name);
        
        // Authorization: User must own the namespace
        // Rule: Every user owns @username. Only staff/verified can publish to @global or other system namespaces.
        let user_namespace = format!("@{}", user.username);
        if namespace != user_namespace && namespace != "@global" {
             tracing::warn!("User {} tried to publish to unauthorized namespace '{}'", user.username, namespace);
             return Err(StatusCode::FORBIDDEN);
        }

        // Additional check for @global: Only verified or staff
        if namespace == "@global" && user.tier != "staff" && user.tier != "verified" {
             tracing::warn!("User {} tried to publish to @global but is not authorized.", user.username);
             return Err(StatusCode::FORBIDDEN);
        }

        // Malware scan before processing
        let scan_result = scan_package(&bytes);
        let safety_status = if scan_result.is_clean {
            "safe"
        } else if scan_result.threats.iter().any(|t| t.to_lowercase().contains("malware") || t.to_lowercase().contains("eicar")) {
            "malware"
        } else {
            "unsure"
        };

        if safety_status == "malware" {
            tracing::error!("CRITICAL: Malware detected in upload from user {}. Suspending user and blocking package.", user.username);
            
            // Suspend the user
            let _ = sqlx::query("UPDATE users SET is_suspended = TRUE WHERE id = $1")
                .bind(user.id)
                .execute(&state.db)
                .await;

            return Err(StatusCode::FORBIDDEN);
        }

        let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM package_owners WHERE package_name = $1 AND namespace = $2")
            .bind(&pkg_name)
            .bind(&namespace)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        if let Some(owner_uid) = owner {
            if owner_uid != user.id {
                tracing::warn!("User {} tried to publish '{}' which they do not own!", user.username, manifest.name);
                return Err(StatusCode::FORBIDDEN)
            }
        } else {
            sqlx::query("INSERT INTO package_owners (package_name, namespace, user_id) VALUES ($1, $2, $3)")
                .bind(&pkg_name)
                .bind(&namespace)
                .bind(user.id)
                .execute(&state.db)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            tracing::info!("User {} claimed ownership of new package '{}'", user.username, manifest.name);
        }

        sqlx::query("INSERT INTO packages (name, namespace, package_name, safety_status) VALUES ($1, $2, $3, $4) ON CONFLICT(name) DO UPDATE SET updated_at = CURRENT_TIMESTAMP, safety_status = $4, namespace = $2, package_name = $3")
            .bind(&manifest.name)
            .bind(&namespace)
            .bind(&pkg_name)
            .bind(safety_status)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let hash = compute_checksum(&bytes);
        manifest.checksum = Some(hash);

        let pkg_dir = format!("./storage/packages/{}/{}/{}", namespace, pkg_name, manifest.version);
        std::fs::create_dir_all(&pkg_dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        std::fs::write(format!("{}/package.tar.gz", pkg_dir), bytes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let updated_json = serde_json::to_string_pretty(&manifest)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        std::fs::write(format!("{}/package.json", pkg_dir), updated_json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        {
            let mut index = state.package_index.write().await;
            index.insert(manifest.name.clone(), manifest.clone());
        }

        return Ok((StatusCode::CREATED, "Package published successfully!"));
    }

    Err(StatusCode::BAD_REQUEST)
}

pub async fn download_handler(
    State(state): State<Arc<AppState>>,
    Path(file): Path<String>,
) -> Result<Response, AppError> {
    
    let structured_path = if let Some(idx) = file.rfind('-') {
        let name = &file[..idx];
        let version_with_ext = &file[idx+1..];
        let version = version_with_ext.strip_suffix(".tar.gz").unwrap_or(version_with_ext);
        Some(format!("./storage/packages/{}/{}/package.tar.gz", name, version))
    } else {
        None
    };

    let file_bytes = if let Some(path) = structured_path.filter(|p| std::path::Path::new(p).exists()) {
        std::fs::read(path)?
    } else {
        
        let legacy_path = format!("./storage/{}", file);
        std::fs::read(legacy_path)?
    };

    if let Some(idx) = file.rfind('-') {
        let pkg_name = &file[..idx];
        
        sqlx::query("INSERT INTO packages (name, downloads) VALUES ($1, 1) ON CONFLICT(name) DO UPDATE SET downloads = packages.downloads + 1")
            .bind(pkg_name)
            .execute(&state.db)
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;
    }

    let headers = [
        ("content-type", "application/gzip"),
        ("content-disposition", &format!("attachment; filename=\"{}\"", file)),
    ];

    Ok((headers, file_bytes).into_response())
}

pub async fn package_latest_api_handler(Path(name): Path<String>) -> Result<Response, AppError> {
    let latest = get_latest_version(&name).ok_or(AppError::NotFound)?;
    let (namespace, pkg_name) = split_package_name(&name);
    let manifest_path = format!("./storage/packages/{}/{}/{}/package.json", namespace, pkg_name, latest);
    
    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;
    
    Ok(Json(manifest).into_response())
}

pub async fn package_version_api_handler(
    Path((name, version)): Path<(String, String)>
) -> Result<Response, AppError> {
    let (namespace, pkg_name) = split_package_name(&name);
    let manifest_path = format!("./storage/packages/{}/{}/{}/package.json", namespace, pkg_name, version);
    
    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;
    
    Ok(Json(manifest).into_response())
}

pub async fn search_api_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Result<Json<Vec<PackageManifest>>, AppError> {
    let query = params.q.to_lowercase();

    let index = state.package_index.read().await;

    let results: Vec<PackageManifest> = index.values()
        .filter(|pkg| {
            pkg.name.to_lowercase().contains(&query) ||
            pkg.description.to_lowercase().contains(&query)
        })
        .cloned()
        .collect();

    Ok(Json(results))
}

pub async fn delete_package_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("User {} is attempting to delete package '{}'...", user.username, name);

    let (namespace, pkg_name) = split_package_name(&name);

    // Try finding owner with split name (modern namespacing)
    let mut owner_id: Option<i64> = sqlx::query_scalar("SELECT user_id FROM package_owners WHERE package_name = $1 AND namespace = $2")
        .bind(&pkg_name)
        .bind(&namespace)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    // If not found, try finding owner with full name as package_name (legacy/migration edge case)
    if owner_id.is_none() {
        owner_id = sqlx::query_scalar("SELECT user_id FROM package_owners WHERE package_name = $1")
            .bind(&name)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    }

    match owner_id {
        Some(uid) if uid == user.id => {
            // Authorized
        }
        Some(_) => {
            tracing::warn!("User {} tried to delete '{}' which they do not own!", user.username, name);
            return Err(AppError::InternalError("Forbidden: You do not own this package.".to_string()));
        }
        None => {
            tracing::warn!("Delete failed: Package '{}' (ns: {}, name: {}) not found in owners table.", name, namespace, pkg_name);
            return Err(AppError::NotFound);
        }
    }

    sqlx::query("DELETE FROM package_owners WHERE (package_name = $1 AND namespace = $2) OR package_name = $3")
        .bind(&pkg_name)
        .bind(&namespace)
        .bind(&name)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    sqlx::query("DELETE FROM packages WHERE name = $1")
        .bind(&name)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    {
        let mut index = state.package_index.write().await;
        index.remove(&name);
    }

    let pkg_dir = format!("./storage/packages/{}/{}", namespace, pkg_name);
    if std::path::Path::new(&pkg_dir).exists() {
        std::fs::remove_dir_all(pkg_dir).map_err(|e| AppError::InternalError(e.to_string()))?;
    }

    tracing::info!("Package '{}' deleted by user {}", name, user.username);
    Ok((StatusCode::OK, "Package deleted successfully"))
}

pub async fn get_author_keys_handler(
    State(state): State<Arc<AppState>>,
    Path(author_name): Path<String>,
) -> Result<Json<AuthorKeysResponse>, AppError> {
    let keys: Vec<PublicKeyEntry> = sqlx::query_as(
        "SELECT uk.key_name as name, uk.public_key as key 
         FROM user_public_keys uk
         JOIN users u ON uk.user_id = u.id
         WHERE u.username = $1
         ORDER BY uk.created_at DESC"
    )
    .bind(&author_name)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(Json(AuthorKeysResponse {
        author: author_name,
        keys,
    }))
}
