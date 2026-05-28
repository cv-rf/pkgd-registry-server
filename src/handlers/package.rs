use axum::{
    extract::{Multipart, Path, State, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{PackageManifest, SearchParams};
use crate::error::AppError;
use crate::utils::{compute_checksum, get_latest_version};

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

        let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM package_owners WHERE package_name = $1")
            .bind(&manifest.name)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        
        if let Some(owner_uid) = owner {
            if owner_uid != user.id {
                tracing::warn!("User {} tried to publish '{}' which they do not own!", user.username, manifest.name);
                return Err(StatusCode::FORBIDDEN)
            }
        } else {
            sqlx::query("INSERT INTO package_owners (package_name, user_id) VALUES ($1, $2)")
                .bind(&manifest.name)
                .bind(user.id)
                .execute(&state.db)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            tracing::info!("User {} claimed ownership of new package '{}'", user.username, manifest.name);
        }

        sqlx::query("INSERT INTO packages (name) VALUES ($1) ON CONFLICT(name) DO UPDATE SET updated_at = CURRENT_TIMESTAMP")
            .bind(&manifest.name)
            .execute(&state.db)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let hash = compute_checksum(&bytes);
        manifest.checksum = Some(hash);

        let pkg_dir = format!("./storage/packages/{}/{}", manifest.name, manifest.version);
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
    let manifest_path = format!("./storage/packages/{}/{}/package.json", name, latest);
    
    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;
    
    Ok(Json(manifest).into_response())
}

pub async fn package_version_api_handler(
    Path((name, version)): Path<(String, String)>
) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/packages/{}/{}/package.json", name, version);
    
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
