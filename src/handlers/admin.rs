use axum::{
    extract::{State, Query, Path},
    http::StatusCode,
    Json,
    response::IntoResponse,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{
    PackageDisplay, UserDisplay, UpgradeRequest, VerifyRequest, 
    AdminPaginationParams, PaginatedResponse, UserVerifyRequest,
    UpdateSafetyRequest, UpdateSuspensionRequest
};
use crate::utils::split_package_name;

pub async fn toggle_safety_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UpdateSafetyRequest>,
) -> Result<StatusCode, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE packages SET safety_status = $1 WHERE name = $2")
        .bind(&payload.safety_status)
        .bind(&payload.name)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update safety status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

pub async fn toggle_suspension_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UpdateSuspensionRequest>,
) -> Result<StatusCode, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE users SET is_suspended = $1 WHERE username = $2")
        .bind(payload.is_suspended)
        .bind(&payload.username)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update suspension status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

pub async fn api_dashboard_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Query(params): Query<AdminPaginationParams>,
) -> Result<Json<PaginatedResponse<PackageDisplay>>, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    let limit = params.limit.unwrap_or(10) as i64;
    let page = params.page.unwrap_or(1);
    let offset = ((page - 1) as i64) * limit;
    let search = params.q.unwrap_or_default();
    let search_pattern = format!("%{}%", search);

    let db_packages: Vec<(String, String, String, i64, bool, String)> = sqlx::query_as(
        "SELECT name, namespace, package_name, downloads, is_verified, safety_status FROM packages WHERE name ILIKE $1 ORDER BY name ASC LIMIT $2 OFFSET $3"
    )
    .bind(&search_pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM packages WHERE name ILIKE $1")
        .bind(&search_pattern)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut packages = Vec::new();
    for (name, namespace, package_name, downloads, is_verified, safety_status) in db_packages {
        packages.push(PackageDisplay {
            name,
            namespace,
            package_name,
            version: "".to_string(),
            description: "".to_string(),
            author: "".to_string(),
            downloads,
            is_verified,
            is_author_verified: false,
            safety_status,
        });
    }

    Ok(Json(PaginatedResponse {
        items: packages,
        total,
        page,
        total_pages: ((total as f64) / (limit as f64)).ceil() as u32,
    }))
}

pub async fn api_list_users_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Query(params): Query<AdminPaginationParams>,
) -> Result<Json<PaginatedResponse<UserDisplay>>, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    let limit = params.limit.unwrap_or(10) as i64;
    let page = params.page.unwrap_or(1);
    let offset = ((page - 1) as i64) * limit;
    let search = params.q.unwrap_or_default();
    let search_pattern = format!("%{}%", search);

    let users: Vec<UserDisplay> = sqlx::query_as::<_, UserDisplay>(
        "SELECT username, tier, is_verified, is_suspended FROM users WHERE username ILIKE $1 ORDER BY username ASC LIMIT $2 OFFSET $3"
    )
    .bind(&search_pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username ILIKE $1")
        .bind(&search_pattern)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(PaginatedResponse {
        items: users,
        total,
        page,
        total_pages: ((total as f64) / (limit as f64)).ceil() as u32,
    }))
}

pub async fn admin_delete_package_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::info!("Staff member {} is deleting package '{}'", user.username, name);

    let (namespace, pkg_name) = split_package_name(&name);

    sqlx::query("DELETE FROM package_owners WHERE package_name = $1 AND namespace = $2")
        .bind(&pkg_name)
        .bind(&namespace)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    sqlx::query("DELETE FROM packages WHERE name = $1")
        .bind(&name)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    {
        let mut index = state.package_index.write().await;
        index.remove(&name);
    }

    let pkg_dir = format!("./storage/packages/{}/{}", namespace, pkg_name);
    if std::path::Path::new(&pkg_dir).exists() {
        std::fs::remove_dir_all(pkg_dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok((StatusCode::OK, "Package deleted successfully"))
}

pub async fn upgrade_user_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UpgradeRequest>,
) -> Result<StatusCode, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    let valid_tiers = ["member", "supporter", "partner", "verified", "staff"];
    if !valid_tiers.contains(&payload.tier.as_str()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    sqlx::query("UPDATE users SET tier = $1 WHERE username = $2")
        .bind(payload.tier)
        .bind(payload.username)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

pub async fn toggle_verify_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<VerifyRequest>,
) -> Result<StatusCode, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE packages SET is_verified = $1 WHERE name = $2")
        .bind(payload.verified)
        .bind(&payload.name)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}

pub async fn toggle_user_verify_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UserVerifyRequest>,
) -> Result<StatusCode, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query("UPDATE users SET is_verified = $1 WHERE username = $2")
        .bind(payload.verified)
        .bind(&payload.username)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}
