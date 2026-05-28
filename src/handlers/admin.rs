use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{PackageDisplay, UserDisplay, UpgradeRequest, VerifyRequest};

pub async fn api_dashboard_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<PackageDisplay>>, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut packages = Vec::new();
    let db_packages: Vec<(String, i64, bool)> = sqlx::query_as("SELECT name, downloads, is_verified FROM packages")
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for (name, downloads, is_verified) in db_packages {
        packages.push(PackageDisplay {
            name,
            version: "".to_string(),
            description: "".to_string(),
            author: "".to_string(),
            downloads,
            is_verified,
            is_author_verified: false, 
        });
    }

    Ok(Json(packages))
}

pub async fn api_list_users_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<UserDisplay>>, StatusCode> {
    if user.tier != "staff" {
        return Err(StatusCode::FORBIDDEN);
    }

    let users: Vec<UserDisplay> = sqlx::query_as!(UserDisplay, "SELECT username, tier FROM users")
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(users))
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

    sqlx::query("UPDATE users SET tier = ? WHERE username = ?")
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

    sqlx::query("UPDATE packages SET is_verified = ? WHERE name = ?")
        .bind(payload.verified)
        .bind(&payload.name)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::OK)
}
