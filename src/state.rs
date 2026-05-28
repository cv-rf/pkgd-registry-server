use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use tera::Tera;
use crate::models::PackageManifest;

pub struct AppState {
    pub tera: Tera,
    pub package_index: RwLock<HashMap<String, PackageManifest>>,
    pub db: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
    pub tier: String,
    #[sqlx(skip)]
    pub token: String,
}

impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            .filter(|h| h.starts_with("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let token = auth_header.trim_start_matches("Bearer ");

        let mut user = sqlx::query_as::<_, AuthenticatedUser>(
            "SELECT users.id, users.username, users.tier FROM api_tokens JOIN users ON users.id = api_tokens.user_id WHERE api_tokens.token = ?"
        )
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

        user.token = token.to_string();
        Ok(user)
    }
}
