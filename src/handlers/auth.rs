use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{AuthRequest, AuthResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;

pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    if payload.username.len() < 3 || payload.username.len() > 32 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    if !username_regex.is_match(&payload.username) {
        return Err(StatusCode::BAD_REQUEST);
    }

    if payload.password.len() < 8 || payload.password.len() > 128 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&payload.username)
        .bind(&password_hash)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => {
            tracing::info!("New user registered: {}", payload.username);
            Ok((StatusCode::CREATED, "User created successfully. You can now login."))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    
    let user_result = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM users WHERE username = ?"
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (user_id, stored_hash) = user_result.ok_or(StatusCode::UNAUTHORIZED)?;

    let parsed_hash = PasswordHash::new(&stored_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let is_valid = Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .is_ok();

    if !is_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    sqlx::query("INSERT INTO api_tokens (token, user_id) VALUES (?, ?)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("User {} successfully logged in.", payload.username);

    Ok(Json(AuthResponse {
        token,
        message: "Login successful. Save this token securely!".to_string(),
    }))
}

pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("DELETE FROM api_tokens WHERE token = ?")
        .bind(&user.token)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("User {} logged out.", user.username);
    Ok((StatusCode::OK, "Logged out successfully."))
}
