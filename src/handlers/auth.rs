use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{AuthRequest, AuthResponse, BioRequest, ProfileEditResponse};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;

pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> impl IntoResponse {
    if payload.username.len() < 3 || payload.username.len() > 32 {
        return (StatusCode::BAD_REQUEST, "Username must be between 3 and 32 characters.").into_response();
    }

    let username_regex = Regex::new(r"^[a-zA-Z0-9_-]+$").unwrap();
    if !username_regex.is_match(&payload.username) {
        return (StatusCode::BAD_REQUEST, "Username can only contain letters, numbers, underscores, and hyphens.").into_response();
    }

    if payload.password.len() < 8 || payload.password.len() > 128 {
        return (StatusCode::BAD_REQUEST, "Password must be between 8 and 128 characters.").into_response();
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = match argon2.hash_password(payload.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            tracing::error!("Password hashing failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error during password hashing.").into_response();
        }
    };

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(&payload.username)
        .bind(&password_hash)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => {
            tracing::info!("New user registered: {}", payload.username);
            (StatusCode::CREATED, "User created successfully. You can now login.").into_response()
        }
        Err(e) => {
            tracing::error!("Registration database error: {}", e);
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return (StatusCode::CONFLICT, "Username is already taken.").into_response();
                }
            }
            (StatusCode::INTERNAL_SERVER_ERROR, "Registration failed due to a server database error.").into_response()
        }
    }
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    
    let user_result = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM users WHERE username = $1"
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Login database error (user fetch): {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (user_id, stored_hash) = user_result.ok_or(StatusCode::UNAUTHORIZED)?;

    let parsed_hash = PasswordHash::new(&stored_hash)
        .map_err(|e| {
            tracing::error!("Invalid stored password hash: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

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

    sqlx::query("INSERT INTO api_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Login database error (token insert): {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

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
    sqlx::query("DELETE FROM api_tokens WHERE token = $1")
        .bind(&user.token)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Logout database error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!("User {} logged out.", user.username);
    Ok((StatusCode::OK, "Logged out successfully."))
}

pub async fn get_profile_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<ProfileEditResponse>, StatusCode> {
    let bio: String = sqlx::query_scalar("SELECT bio FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch user bio: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(ProfileEditResponse {
        username: user.username,
        tier: user.tier,
        bio,
        token: user.token,
    }))
}

pub async fn update_bio_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<BioRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("UPDATE users SET bio = $1 WHERE id = $2")
        .bind(&payload.bio)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update bio: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok((StatusCode::OK, "Bio updated successfully."))
}

pub async fn regenerate_token_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Delete current token
    sqlx::query("DELETE FROM api_tokens WHERE token = $1")
        .bind(&user.token)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete old token: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Generate new token
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    sqlx::query("INSERT INTO api_tokens (token, user_id) VALUES ($1, $2)")
        .bind(&token)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to insert new token: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(AuthResponse {
        token,
        message: "New token generated successfully. Previous token invalidated.".to_string(),
    }))
}
