use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use sqlx::Row;
use crate::state::{AppState, AuthenticatedUser};
use crate::models::{
    AuthRequest, AuthResponse, BioRequest, ProfileEditResponse,
    UpdateProfileRequest, UpdatePasswordRequest, CreateTokenRequest, TokenDisplay,
    PublicKeyEntry, AddKeyRequest
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use md5;

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

    // Simple Gravatar URL generation
    let avatar_url = format!("https://www.gravatar.com/avatar/{:x}?d=identicon", md5::compute(payload.username.to_lowercase()));

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash, avatar_url) VALUES ($1, $2, $3) RETURNING id")
        .bind(&payload.username)
        .bind(&password_hash)
        .bind(avatar_url)
        .fetch_one(&state.db)
        .await;

    match result {
        Ok(row) => {
            let user_id: i64 = row.get(0);
            tracing::info!("New user registered: {}", payload.username);
            
            // Auto-login after registration
            let token: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();

            let _ = sqlx::query("INSERT INTO api_tokens (token, user_id, name) VALUES ($1, $2, $3)")
                .bind(&token)
                .bind(user_id)
                .bind("Initial Session Token")
                .execute(&state.db)
                .await;

            Json(AuthResponse {
                token,
                message: "User created and logged in successfully.".to_string(),
            }).into_response()
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

    sqlx::query("INSERT INTO api_tokens (token, user_id, name) VALUES ($1, $2, $3)")
        .bind(&token)
        .bind(user_id)
        .bind("Web Session")
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
    let row: (String, String, Option<String>, Option<String>, Option<String>, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT bio, tier, avatar_url, github_url, twitter_url, website_url, is_verified, is_suspended FROM users WHERE id = $1"
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch user profile for settings: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ProfileEditResponse {
        username: user.username,
        tier: row.1,
        bio: row.0,
        avatar_url: row.2,
        github_url: row.3,
        twitter_url: row.4,
        website_url: row.5,
        is_verified: row.6,
        is_suspended: row.7,
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

pub async fn update_profile_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("UPDATE users SET bio = COALESCE($1, bio), avatar_url = COALESCE($2, avatar_url), github_url = $3, twitter_url = $4, website_url = $5 WHERE id = $6")
        .bind(payload.bio)
        .bind(payload.avatar_url)
        .bind(payload.github_url)
        .bind(payload.twitter_url)
        .bind(payload.website_url)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update profile: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok((StatusCode::OK, "Profile updated successfully."))
}


pub async fn update_password_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<UpdatePasswordRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let stored_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let parsed_hash = PasswordHash::new(&stored_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if Argon2::default().verify_password(payload.old_password.as_bytes(), &parsed_hash).is_err() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();

    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(new_hash)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, "Password updated successfully."))
}

pub async fn list_tokens_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<TokenDisplay>>, StatusCode> {
    let tokens: Vec<TokenDisplay> = sqlx::query_as("SELECT token, name, created_at FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user.id)
        .fetch_all(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(tokens))
}

pub async fn create_token_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<TokenDisplay>, StatusCode> {
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    
    let name = if payload.name.trim().is_empty() { "New Token".to_string() } else { payload.name };
    
    let row: (String, String, chrono::NaiveDateTime) = sqlx::query_as("INSERT INTO api_tokens (token, user_id, name) VALUES ($1, $2, $3) RETURNING token, name, created_at")
        .bind(&token)
        .bind(user.id)
        .bind(name)
        .fetch_one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(TokenDisplay {
        token: row.0,
        name: row.1,
        created_at: row.2,
    }))
}

pub async fn revoke_token_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query("DELETE FROM api_tokens WHERE token = $1 AND user_id = $2")
        .bind(&token)
        .bind(user.id)
        .execute(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok((StatusCode::OK, "Token revoked successfully."))
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

pub async fn list_public_keys_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<PublicKeyEntry>>, StatusCode> {
    let keys: Vec<PublicKeyEntry> = sqlx::query_as("SELECT key_name as name, public_key as key FROM user_public_keys WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user.id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list public keys: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(keys))
}

pub async fn add_public_key_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(payload): Json<AddKeyRequest>,
) -> Result<Json<PublicKeyEntry>, StatusCode> {
    // Basic validation for hex string (32-byte Ed25519 public key = 64 hex chars)
    if payload.public_key.len() != 64 || !payload.public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let row: (String, String) = sqlx::query_as("INSERT INTO user_public_keys (user_id, key_name, public_key) VALUES ($1, $2, $3) RETURNING key_name, public_key")
        .bind(user.id)
        .bind(&payload.name)
        .bind(&payload.public_key)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to add public key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(PublicKeyEntry {
        name: row.0,
        key: row.1,
    }))
}

pub async fn delete_public_key_handler(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query("DELETE FROM user_public_keys WHERE user_id = $1 AND public_key = $2")
        .bind(user.id)
        .bind(&key)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete public key: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok((StatusCode::OK, "Public key deleted successfully."))
}
