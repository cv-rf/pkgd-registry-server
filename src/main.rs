use axum::{
    Json, Router, extract::{Multipart, Path, State, Query, FromRequestParts}, http::{request::Parts, StatusCode}, response::{Html, IntoResponse, Response, Redirect}, routing::get, routing::post
};
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2
};
use rand::{distributions::Alphanumeric, Rng};
use sha2::{Sha256, Digest};
use tera::{Context, Tera};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::{info, error};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
}

#[derive(Deserialize)]
pub struct SearchParams {
    q: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub message: String,
}

pub enum AppError {
    NotFound,
    InternalError(String),
}

struct AppState {
    tera: Tera,
    package_index: RwLock<HashMap<String, PackageManifest>>,
    db: SqlitePool,
}

#[derive(sqlx::FromRow)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
}

impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            .filter(|h| h.starts_with("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let token = auth_header.trim_start_matches("Bearer ");

        let user = sqlx::query_as::<_, AuthenticatedUser>(
            "SELECT users.id, users.username FROM api_tokens JOIN users ON users.id = api_tokens.user_id WHERE api_tokens.token = ?"
        )
        .bind(token)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        user.ok_or(StatusCode::UNAUTHORIZED)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, message) = match &self {
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "404 Not Found",
                "The package or file you are looking for does not exist.",
            ),
            AppError::InternalError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 Server Error",
                "Something went wrong on our end while processing this request.",
            ),
        };

        if let AppError::InternalError(err) = self {
            error!("Server Error: {}", err);
        }

        let body = format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <title>{} | Registry</title>
                <style>
                    body {{ font-family: 'Poppins', sans-serif; background: #000; color: #fff; text-align: center; padding-top: 100px; }}
                    h1 {{ color: #8F5BFD; font-size: 3rem; margin-bottom: 10px; }}
                    a {{ color: #8F5BFD; text-decoration: none; }}
                </style>
            </head>
            <body>
                <h1>{}</h1>
                <p style="color: #A0A0A0;">{}</p>
                <p><a href="/">← Back to search</a></p>
            </body>
            </html>"#,
            title, title, message
        );

        (status, Html(body)).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => AppError::NotFound,
            _ => AppError::InternalError(err.to_string()),
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::InternalError(format!("Failed to parse JSON: {}", err))
    }
}

impl From<tera::Error> for AppError {
    fn from(err: tera::Error) -> Self {
        AppError::InternalError(format!("Template error: {}", err))
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pkgd_registry_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut tera = Tera::new("templates/**/*").expect("Failed to compile templates");
    tera.autoescape_on(vec!["html", "xml"]);
    let initial_index = build_initial_index();

    let db_pool = SqlitePoolOptions::new()
        .connect("sqlite://registry.db?mode=rwc")
        .await
        .expect("Failed to connect to database");
    
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS package_owners (
            package_name TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id)
        );
        "#
    )
    .execute(&db_pool)
    .await
    .unwrap();

    let shared_state = Arc::new(AppState { 
        tera,
        package_index: RwLock::new(initial_index),
        db: db_pool,
    });

    let app = Router::new()
        .route("/", get(home_handler))

        .route("/api/register", post(register_handler))
        .route("/api/login", post(login_handler))

        .route("/packages/{name}", get(package_latest_web_handler))
        .route("/packages/{name}/{version}", get(package_version_web_handler))
        
        .route("/api/search", get(search_api_handler))
        .route("/api/packages/{name}", get(package_latest_api_handler))
        .route("/api/packages/{name}/{version}", get(package_version_api_handler))

        .route("/api/publish", post(publish_handler))
        .route("/download/{file}", get(download_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9999").await.unwrap();
    info!("Registry Server running on http://0.0.0.0:9999");
    axum::serve(listener, app).await.unwrap();
}

fn compute_checksum(file_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_bytes);
    let result = hasher.finalize();
    
    hex::encode(result)
}

fn build_initial_index() -> HashMap<String, PackageManifest> {
    let mut index: HashMap<String, PackageManifest> = HashMap::new();
    
    if let Ok(entries) = std::fs::read_dir("./storage") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(json) = std::fs::read_to_string(&path) {
                    if let Ok(manifest) = serde_json::from_str::<PackageManifest>(&json) {
                        
                        let should_insert = match index.get(&manifest.name) {
                            None => true,
                            Some(existing) => {
                                if let (Ok(new_v), Ok(old_v)) = (
                                    semver::Version::parse(&manifest.version),
                                    semver::Version::parse(&existing.version)
                                ) {
                                    new_v > old_v
                                } else {
                                    true
                                }
                            }
                        };

                        if should_insert {
                            index.insert(manifest.name.clone(), manifest);
                        }
                    }
                }
            }
        }
    }
    
    println!("Loaded {} unique packages into memory index.", index.len());
    index
}

fn get_latest_version(pkg_name: &str) -> Option<String> {
    let mut versions = Vec::new();

    let entries = std::fs::read_dir("./storage").ok()?;

    for entry in entries.filter_map(Result::ok) {
        if let Ok(file_name) = entry.file_name().into_string() {
            if file_name.starts_with(&format!("{}-", pkg_name)) && file_name.ends_with(".json") {
                if let Some(version_str) = file_name
                    .strip_prefix(&format!("{}-", pkg_name))
                    .and_then(|s| s.strip_suffix(".json"))
                {
                    if let Ok(version) = semver::Version::parse(version_str) {
                        versions.push(version);
                    }
                }
            }
        }
    }

    versions.into_iter().max().map(|v| v.to_string())
}

async fn home_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let context = Context::new();
    let html_content = state.tera.render("index.html", &context).unwrap();
    Html(html_content)
}

async fn package_latest_web_handler(Path(name): Path<String>) -> Result<Response, AppError> {
    let latest = get_latest_version(&name).ok_or(AppError::NotFound)?;
    
    let redirect_url = format!("/packages/{}/{}", name, latest);
    Ok(Redirect::temporary(&redirect_url).into_response())
}

async fn package_version_web_handler(
    Path((name, version)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/{}-{}.json", name, version);

    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;

    let mut context = Context::new();
    context.insert("manifest", &manifest);
    context.insert("raw_json", &raw_json);

    let html_content = state.tera.render("package.html", &context)?;
    Ok(Html(html_content).into_response())
}

async fn package_latest_api_handler(Path(name): Path<String>) -> Result<Response, AppError> {
    let latest = get_latest_version(&name).ok_or(AppError::NotFound)?;
    let manifest_path = format!("./storage/{}-{}.json", name, latest);
    
    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;
    
    Ok(Json(manifest).into_response())
}

async fn search_api_handler(
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

async fn package_version_api_handler(
    Path((name, version)): Path<(String, String)>
) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/{}-{}.json", name, version);
    
    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;
    
    Ok(Json(manifest).into_response())
}

async fn download_handler(Path(file): Path<String>) -> Result<Response, AppError> {
    let file_path = format!("./storage/{}", file);

    let file_bytes = std::fs::read(file_path)?;

    let headers = [
        ("content-type", "application/gzip"),
        ("content-disposition", &format!("attachment; filename=\"{}\"", file)),
    ];

    Ok((headers, file_bytes).into_response())
}

async fn publish_handler(
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

        let owner: Option<i64> = sqlx::query_scalar("SELECT user_id FROM package_owners WHERE package_name = ?")
            .bind(&manifest.name)
            .fetch_optional(&state.db)
            .await.unwrap();
        
        if let Some(owner_uid) = owner {
            if owner_uid != user.id {
                tracing::warn!("User {} tried to publish '{}' which they do not own!", user.username, manifest.name);
                return Err(StatusCode::FORBIDDEN)
            }
        } else {
            sqlx::query("INSERT INTO package_owners (package_name, user_id) VALUES (?, ?)")
                .bind(&manifest.name)
                .bind(user.id)
                .execute(&state.db)
                .await.unwrap();
            tracing::info!("User {} claimed ownership of new package '{}'", user.username, manifest.name);
        }

        let hash = compute_checksum(&bytes);
        manifest.checksum = Some(hash);

        let base_name = format!("{}-{}", manifest.name, manifest.version);

        std::fs::write(format!("./storage/{}.tar.gz", base_name), bytes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let updated_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(format!("./storage/{}.json", base_name), updated_json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        {
            let mut index = state.package_index.write().await;
            index.insert(manifest.name.clone(), manifest.clone());
        }

        return Ok((StatusCode::CREATED, "Package published successfully!"));
    }

    Err(StatusCode::BAD_REQUEST)
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, StatusCode> {
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

async fn login_handler(
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