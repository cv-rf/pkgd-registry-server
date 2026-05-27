use axum::{
    Json, Router, extract::{Multipart, Path, State}, http::StatusCode, response::{Html, IntoResponse, Response}, routing::get, routing::post
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

pub enum AppError {
    NotFound,
    InternalError(String),
}

struct AppState {
    tera: Tera,
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
            error!("💥 Server Error: {}", err);
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

    let shared_state = Arc::new(AppState { tera} );

    let app = Router::new()
        .route("/", get(home_handler))
        .route("/packages/{name}", get(package_web_handler))
        .route("/api/packages/{name}", get(package_api_handler))
        .route("/api/publish", post(publish_handler))
        .route("/download/{file}", get(download_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    info!("Registry Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

fn compute_checksum(file_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_bytes);
    let result = hasher.finalize();
    
    hex::encode(result)
}

async fn home_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let context = Context::new();
    let html_content = state.tera.render("index.html", &context).unwrap();
    Html(html_content)
}

async fn package_web_handler(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/{}-1.0.0.json", name);

    let raw_json = std::fs::read_to_string(manifest_path)?;
    let manifest: PackageManifest = serde_json::from_str(&raw_json)?;

    let mut context = Context::new();
    context.insert("manifest", &manifest);
    context.insert("raw_json", &raw_json);

    let html_content = state.tera.render("package.html", &context)?;
    Ok(Html(html_content).into_response())
}

async fn package_api_handler(Path(name): Path<String>) -> Result<Response, AppError> {
    let manifest_path = format!("./storage/{}-1.0.0.json", name);

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

async fn publish_handler(mut multipart: Multipart) -> Result<impl IntoResponse, StatusCode> {
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

        let hash = compute_checksum(&bytes);
        manifest.checksum = Some(hash);

        let base_name = format!("{}-{}", manifest.name, manifest.version);

        std::fs::write(format!("./storage/{}.tar.gz", base_name), bytes)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let updated_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(format!("./storage/{}.json", base_name), updated_json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Ok((StatusCode::CREATED, "Package published successfully!"));
    }

    Err(StatusCode::BAD_REQUEST)
}