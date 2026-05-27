use axum::{
    Json, Router, extract::{Multipart, Path, State}, http::StatusCode, response::{Html, IntoResponse, Response}, routing::get, routing::post
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sha2::{Sha256, Digest};
use tera::{Context, Tera};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub checksum: Option<String>,
}

struct AppState {
    tera: Tera,
}

#[tokio::main]
async fn main() {
    let mut tera = Tera::new("templates/**/*").expect("Failed to compile templates");
    tera.autoescape_on(vec!["html", "xml"]);

    let shared_state = Arc::new(AppState { tera} );

    let app = Router::new()
        .route("/", get(home_handler))
        .route("/packages/{name}", get(package_web_handler))
        .route("/api/packages/{name}", get(package_api_handler))
        .route("/api/publish", post(publish_handler))
        .route("/download/{file}", get(download_handler))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Registry Server running on http://127.0.0.1:3000");
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
) -> Response {
    let manifest_path = format!("./storage/{}-1.0.0.json", name);

    if !std::path::Path::new(&manifest_path).exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let raw_json = std::fs::read_to_string(manifest_path).unwrap();
    let manifest: PackageManifest = serde_json::from_str(&raw_json).unwrap();

    let mut context = Context::new();
    context.insert("manifest", &manifest);
    context.insert("raw_json", &raw_json);

    let html_content = state.tera.render("package.html", &context).unwrap();
    Html(html_content).into_response()
}

async fn package_api_handler(Path(name): Path<String>) -> Response {
    let manifest_path = format!("./storage/{}-1.0.0.json", name);

    if let Ok(raw_json) = std::fs::read_to_string(manifest_path) {
        if let Ok(manifest) = serde_json::from_str::<PackageManifest>(&raw_json) {
            return Json(manifest).into_response();
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn download_handler(Path(file): Path<String>) -> Response {
    let file_path = format!("./storage/{}", file);

    if let Ok(file_bytes) = std::fs::read(file_path) {
        let headers = [
            ("content-type", "application/gzip"),
            ("content-disposition", &format!("attachment; filename=\"{}\"", file)),
        ];
        return (headers, file_bytes).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn publish_handler(mut multipart: Multipart) -> Result<impl IntoResponse, StatusCode> {
    let mut manifest_json = None;
    let mut file_bytes = None;

    while let Some(field) = multipart.next_field().await.map_err(|_| StatusCode::BAD_REQUEST)? {
        let name = field.name().unwrap_or("").to_string();

        if name == "manifest" {
            // Read the manifest JSON string
            let text = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
            manifest_json = Some(text);
        } else if name == "tarball" {
            // Read the raw .tar.gz file bytes
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