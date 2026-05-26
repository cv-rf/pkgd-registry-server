use axum::{
    Json, Router, extract::{Path, State}, http::StatusCode, response::{Html, IntoResponse, Response}, routing::get
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tera::{Context, Tera};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
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
        .route("/download/{file}", get(download_handler))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Registry Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
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