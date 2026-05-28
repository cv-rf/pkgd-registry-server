use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use tracing::error;

pub enum AppError {
    NotFound,
    InternalError(String),
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
