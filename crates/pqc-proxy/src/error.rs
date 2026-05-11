use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum GatewayError {
    UpstreamConnection(String),
    UpstreamTimeout(String),
    NoRouteMatch,
    MethodNotAllowed,
    Internal(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpstreamConnection(msg) => write!(f, "upstream connection error: {msg}"),
            Self::UpstreamTimeout(msg) => write!(f, "upstream timeout: {msg}"),
            Self::NoRouteMatch => write!(f, "no matching route"),
            Self::MethodNotAllowed => write!(f, "method not allowed"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            GatewayError::UpstreamConnection(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            GatewayError::UpstreamTimeout(msg) => (StatusCode::GATEWAY_TIMEOUT, msg.clone()),
            GatewayError::NoRouteMatch => (StatusCode::NOT_FOUND, "not found".to_string()),
            GatewayError::MethodNotAllowed => {
                (StatusCode::METHOD_NOT_ALLOWED, "method not allowed".to_string())
            }
            GatewayError::Internal(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, msg.clone())
            }
        };

        let body = json!({ "error": message, "status": status.as_u16() });
        (status, axum::Json(body)).into_response()
    }
}