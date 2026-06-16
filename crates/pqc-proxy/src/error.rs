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
    RateLimited,
    BodyTooLarge(u64),
    Unauthorized(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UpstreamConnection(msg) => write!(f, "upstream connection error: {msg}"),
            Self::UpstreamTimeout(msg) => write!(f, "upstream timeout: {msg}"),
            Self::NoRouteMatch => write!(f, "no matching route"),
            Self::MethodNotAllowed => write!(f, "method not allowed"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::RateLimited => write!(f, "rate limit exceeded"),
            Self::BodyTooLarge(max) => write!(f, "request body too large (max {max} bytes)"),
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
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
            GatewayError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".to_string())
            }
            GatewayError::BodyTooLarge(max) => {
                (StatusCode::PAYLOAD_TOO_LARGE, format!("request body exceeds {max} byte limit"))
            }
            GatewayError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, msg.clone())
            }
        };

        let body = json!({ "error": message, "status": status.as_u16() });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            GatewayError::RateLimited.to_string(),
            "rate limit exceeded"
        );
        assert_eq!(
            GatewayError::BodyTooLarge(1024).to_string(),
            "request body too large (max 1024 bytes)"
        );
        assert_eq!(
            GatewayError::Unauthorized("bad key".to_string()).to_string(),
            "unauthorized: bad key"
        );
    }

    #[test]
    fn test_error_display_all_variants() {
        assert!(GatewayError::UpstreamConnection("conn err".into()).to_string().contains("conn err"));
        assert!(GatewayError::UpstreamTimeout("timed out".into()).to_string().contains("timed out"));
        assert_eq!(GatewayError::NoRouteMatch.to_string(), "no matching route");
        assert_eq!(GatewayError::MethodNotAllowed.to_string(), "method not allowed");
        assert!(GatewayError::Internal("oops".into()).to_string().contains("oops"));
    }

    #[test]
    fn test_error_into_response_status_codes() {
        let cases: Vec<(GatewayError, StatusCode)> = vec![
            (GatewayError::UpstreamConnection("err".into()), StatusCode::BAD_GATEWAY),
            (GatewayError::UpstreamTimeout("timeout".into()), StatusCode::GATEWAY_TIMEOUT),
            (GatewayError::NoRouteMatch, StatusCode::NOT_FOUND),
            (GatewayError::MethodNotAllowed, StatusCode::METHOD_NOT_ALLOWED),
            (GatewayError::Internal("err".into()), StatusCode::INTERNAL_SERVER_ERROR),
            (GatewayError::RateLimited, StatusCode::TOO_MANY_REQUESTS),
            (GatewayError::BodyTooLarge(1024), StatusCode::PAYLOAD_TOO_LARGE),
            (GatewayError::Unauthorized("no".into()), StatusCode::UNAUTHORIZED),
        ];
        for (err, expected_status) in cases {
            let resp = err.into_response();
            assert_eq!(resp.status(), expected_status);
        }
    }
}