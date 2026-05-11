use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use hyper::header::HeaderValue;
use std::time::Instant;
use tracing::{info, info_span, Instrument};
use uuid::Uuid;

/// Middleware that assigns a unique X-Request-Id to every request.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(val) = HeaderValue::from_str(&id) {
        req.headers_mut().insert("x-request-id", val.clone());
    }

    let mut resp = next.run(req).await;

    if let Ok(val) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert("x-request-id", val);
    }

    resp
}

/// Middleware that logs every request with method, path, status, and duration.
pub async fn logging_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    let span = info_span!(
        "request",
        method = %method,
        path = %path,
        request_id = %request_id,
    );

    async move {
        let start = Instant::now();
        let response = next.run(req).await;
        let duration = start.elapsed();
        let status = response.status().as_u16();

        info!(
            status = status,
            duration_ms = duration.as_millis() as u64,
            "Request completed"
        );

        response
    }
    .instrument(span)
    .await
}