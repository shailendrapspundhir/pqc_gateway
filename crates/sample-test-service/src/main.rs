use axum::extract::Request;
use axum::response::Json;
use axum::routing::{any, get};
use axum::Router;
use serde_json::json;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let app = Router::new()
        .route("/test/health", get(health))
        .route("/test/echo", any(echo))
        .route("/test/echo/{*rest}", any(echo))
        .route("/test/headers", get(headers));

    let listener = TcpListener::bind("0.0.0.0:9002").await.unwrap();
    info!("Sample test service listening on 0.0.0.0:9002");

    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "sample-test-service",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn echo(req: Request) -> Json<serde_json::Value> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    let headers: std::collections::HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string(), val.to_string()))
        })
        .collect();

    let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    info!(method = %method, path = %path, "Echo request");

    Json(json!({
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "body": body_str,
        "service": "sample-test-service",
    }))
}

async fn headers(req: Request) -> Json<serde_json::Value> {
    let headers: std::collections::HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string(), val.to_string()))
        })
        .collect();

    Json(json!({
        "headers": headers,
    }))
}