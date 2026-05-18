use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Item {
    id: String,
    name: String,
    description: String,
}

/// A secret stored in the high-security vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Secret {
    id: String,
    label: String,
    value: String,
    classification: String,
}

/// Shared state holding both item and vault stores.
#[derive(Clone)]
struct AppState {
    items: Arc<RwLock<HashMap<String, Item>>>,
    vault: Arc<RwLock<HashMap<String, Secret>>>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let items: Arc<RwLock<HashMap<String, Item>>> = Arc::new(RwLock::new(HashMap::new()));
    let vault: Arc<RwLock<HashMap<String, Secret>>> = Arc::new(RwLock::new(HashMap::new()));

    // Seed item data
    {
        let mut s = items.write().await;
        s.insert(
            "1".to_string(),
            Item {
                id: "1".to_string(),
                name: "Widget".to_string(),
                description: "A useful widget".to_string(),
            },
        );
        s.insert(
            "2".to_string(),
            Item {
                id: "2".to_string(),
                name: "Gadget".to_string(),
                description: "A fancy gadget".to_string(),
            },
        );
    }

    // Seed vault data
    {
        let mut v = vault.write().await;
        v.insert(
            "secret-1".to_string(),
            Secret {
                id: "secret-1".to_string(),
                label: "DB Password".to_string(),
                value: "s3cret-p@ssw0rd".to_string(),
                classification: "top-secret".to_string(),
            },
        );
    }

    let state = AppState { items, vault };

    let app = Router::new()
        // Normal items endpoints (hybrid signatures)
        .route("/api/v1/items", get(list_items).post(create_item))
        .route(
            "/api/v1/items/{id}",
            get(get_item).put(update_item).delete(delete_item),
        )
        // High-security vault endpoints (mldsa-only signatures)
        .route("/api/v1/secure/vault", get(list_secrets).post(create_secret))
        .route(
            "/api/v1/secure/vault/{id}",
            get(get_secret).delete(delete_secret),
        )
        .route("/ws/echo", get(ws_handler))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:9001").await.unwrap();
    info!("Sample API service listening on 0.0.0.0:9001");

    axum::serve(listener, app).await.unwrap();
}

// ---- Item CRUD (normal path — hybrid signatures) ----

async fn list_items(State(state): State<AppState>) -> Json<serde_json::Value> {
    let s = state.items.read().await;
    let items: Vec<&Item> = s.values().collect();
    Json(serde_json::json!({ "items": items, "count": items.len() }))
}

async fn get_item(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let s = state.items.read().await;
    match s.get(&id) {
        Some(item) => Ok(Json(serde_json::json!(item))),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn create_item(
    State(state): State<AppState>,
    Json(item): Json<Item>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let mut s = state.items.write().await;
    let id = if item.id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        item.id.clone()
    };
    let new_item = Item {
        id: id.clone(),
        name: item.name,
        description: item.description,
    };
    s.insert(id.clone(), new_item.clone());
    info!(id = %id, "Item created");
    (
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!(new_item)),
    )
}

async fn update_item(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(update): Json<Item>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut s = state.items.write().await;
    if !s.contains_key(&id) {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }
    let item = Item {
        id: id.clone(),
        name: update.name,
        description: update.description,
    };
    s.insert(id.clone(), item.clone());
    info!(id = %id, "Item updated");
    Ok(Json(serde_json::json!(item)))
}

async fn delete_item(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut s = state.items.write().await;
    match s.remove(&id) {
        Some(item) => {
            info!(id = %id, "Item deleted");
            Ok(Json(serde_json::json!({ "deleted": item })))
        }
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

// ---- Secure Vault CRUD (high-security path — mldsa-only signatures) ----

async fn list_secrets(State(state): State<AppState>) -> Json<serde_json::Value> {
    let v = state.vault.read().await;
    let secrets: Vec<&Secret> = v.values().collect();
    Json(serde_json::json!({ "secrets": secrets, "count": secrets.len() }))
}

async fn get_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let v = state.vault.read().await;
    match v.get(&id) {
        Some(secret) => Ok(Json(serde_json::json!(secret))),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn create_secret(
    State(state): State<AppState>,
    Json(secret): Json<Secret>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let mut v = state.vault.write().await;
    let id = if secret.id.is_empty() {
        uuid::Uuid::new_v4().to_string()
    } else {
        secret.id.clone()
    };
    let new_secret = Secret {
        id: id.clone(),
        label: secret.label,
        value: secret.value,
        classification: secret.classification,
    };
    v.insert(id.clone(), new_secret.clone());
    info!(id = %id, "Secret stored in vault");
    (
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!(new_secret)),
    )
}

async fn delete_secret(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut v = state.vault.write().await;
    match v.remove(&id) {
        Some(secret) => {
            info!(id = %id, "Secret deleted from vault");
            Ok(Json(serde_json::json!({ "deleted": secret })))
        }
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn ws_handler(ws: WebSocketUpgrade) -> axum::response::Response {
    ws.on_upgrade(handle_websocket)
}

async fn handle_websocket(mut socket: WebSocket) {
    info!("WebSocket connection established");
    while let Some(Ok(msg)) = socket.next().await {
        match msg {
            Message::Text(text) => {
                info!(msg = %text, "WS received text");
                let reply = format!("echo: {text}");
                if socket.send(Message::Text(reply.into())).await.is_err() {
                    break;
                }
            }
            Message::Binary(data) => {
                if socket.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Message::Ping(data) => {
                if socket.send(Message::Pong(data)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => {
                info!("WebSocket closed by client");
                break;
            }
            _ => {}
        }
    }
    info!("WebSocket connection closed");
}