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

type ItemStore = Arc<RwLock<HashMap<String, Item>>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let store: ItemStore = Arc::new(RwLock::new(HashMap::new()));

    // Seed some data
    {
        let mut s = store.write().await;
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

    let app = Router::new()
        .route("/api/v1/items", get(list_items).post(create_item))
        .route(
            "/api/v1/items/{id}",
            get(get_item).put(update_item).delete(delete_item),
        )
        .route("/ws/echo", get(ws_handler))
        .with_state(store);

    let listener = TcpListener::bind("0.0.0.0:9001").await.unwrap();
    info!("Sample API service listening on 0.0.0.0:9001");

    axum::serve(listener, app).await.unwrap();
}

async fn list_items(State(store): State<ItemStore>) -> Json<serde_json::Value> {
    let s = store.read().await;
    let items: Vec<&Item> = s.values().collect();
    Json(serde_json::json!({ "items": items, "count": items.len() }))
}

async fn get_item(
    State(store): State<ItemStore>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let s = store.read().await;
    match s.get(&id) {
        Some(item) => Ok(Json(serde_json::json!(item))),
        None => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn create_item(
    State(store): State<ItemStore>,
    Json(item): Json<Item>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    let mut s = store.write().await;
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
    State(store): State<ItemStore>,
    Path(id): Path<String>,
    Json(update): Json<Item>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut s = store.write().await;
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
    State(store): State<ItemStore>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut s = store.write().await;
    match s.remove(&id) {
        Some(item) => {
            info!(id = %id, "Item deleted");
            Ok(Json(serde_json::json!({ "deleted": item })))
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