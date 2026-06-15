//! WebSocket Upgrade Tunnel — proper bidirectional proxy.
//!
//! Handles:
//! - Detecting WebSocket upgrade requests
//! - Establishing upstream WebSocket connection
//! - Bidirectional frame forwarding (client ↔ gateway ↔ upstream)
//! - Ping/pong keepalive forwarding
//! - Clean shutdown on either side disconnecting

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as TungMessage;
use tracing::{error, info};

use crate::router::Route;

/// Check if a request is a WebSocket upgrade request.
pub fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Handle WebSocket upgrade and proxy frames to upstream.
pub async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    upstream_url: String,
) -> Response {
    info!(upstream = %upstream_url, "WebSocket upgrade accepted, connecting to upstream");
    ws.on_upgrade(move |socket| proxy_websocket(socket, upstream_url))
}

/// Proxy WebSocket frames between client and upstream bidirectionally.
async fn proxy_websocket(client_ws: WebSocket, upstream_url: String) {
    // Connect to upstream WebSocket
    let upstream_ws = match connect_async(&upstream_url).await {
        Ok((ws, _)) => {
            info!(upstream = %upstream_url, "Upstream WebSocket connection established");
            ws
        }
        Err(e) => {
            error!(upstream = %upstream_url, error = %e, "Failed to connect to upstream WebSocket");
            return;
        }
    };

    let (client_tx, client_rx) = client_ws.split();
    let (upstream_tx, upstream_rx) = upstream_ws.split();

    // Forward client → upstream
    let client_to_upstream = forward_client_to_upstream(client_rx, upstream_tx);

    // Forward upstream → client
    let upstream_to_client = forward_upstream_to_client(upstream_rx, client_tx);

    // Run both directions concurrently; stop when either side closes
    tokio::select! {
        result = client_to_upstream => {
            if let Err(e) = result {
                info!(error = %e, "Client→upstream forwarding ended");
            }
        }
        result = upstream_to_client => {
            if let Err(e) = result {
                info!(error = %e, "Upstream→client forwarding ended");
            }
        }
    }

    info!(upstream = %upstream_url, "WebSocket proxy session ended");
}

/// Forward frames from client (axum) to upstream (tungstenite).
async fn forward_client_to_upstream(
    mut client_rx: SplitStream<WebSocket>,
    mut upstream_tx: SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TungMessage,
    >,
) -> Result<(), String> {
    while let Some(msg) = client_rx.next().await {
        let msg = msg.map_err(|e| format!("client recv error: {e}"))?;
        let tung_msg = axum_to_tungstenite(msg);
        if let Some(m) = tung_msg {
            upstream_tx
                .send(m)
                .await
                .map_err(|e| format!("upstream send error: {e}"))?;
        } else {
            // Close frame or unhandled
            break;
        }
    }
    let _ = upstream_tx.close().await;
    Ok(())
}

/// Forward frames from upstream (tungstenite) to client (axum).
async fn forward_upstream_to_client(
    mut upstream_rx: SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    mut client_tx: SplitSink<WebSocket, Message>,
) -> Result<(), String> {
    while let Some(msg) = upstream_rx.next().await {
        let msg = msg.map_err(|e| format!("upstream recv error: {e}"))?;
        let axum_msg = tungstenite_to_axum(msg);
        if let Some(m) = axum_msg {
            client_tx
                .send(m)
                .await
                .map_err(|e| format!("client send error: {e}"))?;
        } else {
            break;
        }
    }
    let _ = client_tx.close().await;
    Ok(())
}

/// Convert an axum WebSocket message to a tungstenite message.
fn axum_to_tungstenite(msg: Message) -> Option<TungMessage> {
    match msg {
        Message::Text(text) => Some(TungMessage::Text(text.to_string().into())),
        Message::Binary(data) => Some(TungMessage::Binary(data.to_vec().into())),
        Message::Ping(data) => Some(TungMessage::Ping(data.to_vec().into())),
        Message::Pong(data) => Some(TungMessage::Pong(data.to_vec().into())),
        Message::Close(frame) => {
            let tung_frame = frame.map(|f| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(f.code),
                reason: f.reason.to_string().into(),
            });
            Some(TungMessage::Close(tung_frame))
        }
    }
}

/// Convert a tungstenite message to an axum WebSocket message.
fn tungstenite_to_axum(msg: TungMessage) -> Option<Message> {
    match msg {
        TungMessage::Text(text) => Some(Message::Text(text.to_string().into())),
        TungMessage::Binary(data) => Some(Message::Binary(data.to_vec().into())),
        TungMessage::Ping(data) => Some(Message::Ping(data.to_vec().into())),
        TungMessage::Pong(data) => Some(Message::Pong(data.to_vec().into())),
        TungMessage::Close(frame) => {
            let axum_frame = frame.map(|f| CloseFrame {
                code: f.code.into(),
                reason: f.reason.to_string().into(),
            });
            Some(Message::Close(axum_frame))
        }
        TungMessage::Frame(_) => None,
    }
}

/// Build the upstream WebSocket URL from a route and request path.
pub fn build_upstream_ws_url(route: &Route, request_path: &str) -> String {
    let base = &route.upstream;
    // Convert http:// to ws:// for the upstream connection
    let ws_base = if base.starts_with("http://") {
        base.replace("http://", "ws://")
    } else if base.starts_with("https://") {
        base.replace("https://", "wss://")
    } else {
        format!("ws://{base}")
    };

    let suffix = if route.strip_prefix {
        request_path
            .strip_prefix(&route.path_prefix)
            .unwrap_or("")
    } else {
        request_path
    };

    format!("{ws_base}{suffix}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_websocket_upgrade() {
        let mut headers = hyper::HeaderMap::new();
        assert!(!is_websocket_upgrade(&headers));

        headers.insert("upgrade", "websocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));

        headers.insert("upgrade", "WebSocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));

        headers.insert("upgrade", "http".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_build_upstream_ws_url_no_strip() {
        let route = Route {
            id: "ws-echo".to_string(),
            path_prefix: "/ws".to_string(),
            upstream: "http://127.0.0.1:9001".to_string(),
            strip_prefix: false,
            methods: vec!["GET".to_string()],
            timeout_ms: 30000,
            signature_mode: None,
        };
        let url = build_upstream_ws_url(&route, "/ws/echo");
        assert_eq!(url, "ws://127.0.0.1:9001/ws/echo");
    }

    #[test]
    fn test_build_upstream_ws_url_with_strip() {
        let route = Route {
            id: "ws-chat".to_string(),
            path_prefix: "/ws".to_string(),
            upstream: "http://127.0.0.1:9001".to_string(),
            strip_prefix: true,
            methods: vec!["GET".to_string()],
            timeout_ms: 30000,
            signature_mode: None,
        };
        let url = build_upstream_ws_url(&route, "/ws/chat/room1");
        assert_eq!(url, "ws://127.0.0.1:9001/chat/room1");
    }

    #[test]
    fn test_axum_to_tungstenite_text() {
        let msg = Message::Text("hello".into());
        let result = axum_to_tungstenite(msg).unwrap();
        assert!(matches!(result, TungMessage::Text(_)));
    }

    #[test]
    fn test_axum_to_tungstenite_binary() {
        let msg = Message::Binary(vec![1, 2, 3].into());
        let result = axum_to_tungstenite(msg).unwrap();
        assert!(matches!(result, TungMessage::Binary(_)));
    }

    #[test]
    fn test_axum_to_tungstenite_ping() {
        let msg = Message::Ping(vec![].into());
        let result = axum_to_tungstenite(msg).unwrap();
        assert!(matches!(result, TungMessage::Ping(_)));
    }

    #[test]
    fn test_tungstenite_to_axum_text() {
        let msg = TungMessage::Text("hello".to_string().into());
        let result = tungstenite_to_axum(msg).unwrap();
        assert!(matches!(result, Message::Text(_)));
    }

    #[test]
    fn test_tungstenite_to_axum_binary() {
        let msg = TungMessage::Binary(vec![1u8, 2, 3].into());
        let result = tungstenite_to_axum(msg).unwrap();
        assert!(matches!(result, Message::Binary(_)));
    }
}