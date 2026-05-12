use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message;

const GATEWAY_HTTP_URL: &str = "http://127.0.0.1:8090";
const GATEWAY_HTTPS_URL: &str = "https://127.0.0.1:8443";

fn gateway_url() -> &'static str {
    // Use HTTPS if the TLS gateway is running, else fall back to HTTP
    if std::env::var("PQC_USE_TLS").unwrap_or_default() == "1" {
        GATEWAY_HTTPS_URL
    } else {
        GATEWAY_HTTP_URL
    }
}

fn build_client() -> Result<reqwest::Client> {
    if gateway_url().starts_with("https") {
        // Build a client that trusts our self-signed CA
        let ca_cert_path = std::env::var("PQC_CA_CERT")
            .unwrap_or_else(|_| "config/certs/ca.crt".to_string());
        let ca_pem = std::fs::read(&ca_cert_path)
            .unwrap_or_default();
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // For self-signed certs in testing
            .use_rustls_tls();
        if !ca_pem.is_empty() {
            let cert = reqwest::Certificate::from_pem(&ca_pem)?;
            builder = builder.add_root_certificate(cert);
        }
        Ok(builder.build()?)
    } else {
        Ok(reqwest::Client::new())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let client = build_client()?;
    let mut passed = 0u32;
    let mut failed = 0u32;

    let gw = gateway_url();
    println!("=== PQC Gateway Sample Client ===");
    println!("Gateway URL: {gw}\n");

    // --- Test 1: Gateway health ---
    print_test("1. Gateway health check");
    match client.get(format!("{gw}/health")).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - Status: healthy, Response: {body}");
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Unexpected status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 2: GET /api/v1/items (list) ---
    print_test("2. GET /api/v1/items (list items)");
    match client
        .get(format!("{gw}/api/v1/items"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            let count = body["count"].as_u64().unwrap_or(0);
            println!("   PASS - Got {count} items");
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 3: POST /api/v1/items (create) ---
    print_test("3. POST /api/v1/items (create item)");
    let new_item = json!({
        "id": "test-100",
        "name": "Test Item",
        "description": "Created by sample client"
    });
    match client
        .post(format!("{gw}/api/v1/items"))
        .json(&new_item)
        .send()
        .await
    {
        Ok(resp) if resp.status().as_u16() == 201 => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - Created: {}", body["name"]);
            passed += 1;
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            println!("   FAIL - Status: {status}, Body: {body}");
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 4: GET /api/v1/items/test-100 (get specific) ---
    print_test("4. GET /api/v1/items/test-100 (get created item)");
    match client
        .get(format!("{gw}/api/v1/items/test-100"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - Got item: {}", body["name"]);
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 5: PUT /api/v1/items/test-100 (update) ---
    print_test("5. PUT /api/v1/items/test-100 (update item)");
    let updated = json!({
        "id": "test-100",
        "name": "Updated Test Item",
        "description": "Updated by sample client"
    });
    match client
        .put(format!("{gw}/api/v1/items/test-100"))
        .json(&updated)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - Updated: {}", body["name"]);
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 6: DELETE /api/v1/items/test-100 ---
    print_test("6. DELETE /api/v1/items/test-100 (delete item)");
    match client
        .delete(format!("{gw}/api/v1/items/test-100"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - Deleted: {}", body["deleted"]["name"]);
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 7: GET /api/v1/items/test-100 (should be 404 now) ---
    print_test("7. GET /api/v1/items/test-100 (should be 404 after delete)");
    match client
        .get(format!("{gw}/api/v1/items/test-100"))
        .send()
        .await
    {
        Ok(resp) if resp.status().as_u16() == 404 => {
            println!("   PASS - Correctly got 404");
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Expected 404, got: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 8: Test service echo (POST) ---
    print_test("8. POST /test/echo (echo service)");
    match client
        .post(format!("{gw}/test/echo"))
        .body("hello gateway")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            let echoed_method = body["method"].as_str().unwrap_or("");
            let echoed_body = body["body"].as_str().unwrap_or("");
            if echoed_method == "POST" && echoed_body == "hello gateway" {
                println!("   PASS - Echo correct: method={echoed_method}, body={echoed_body}");
                passed += 1;
            } else {
                println!("   FAIL - Echo mismatch: {body}");
                failed += 1;
            }
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 9: Test service health ---
    print_test("9. GET /test/health");
    match client
        .get(format!("{gw}/test/health"))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            println!("   PASS - {}", body["service"]);
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 10: Test service headers (verify X-Request-Id forwarded) ---
    print_test("10. GET /test/headers (verify X-Request-Id)");
    match client
        .get(format!("{gw}/test/headers"))
        .header("x-custom-header", "test-value")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await?;
            let headers = &body["headers"];
            let has_request_id = headers.get("x-request-id").is_some();
            let has_forwarded_proto = headers.get("x-forwarded-proto").is_some();
            if has_request_id && has_forwarded_proto {
                println!("   PASS - X-Request-Id and X-Forwarded-Proto present");
                passed += 1;
            } else {
                println!("   FAIL - Missing gateway headers: {headers}");
                failed += 1;
            }
        }
        Ok(resp) => {
            println!("   FAIL - Status: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 11: 404 on unknown route ---
    print_test("11. GET /unknown/route (should be 404)");
    match client
        .get(format!("{gw}/unknown/route"))
        .send()
        .await
    {
        Ok(resp) if resp.status().as_u16() == 404 => {
            println!("   PASS - Correctly got 404");
            passed += 1;
        }
        Ok(resp) => {
            println!("   FAIL - Expected 404, got: {}", resp.status());
            failed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // --- Test 12: WebSocket echo through gateway ---
    print_test("12. WebSocket echo through gateway");
    match test_websocket().await {
        Ok(()) => {
            println!("   PASS - WebSocket echo works");
            passed += 1;
        }
        Err(e) => {
            println!("   FAIL - {e}");
            failed += 1;
        }
    }

    // Summary
    println!("\n=== Results: {passed} passed, {failed} failed out of {} ===", passed + failed);
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

async fn test_websocket() -> Result<()> {
    let url = "ws://127.0.0.1:9001/ws/echo";
    let (mut ws, _) = connect_async(url).await?;

    // Send a message
    ws.send(Message::Text("hello websocket".into())).await?;

    // Receive the echo
    if let Some(Ok(msg)) = ws.next().await {
        let text = msg.into_text()?;
        if text == "echo: hello websocket" {
            // Send close
            ws.close(None).await.ok();
            return Ok(());
        } else {
            anyhow::bail!("Unexpected echo: {text}");
        }
    }
    anyhow::bail!("No response received");
}

fn print_test(name: &str) {
    println!(">> {name}");
}