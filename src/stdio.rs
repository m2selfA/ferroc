use crate::{
    protocol::MAX_FRAME,
    runtime::{Runtime, tools},
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};

pub async fn bounded_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        let count = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(buf.len());
        ensure!(
            line.len() + count <= MAX_FRAME,
            "MCP line exceeds 1 MiB; closing connection"
        );
        let complete = buf[count - 1] == b'\n';
        line.extend_from_slice(&buf[..count]);
        reader.consume(count);
        if complete {
            return Ok(Some(line));
        }
    }
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

#[derive(Clone, Default)]
pub struct Mcp {
    initialized: bool,
}
impl Mcp {
    pub async fn handle(&mut self, runtime: &Runtime, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        if request.get("jsonrpc") != Some(&json!("2.0")) || !request["method"].is_string() {
            return Some(error(id.unwrap_or(Value::Null), -32600, "Invalid Request"));
        }
        let method = request["method"].as_str().unwrap_or_default();
        let id = id?;
        if !id.is_string() && !id.is_number() {
            return Some(error(Value::Null, -32600, "Invalid request id"));
        }
        let result = match method {
            "initialize" => {
                if self.initialized {
                    return Some(error(id, -32600, "Already initialized"));
                }
                if !request["params"]["protocolVersion"].is_string() {
                    return Some(error(id, -32602, "protocolVersion required"));
                }
                let requested = request["params"]["protocolVersion"]
                    .as_str()
                    .unwrap_or_default();
                let supported = ["2024-11-05", "2025-03-26", "2025-06-18"];
                let version = if supported.contains(&requested) {
                    requested
                } else {
                    "2025-06-18"
                };
                self.initialized = true;
                json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"ferroc","version":env!("CARGO_PKG_VERSION")},"instructions":"Ferrum + Commander. Local policy guard is not a sandbox; shell disabled by default."})
            }
            "ping" => json!({}),
            _ if !self.initialized => return Some(error(id, -32000, "Initialize first")),
            "tools/list" => json!({"tools":tools()}),
            "tools/call" => {
                let Some(name) = request["params"]["name"].as_str() else {
                    return Some(error(id, -32602, "tool name required"));
                };
                let args = request["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                serde_json::to_value(runtime.call(name, args).await).expect("tool result")
            }
            _ => return Some(error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

pub async fn serve(runtime: Arc<Runtime>) -> Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut mcp = Mcp::default();
    while let Some(line) = bounded_line(&mut input).await? {
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(value) => mcp.handle(&runtime, value).await,
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            let mut encoded = serde_json::to_vec(&response)?;
            if encoded.len() > MAX_FRAME {
                encoded = serde_json::to_vec(&error(
                    response["id"].clone(),
                    -32000,
                    "Response exceeds 1 MiB; operation may have completed. Request smaller pages.",
                ))?;
            }
            encoded.push(b'\n');
            output.write_all(&encoded).await?;
            output.flush().await?;
        }
    }
    Ok(())
}
