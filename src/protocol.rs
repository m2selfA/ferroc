use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<Value>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}
impl ToolResult {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![serde_json::json!({"type":"text", "text":text.into()})],
            is_error: None,
        }
    }
    pub fn json(value: impl Serialize) -> Self {
        Self::text(serde_json::to_string_pretty(&value).expect("serializable tool output"))
    }
    pub fn error(error: impl std::fmt::Display) -> Self {
        Self {
            is_error: Some(true),
            ..Self::text(error.to_string())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    #[serde(rename = "welcome")]
    Welcome { protocol: u32 },
    #[serde(rename = "ping")]
    Ping { ts: u64 },
    #[serde(rename = "call")]
    Call {
        id: String,
        tool: String,
        args: Value,
        #[serde(rename = "timeoutMs")]
        timeout_ms: Option<u64>,
    },
    #[serde(rename = "error")]
    Error {
        code: String,
        message: String,
        #[serde(default)]
        fatal: bool,
    },
}
