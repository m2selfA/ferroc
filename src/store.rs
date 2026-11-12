//! Native SQLite persistence for the Rust relay. Secrets are keys hashed by the caller.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub struct Store {
    connection: Mutex<Connection>,
}
impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let c = Connection::open(path)?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS kv(ns TEXT NOT NULL,k TEXT NOT NULL,v TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(ns,k)); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,device TEXT NOT NULL,client TEXT NOT NULL,tool TEXT NOT NULL,args_hash TEXT NOT NULL,ok INTEGER NOT NULL,ms INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS kv_expiry ON kv(expires);")?;
        Ok(Self {
            connection: Mutex::new(c),
        })
    }
    pub fn put(&self, ns: &str, key: &str, value: &Value, ttl: i64) -> Result<()> {
        ensure!(ttl > 0, "positive TTL required");
        let c = self.connection.lock().expect("store lock");
        c.execute("DELETE FROM kv WHERE expires<=?1", [now()])?;
        let count: i64 = c.query_row("SELECT count(*) FROM kv WHERE ns=?1", [ns], |r| r.get(0))?;
        ensure!(count < 10000, "namespace capacity exceeded");
        c.execute("INSERT INTO kv(ns,k,v,expires) VALUES(?1,?2,?3,?4) ON CONFLICT(ns,k) DO UPDATE SET v=excluded.v,expires=excluded.expires",params![ns,key,value.to_string(),now()+ttl])?;
        Ok(())
    }
    /// Unique creation: never overwrite a concurrently registered identity.
    pub fn insert_new(&self, ns: &str, key: &str, value: &Value, ttl: i64) -> Result<()> {
        ensure!(ttl > 0, "positive TTL required");
        let c = self.connection.lock().expect("store lock");
        c.execute("DELETE FROM kv WHERE expires<=?1", [now()])?;
        let count: i64 = c.query_row("SELECT count(*) FROM kv WHERE ns=?1", [ns], |r| r.get(0))?;
        ensure!(count < 10000, "namespace capacity exceeded");
        c.execute(
            "INSERT INTO kv(ns,k,v,expires) VALUES(?1,?2,?3,?4)",
            params![ns, key, value.to_string(), now() + ttl],
        )?;
        Ok(())
    }
    pub fn get(&self, ns: &str, key: &str) -> Result<Option<Value>> {
        let c = self.connection.lock().expect("store lock");
        let text: Option<String> = c
            .query_row(
                "SELECT v FROM kv WHERE ns=?1 AND k=?2 AND expires>?3",
                params![ns, key, now()],
                |r| r.get(0),
            )
            .optional()?;
        text.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    /// One-shot secrets (authorization codes / refresh tokens) are consumed atomically.
    pub fn take(&self, ns: &str, key: &str) -> Result<Option<Value>> {
        let mut c = self.connection.lock().expect("store lock");
        let tx = c.transaction()?;
        let text: Option<String> = tx
            .query_row(
                "DELETE FROM kv WHERE ns=?1 AND k=?2 AND expires>?3 RETURNING v",
                params![ns, key, now()],
                |r| r.get(0),
            )
            .optional()?;
        tx.commit()?;
        text.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    /// Update an existing record without extending its original deadline.
    pub fn update(&self, ns: &str, key: &str, value: &Value) -> Result<bool> {
        let c = self.connection.lock().expect("store lock");
        Ok(c.execute(
            "UPDATE kv SET v=?1 WHERE ns=?2 AND k=?3 AND expires>?4",
            params![value.to_string(), ns, key, now()],
        )? == 1)
    }
    pub fn delete(&self, ns: &str, key: &str) -> Result<()> {
        self.connection
            .lock()
            .expect("store lock")
            .execute("DELETE FROM kv WHERE ns=?1 AND k=?2", params![ns, key])?;
        Ok(())
    }
    pub fn list(&self, ns: &str) -> Result<Vec<(String, Value)>> {
        let c = self.connection.lock().expect("store lock");
        let mut stmt = c.prepare("SELECT k,v FROM kv WHERE ns=?1 AND expires>?2 ORDER BY k")?;
        let rows = stmt.query_map(params![ns, now()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (k, v) = row?;
            Ok((k, serde_json::from_str(&v)?))
        })
        .collect()
    }
    pub fn audit(
        &self,
        device: &str,
        client: &str,
        tool: &str,
        args_hash: &str,
        ok: bool,
        ms: i64,
    ) -> Result<()> {
        let c = self.connection.lock().expect("store lock");
        c.execute(
            "INSERT INTO audit(ts,device,client,tool,args_hash,ok,ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![now(), device, client, tool, args_hash, ok, ms],
        )?;
        c.execute(
            "DELETE FROM audit WHERE id <= (SELECT max(id)-10000 FROM audit)",
            [],
        )?;
        Ok(())
    }
    pub fn recent_audit(&self) -> Result<Value> {
        let c = self.connection.lock().expect("store lock");
        let mut stmt = c.prepare(
            "SELECT ts,device,client,tool,args_hash,ok,ms FROM audit ORDER BY id DESC LIMIT 100",
        )?;
        let rows=stmt.query_map([],|r|Ok(serde_json::json!({"ts":r.get::<_,i64>(0)?,"device":r.get::<_,String>(1)?,"client":r.get::<_,String>(2)?,"tool":r.get::<_,String>(3)?,"argsHash":r.get::<_,String>(4)?,"ok":r.get::<_,bool>(5)?,"ms":r.get::<_,i64>(6)?})))?;
        Ok(Value::Array(
            rows.collect::<std::result::Result<Vec<_>, _>>()?,
        ))
    }
}
