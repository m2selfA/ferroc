use crate::config::{Policy, boolean, integer, string};
use anyhow::{Context, Result, ensure};
use regex::RegexBuilder;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use walkdir::WalkDir;

struct Search {
    cancel: AtomicBool,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    results: Vec<Value>,
    done: bool,
    truncated: bool,
    errors: Vec<String>,
    bytes: usize,
    skipped_files: usize,
}
#[derive(Default)]
pub struct Searches {
    sessions: Mutex<HashMap<String, Arc<Search>>>,
}
impl Searches {
    pub fn start(&self, policy: Policy, args: Value) -> Result<Value> {
        let root = policy.resolve(string(&args, "path")?)?;
        let pattern = string(&args, "pattern")?.to_owned();
        ensure!(pattern.len() <= 4096, "pattern too large");
        let search_type = if args.get("searchType").is_some() {
            string(&args, "searchType")?
        } else {
            "files"
        };
        ensure!(
            search_type == "files" || search_type == "content",
            "searchType must be files or content"
        );
        let content = search_type == "content";
        let literal = boolean(&args, "literalSearch", false)?;
        let pattern = if literal {
            regex::escape(&pattern)
        } else {
            pattern
        };
        let re = RegexBuilder::new(&pattern)
            .case_insensitive(boolean(&args, "ignoreCase", true)?)
            .size_limit(4 * 1024 * 1024)
            .build()?;
        let file_glob = args
            .get("filePattern")
            .map(|v| {
                let value = v.as_str().context("filePattern must be a string")?;
                let mut b = globset::GlobSetBuilder::new();
                for p in value.split('|') {
                    b.add(globset::Glob::new(p)?);
                }
                b.build().map_err(anyhow::Error::from)
            })
            .transpose()?;
        let hidden = boolean(&args, "includeHidden", false)?;
        let max = integer(&args, "maxResults", 1000, 1, 10_000)? as usize;
        let timeout = integer(&args, "timeout_ms", 10_000, 1, 60_000)? as u64;
        let context = integer(&args, "contextLines", 5, 0, 20)? as usize;
        let early = boolean(&args, "earlyTermination", !content)?;
        let exact = string(&args, "pattern")?.to_owned();
        let id = Uuid::new_v4().to_string();
        let session = Arc::new(Search {
            cancel: AtomicBool::new(false),
            state: Mutex::new(State::default()),
        });
        let mut sessions = self.sessions.lock().expect("searches lock");
        ensure!(
            sessions.len() < 64,
            "search retention limit reached; restart agent to release retained searches"
        );
        sessions.insert(id.clone(), session.clone());
        drop(sessions);
        tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + Duration::from_millis(timeout);
            let run = || -> Result<()> {
                for entry in WalkDir::new(&root)
                    .follow_links(false)
                    .into_iter()
                    .filter_entry(|e| {
                        hidden
                            || e.depth() == 0
                            || !e.file_name().to_string_lossy().starts_with('.')
                    })
                {
                    if session.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    if Instant::now() >= deadline {
                        session.state.lock().expect("search lock").truncated = true;
                        break;
                    }
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => {
                            let mut s = session.state.lock().expect("search lock");
                            if s.errors.len() < 20 {
                                s.errors.push(e.to_string());
                            }
                            continue;
                        }
                    };
                    if entry.file_type().is_symlink() {
                        continue;
                    }
                    let name = entry.file_name().to_string_lossy();
                    if let Some(g) = &file_glob
                        && !g.is_match(name.as_ref())
                    {
                        continue;
                    }
                    let mut results = Vec::new();
                    let mut result_bytes = 0usize;
                    let mut limited = false;
                    if !content {
                        if re.is_match(&name) {
                            results.push(json!({"path":entry.path(),"type":"file_match"}));
                        }
                    } else if entry.file_type().is_file() {
                        // Check policy again at read time; never follow a link outside the root.
                        let path = entry.path().to_string_lossy();
                        if let Ok(text) = policy.read_text(&path) {
                            let lines: Vec<_> = text.lines().collect();
                            for (i, line) in lines.iter().enumerate() {
                                if session.cancel.load(Ordering::Relaxed)
                                    || Instant::now() >= deadline
                                {
                                    break;
                                }
                                if re.is_match(line) {
                                    let start = i.saturating_sub(context);
                                    let end = (i + context + 1).min(lines.len());
                                    // Bound each line; a single enormous text line must not inflate results.
                                    let excerpt: Vec<String> = lines[start..end]
                                        .iter()
                                        .map(|s| s.chars().take(1024).collect())
                                        .collect();
                                    let item = json!({"path":entry.path(),"lineNumber":i+1,"contextStart":start+1,"lines":excerpt});
                                    result_bytes += item.to_string().len();
                                    results.push(item);
                                    if results.len() == max || result_bytes >= 256 * 1024 {
                                        limited = true;
                                        break;
                                    }
                                }
                            }
                        } else {
                            session.state.lock().expect("search lock").skipped_files += 1;
                        }
                    }
                    let mut state = session.state.lock().expect("search lock");
                    state.truncated |= limited;
                    for item in results {
                        let size = item.to_string().len();
                        if state.bytes + size > 512 * 1024 || state.results.len() >= max {
                            state.truncated = true;
                            break;
                        }
                        state.bytes += size;
                        state.results.push(item);
                    }
                    if state.truncated || state.results.len() >= max {
                        state.truncated = true;
                        break;
                    }
                    if early && !content && name == exact {
                        break;
                    }
                }
                Ok(())
            };
            let result = run();
            let mut state = session.state.lock().expect("search lock");
            if let Err(e) = result {
                state.errors.push(e.to_string());
            }
            if Instant::now() >= deadline {
                state.truncated = true;
            }
            state.done = true;
        });
        Ok(json!({"sessionId":id,"status":"running"}))
    }
    pub fn results(&self, args: &Value) -> Result<Value> {
        let id = string(args, "sessionId")?;
        let sessions = self.sessions.lock().expect("searches lock");
        let s = sessions.get(id).context("unknown search session")?;
        let s = s.state.lock().expect("search lock");
        let offset = integer(args, "offset", 0, -10_000, 100_000)?;
        let length = integer(args, "length", 100, 1, 1000)? as usize;
        let start = if offset < 0 {
            s.results
                .len()
                .saturating_sub(offset.unsigned_abs() as usize)
        } else {
            (offset as usize).min(s.results.len())
        };
        let end = if offset < 0 {
            s.results.len()
        } else {
            (start + length).min(s.results.len())
        };
        Ok(
            json!({"sessionId":id,"results":&s.results[start..end],"totalResults":s.results.len(),"done":s.done,"truncated":s.truncated,"errors":s.errors,"skippedFiles":s.skipped_files}),
        )
    }
    pub fn stop(&self, args: &Value) -> Result<Value> {
        let sessions = self.sessions.lock().expect("searches lock");
        let id = string(args, "sessionId")?;
        let s = sessions.get(id).context("unknown search session")?;
        s.cancel.store(true, Ordering::Relaxed);
        Ok(json!({"sessionId":id,"stopRequested":true}))
    }
    pub fn list(&self) -> Value {
        let sessions = self.sessions.lock().expect("searches lock");
        json!(
            sessions
                .iter()
                .map(|(id, s)| {
                    let state = s.state.lock().expect("search lock");
                    json!({"sessionId":id,"done":state.done,"totalResults":state.results.len()})
                })
                .collect::<Vec<_>>()
        )
    }
    pub fn shutdown(&self) {
        for s in self.sessions.lock().expect("searches lock").values() {
            s.cancel.store(true, Ordering::Relaxed);
        }
    }
}
