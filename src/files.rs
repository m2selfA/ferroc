use crate::config::{MAX_FILE, Policy, integer, string};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
};
use walkdir::WalkDir;

pub fn paginate(text: &str, offset: i64, length: usize) -> String {
    let lines: Vec<_> = text.lines().collect();
    let start = if offset < 0 {
        lines.len().saturating_sub(offset.unsigned_abs() as usize)
    } else {
        (offset as usize).min(lines.len())
    };
    let take = if offset < 0 {
        lines.len() - start
    } else {
        length
    };
    lines
        .into_iter()
        .skip(start)
        .take(take)
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn call(policy: &Policy, tool: &str, args: &Value) -> Result<Value> {
    match tool {
        "read_file" => {
            ensure!(
                !crate::config::boolean(args, "isUrl", false)?,
                "URL fetching is not enabled"
            );
            ensure!(
                args.get("sheet").is_none() && args.get("range").is_none(),
                "rich documents are not supported"
            );
            let text = policy.read_text(string(args, "path")?)?;
            let offset = integer(args, "offset", 0, -100_000, 100_000_000)?;
            let length = integer(args, "length", 1000, 1, 10_000)? as usize;
            Ok(json!({"text":paginate(&text,offset,length),"totalLines":text.lines().count()}))
        }
        "read_multiple_files" => {
            let paths = args["paths"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("paths must be an array"))?;
            ensure!(paths.len() <= 32, "at most 32 files per call");
            let mut remaining = MAX_FILE as usize;
            let mut results = Vec::new();
            for path in paths {
                let p = path
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("path must be a string"))?;
                let result = match policy.read_text(p) {
                    Ok(text) if text.len() <= remaining => {
                        remaining -= text.len();
                        json!({"path":p,"text":text})
                    }
                    Ok(_) => json!({"path":p,"error":"aggregate output limit exceeded"}),
                    Err(e) => json!({"path":p,"error":e.to_string()}),
                };
                results.push(result);
            }
            Ok(json!(results))
        }
        "write_file" => {
            let path = policy.resolve(string(args, "path")?)?;
            let content = string(args, "content")?;
            ensure!(content.len() as u64 <= MAX_FILE, "content exceeds 8 MiB");
            let mode = if args.get("mode").is_some() {
                string(args, "mode")?
            } else {
                "rewrite"
            };
            ensure!(
                mode == "rewrite" || mode == "append",
                "mode must be rewrite or append"
            );
            if mode == "append" {
                let mut file = OpenOptions::new().create(true).append(true).open(path)?;
                ensure!(
                    file.metadata()?.len().saturating_add(content.len() as u64) <= MAX_FILE,
                    "result exceeds 8 MiB"
                );
                file.write_all(content.as_bytes())?;
            } else {
                fs::write(path, content)?;
            }
            Ok(json!({"writtenBytes":content.len(),"mode":mode}))
        }
        "edit_block" => {
            ensure!(
                args.get("range").is_none(),
                "structured range editing is not supported"
            );
            let input = string(args, "file_path")?;
            let original = policy.read_text(input)?;
            let old = string(args, "old_string")?;
            let new = string(args, "new_string")?;
            ensure!(!old.is_empty(), "old_string must not be empty");
            let expected = integer(args, "expected_replacements", 1, 1, 100_000)? as usize;
            let count = original.matches(old).count();
            ensure!(
                count == expected,
                "expected {expected} matches, found {count}; file unchanged"
            );
            let replacement = original.replace(old, new);
            ensure!(
                replacement.len() as u64 <= MAX_FILE,
                "edited file exceeds 8 MiB"
            );
            let path = policy.resolve(input)?;
            fs::write(path, replacement)?;
            Ok(json!({"replacements":count}))
        }
        "create_directory" => {
            let path = policy.resolve(string(args, "path")?)?;
            fs::create_dir_all(&path)?;
            Ok(json!({"path":path}))
        }
        "move_file" => {
            let source = policy.resolve(string(args, "source")?)?;
            let destination = policy.resolve(string(args, "destination")?)?;
            ensure!(
                !destination.try_exists()?,
                "destination exists; refusing overwrite"
            );
            fs::rename(source, destination)?;
            Ok(json!({"moved":true}))
        }
        "list_directory" => {
            let root = policy.resolve(string(args, "path")?)?;
            ensure!(root.is_dir(), "not a directory");
            let depth = integer(args, "depth", 2, 1, 10)? as usize;
            let mut entries = Vec::new();
            let mut truncated = false;
            for entry in WalkDir::new(root)
                .min_depth(1)
                .max_depth(depth)
                .follow_links(false)
                .sort_by_file_name()
            {
                let entry = entry?;
                if entries.len() == 10_000 {
                    truncated = true;
                    break;
                }
                entries.push(json!({"path":entry.path(),"directory":entry.file_type().is_dir(),"symlink":entry.file_type().is_symlink()}));
            }
            Ok(json!({"entries":entries,"truncated":truncated}))
        }
        "get_file_info" => {
            let path = policy.resolve(string(args, "path")?)?;
            let m = fs::metadata(&path)?;
            Ok(
                json!({"path":path,"size":m.len(),"isDirectory":m.is_dir(),"readonly":m.permissions().readonly(),
                "modifiedUnixMs":m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d|d.as_millis())}),
            )
        }
        _ => bail!("unknown filesystem tool: {tool}"),
    }
}
