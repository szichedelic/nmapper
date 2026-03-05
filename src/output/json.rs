use std::path::Path;

use anyhow::{Context, Result};

use crate::models::ScanResult;

/// Print scan results as formatted JSON to stdout.
pub fn print_json(result: &ScanResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result).context("Failed to serialize results")?;
    println!("{json}");
    Ok(())
}

/// Write scan results as JSON to a file.
pub fn write_json_file(result: &ScanResult, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(result).context("Failed to serialize results")?;
    std::fs::write(Path::new(path), &json)
        .with_context(|| format!("Failed to write output to {path}"))?;
    eprintln!("[*] JSON output written to {path}");
    Ok(())
}
