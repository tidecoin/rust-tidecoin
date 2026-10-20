// SPDX-License-Identifier: CC0-1.0

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use crate::{NodeParityError, TidecoinNodeHarness};

/// Standalone executable built from `validation-oracle/CMakeLists.txt`.
pub const ORACLE_ENV: &str = "TIDECOIN_NODE_VALIDATION_ORACLE";

struct TestDirectory(PathBuf);
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Calls original C++ validation functions with explicit test context.
///
/// Each process has fresh node caches and its own temporary data directory.
/// Infrastructure failures are errors; decode failures are distinguished from validation verdicts.
/// Requests and results use the test-only JSON contract in `oracle.cpp`.
pub fn run(requests: &[Value]) -> Result<Vec<Value>, NodeParityError> {
    let harness = TidecoinNodeHarness::from_env()?;
    let executable = std::env::var_os(ORACLE_ENV)
        .ok_or(NodeParityError::Environment("build/set TIDECOIN_NODE_VALIDATION_ORACLE"))?;
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "rust-tidecoin-oracle-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    let directory = TestDirectory(path);
    let mut child = Command::new(executable)
        .arg(&directory.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    let input = serde_json::to_vec(&json!({"requests": requests})).expect("serialize test request");
    let written = child.stdin.take().expect("piped stdin").write_all(&input);
    let output = child.wait_with_output().map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    if !output.status.success() {
        return Err(NodeParityError::Oracle(format!(
            "{}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    written.map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    let response: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    if response["revision"].as_str() != Some(include_str!("../NODE_REVISION").trim()) {
        return Err(NodeParityError::Oracle(
            "executable revision differs from NODE_REVISION".into(),
        ));
    }
    let source = std::fs::read(harness.node_repo().join("src/validation.cpp"))
        .map_err(|e| NodeParityError::Oracle(e.to_string()))?;
    let source_hash = hashes::sha256::Hash::hash(&source).to_string();
    if response["validation_sha256"].as_str() != Some(source_hash.as_str()) {
        return Err(NodeParityError::Oracle(
            "executable validation.cpp digest differs from checkout".into(),
        ));
    }
    let results = response["results"]
        .as_array()
        .ok_or_else(|| NodeParityError::Oracle("missing results".into()))?;
    if results.len() != requests.len() {
        return Err(NodeParityError::Oracle("wrong verdict count".into()));
    }
    Ok(results.clone())
}

pub(crate) fn one(request: Value) -> Value {
    // Existing parity callers use is_ok() for acceptance. Panic on infrastructure
    // failures so missing tools or malformed adapters cannot look like rejection.
    run(&[request]).expect("original C++ validation oracle must produce a verdict").remove(0)
}

pub(crate) fn verdict(value: Value) -> Result<(), NodeParityError> {
    if value["decoded"].as_bool() == Some(false) {
        return Err(NodeParityError::NodeDecode(
            value["decode_error"].as_str().expect("decode error").into(),
        ));
    }
    match value["valid"].as_bool().expect("node verdict must contain a boolean") {
        true => Ok(()),
        false => Err(NodeParityError::NodeValidation {
            reason: value["reason"].as_str().expect("node reject reason").to_owned(),
            result: value["result"].as_i64().expect("node result category") as i32,
        }),
    }
}
