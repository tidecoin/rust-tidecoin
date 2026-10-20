// SPDX-License-Identifier: CC0-1.0
use std::process::Command;
use tidecoin_node_parity::TidecoinNodeHarness;

#[test]
fn configuration_child() {
    if std::env::var_os("TIDECOIN_PARITY_CONFIG_CHILD").is_some() {
        let _ = TidecoinNodeHarness::optional_from_env();
    }
}

fn child(required: &str, repo: Option<&str>) -> bool {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "configuration_child", "--nocapture"])
        .env("TIDECOIN_PARITY_CONFIG_CHILD", "1")
        .env("TIDECOIN_NODE_PARITY_REQUIRED", required)
        .env_remove("TIDECOIN_NODE_REPO");
    if let Some(repo) = repo {
        command.env("TIDECOIN_NODE_REPO", repo);
    }
    let output = command.output().unwrap();
    output.status.success()
}

#[test]
fn required_missing_and_invalid_configurations_fail_instead_of_skipping() {
    assert!(!child("1", None));
    assert!(!child("0", Some("/nonexistent-tidecoin-parity-checkout")));
    assert!(!child("invalid", None));
    // A required build cannot be turned into an optional one at runtime.
    assert_eq!(child("0", None), env!("TIDECOIN_NODE_PARITY_BUILT_REQUIRED") != "1");
}

#[test]
fn a_different_runtime_checkout_cannot_label_the_compiled_oracle() {
    let directory =
        std::env::temp_dir().join(format!("tidecoin-parity-config-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("src")).unwrap();
    // In a native build this is a different checkout; in a stub build it must
    // not activate an unavailable backend merely because a src directory exists.
    let accepted = child("1", Some(directory.to_str().unwrap()));
    std::fs::remove_dir_all(directory).unwrap();
    assert!(!accepted);
}

#[test]
fn oracle_configuration_child() {
    if let Ok(expected) = std::env::var("TIDECOIN_ORACLE_EXPECT_ERROR") {
        let error = tidecoin_node_parity::validation::run(&[]).expect_err("bad oracle must fail");
        assert!(error.to_string().contains(&expected), "{error}");
    }
}

#[test]
#[cfg(unix)]
fn original_oracle_missing_and_stale_executables_are_not_verdicts() {
    use std::os::unix::fs::PermissionsExt;
    use tidecoin_node_parity::validation::ORACLE_ENV;
    let Some(_) = TidecoinNodeHarness::optional_from_env() else { return };
    let directory =
        std::env::temp_dir().join(format!("tidecoin-oracle-config-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("fake-oracle");
    for (revision, digest, expected) in [
        ("wrong", "wrong", "executable revision differs"),
        (include_str!("../NODE_REVISION").trim(), "wrong", "validation.cpp digest differs"),
    ] {
        let response =
            serde_json::json!({"revision": revision, "validation_sha256": digest, "results": []});
        std::fs::write(
            &executable,
            format!("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{response}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "oracle_configuration_child", "--nocapture"])
            .env(ORACLE_ENV, &executable)
            .env("TIDECOIN_ORACLE_EXPECT_ERROR", expected)
            .status()
            .unwrap();
        assert!(status.success());
    }
    for path in [None, Some("/nonexistent-original-node-oracle")] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "oracle_configuration_child", "--nocapture"])
            .env_remove(ORACLE_ENV)
            .env(
                "TIDECOIN_ORACLE_EXPECT_ERROR",
                if path.is_some() { "oracle failed" } else { "build/set" },
            );
        if let Some(path) = path {
            child.env(ORACLE_ENV, path);
        }
        assert!(child.status().unwrap().success());
    }
    std::fs::remove_dir_all(directory).unwrap();
}
