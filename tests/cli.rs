//! Drives the `frostsig` binary the way a user would.

use std::process::{Command, Output};

fn frostsig(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frostsig")).args(args).output().expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn vectors_command_passes() {
    let o = frostsig(&["vectors"]);
    assert!(o.status.success(), "{}", stdout(&o));
    let out = stdout(&o);
    assert!(out.contains("FROST(Ed25519, SHA-512)"));
    assert!(out.contains("FROST(ristretto255, SHA-512)"));
    assert!(!out.contains("[FAIL]"));
    assert!(out.contains("47 of 47 checks passed"));
}

#[test]
fn simulate_text_and_json() {
    let o = frostsig(&["simulate", "--seed", "1", "-t", "2", "-n", "3", "--keygen", "dkg", "-m", "hi"]);
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("educational software"));
    assert!(out.contains("verify (ed25519-dalek strict): OK"));

    let o = frostsig(&[
        "simulate",
        "--seed",
        "1",
        "--suite",
        "ristretto255",
        "-t",
        "2",
        "-n",
        "4",
        "--fault",
        "2=bad-share",
        "--json",
        "--timeout-ms",
        "300",
    ]);
    assert!(o.status.success());
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["suite"], "FROST(ristretto255, SHA-512)");
    assert_eq!(v["sessions"][0]["attempts"][0]["culprits"][0], 2);
    assert_eq!(v["sessions"][0]["verified"], true);
}

#[test]
fn keygen_sign_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let keys_s = keys.to_str().unwrap();
    let o = frostsig(&["keygen", "--keygen", "dkg", "-t", "2", "-n", "3", "--seed", "5", "--out", keys_s]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(keys.join("group.json").exists());
    for i in 1..=3 {
        let p = keys.join(format!("participant-{i}.json"));
        assert!(p.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
    let group: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(keys.join("group.json")).unwrap()).unwrap();
    let pk = group["verifying_key"].as_str().unwrap().to_string();

    // Remove one participant's file: the remaining two still meet t = 2.
    std::fs::remove_file(keys.join("participant-1.json")).unwrap();
    let o = frostsig(&["sign", "--keys", keys_s, "-m", "ship it", "--json"]);
    assert!(o.status.success(), "{}", stdout(&o));
    let report: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(report["sessions"][0]["attempts"][0]["signers"], serde_json::json!([2, 3]));
    let sig = report["sessions"][0]["signature"].as_str().unwrap().to_string();

    let o = frostsig(&["verify", "--public-key", &pk, "-m", "ship it", "--signature", &sig]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("verify (ed25519-dalek strict): OK"));

    let o = frostsig(&["verify", "--public-key", &pk, "-m", "ship it!", "--signature", &sig]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stdout(&o).contains("FAILED"));

    // A wrong-suite verification fails cleanly too.
    let o = frostsig(&[
        "verify",
        "--suite",
        "ristretto255",
        "--public-key",
        &pk,
        "-m",
        "ship it",
        "--signature",
        &sig,
    ]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn sign_rejects_foreign_or_missing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    for (d, seed) in [(&a, "1"), (&b, "2")] {
        let o = frostsig(&["keygen", "-t", "2", "-n", "2", "--seed", seed, "--out", d.to_str().unwrap()]);
        assert!(o.status.success());
    }
    // Swap in a key file from another group.
    std::fs::copy(b.join("participant-2.json"), a.join("participant-2.json")).unwrap();
    let o = frostsig(&["sign", "--keys", a.to_str().unwrap(), "-m", "x"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not belong to this group"));

    let o = frostsig(&["sign", "--keys", dir.path().join("nope").to_str().unwrap(), "-m", "x"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn keygen_failure_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("k");
    let o = frostsig(&[
        "keygen",
        "--keygen",
        "dkg",
        "-t",
        "2",
        "-n",
        "3",
        "--seed",
        "1",
        "--fault",
        "2=bad-dkg-share:3",
        "--timeout-ms",
        "300",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stdout(&o).contains("identified culprits: [P2]"));
    assert!(String::from_utf8_lossy(&o.stderr).contains("nothing written"));
    assert!(!out.exists());

    let o = frostsig(&["keygen", "-t", "5", "-n", "3", "--out", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid threshold"));
}

#[test]
fn bad_arguments_exit_with_code_2() {
    for args in [
        vec!["simulate", "--fault", "2"],
        vec!["simulate", "--fault", "x=bad-share"],
        vec!["simulate", "--fault", "2=gremlin"],
        vec!["simulate", "--keygen", "magic"],
        vec!["verify", "--public-key", "00", "-m", "x", "--signature", "00"],
        vec!["verify", "--public-key", &"00".repeat(32), "-m", "x", "--signature", "00"],
        vec!["bench", "--sizes", "1"],
    ] {
        let o = frostsig(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn bench_prints_a_table() {
    let o = frostsig(&[
        "bench",
        "--suite",
        "ristretto255",
        "--sizes",
        "3,4",
        "--iterations",
        "1",
        "--dkg-max-n",
        "3",
    ]);
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("| n | t |"));
    assert!(out.contains("| 4 | 3 |"));
}
