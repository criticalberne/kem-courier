use assert_cmd::prelude::*;
use predicates::str::contains;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const PASSPHRASE: &str = "correct horse battery staple";
const PLAINTEXT: &[u8] = b"post-quantum courier payload\nwith multiple lines\n";

#[test]
fn hybrid_round_trip_under_policy_reports_controls_and_verifies_audit_chain() {
    let dir = TempDir::new().expect("tempdir");

    generate_identity(&dir, "Alice Sender", "sender.json");
    generate_identity(&dir, "Bob Recipient", "recipient.json");
    export_public(&dir, "sender.json", "sender.public.json");
    export_public(&dir, "recipient.json", "recipient.public.json");
    fs::write(dir.path().join("message.txt"), PLAINTEXT).expect("write plaintext");

    kem(&dir)
        .args([
            "encrypt",
            "--sender",
            "sender.json",
            "--recipient",
            "recipient.public.json",
            "--mode",
            "hybrid-x25519-mlkem768",
            "--in",
            "message.txt",
            "--out",
            "envelope.json",
        ])
        .assert()
        .success()
        .stdout(contains("wrote envelope envelope.json"));

    let policy = write_policy(&dir, "sender.json", "recipient.json");

    kem(&dir)
        .args([
            "identity",
            "checkout",
            "--identity",
            "recipient.json",
            "--ttl",
            "10m",
            "--reason",
            "integration test decrypt",
            "--out",
            "recipient.lease.json",
        ])
        .assert()
        .success()
        .stdout(contains("wrote lease recipient.lease.json"));

    kem(&dir)
        .args([
            "decrypt",
            "--identity",
            "recipient.json",
            "--sender",
            "sender.public.json",
            "--in",
            "envelope.json",
            "--out",
            "decrypted.txt",
            "--policy",
        ])
        .arg(&policy)
        .args(["--lease", "recipient.lease.json"])
        .assert()
        .success()
        .stdout(contains("wrote plaintext decrypted.txt"));

    assert_eq!(
        fs::read(dir.path().join("decrypted.txt")).expect("read decrypted"),
        PLAINTEXT,
        "decrypt must recover the exact encrypted bytes"
    );

    let inspect = command_stdout(
        kem(&dir)
            .arg("inspect")
            .arg("envelope.json")
            .assert()
            .success(),
    );
    assert_contains_all(
        &inspect,
        &[
            "KEM Courier Envelope",
            "Suite: KEMCOURIER_MLKEM768_X25519_AES256GCM_MLDSA65_HKDFSHA256_V1",
            "Mode: HybridX25519Mlkem768",
            "Signature: ML-DSA-65",
            "Hybrid x25519: true",
            "Signed metadata: yes",
        ],
    );

    let review = command_stdout(
        kem(&dir)
            .args(["access-review", "--in", "envelope.json", "--policy"])
            .arg(&policy)
            .assert()
            .success(),
    );
    assert_contains_all(
        &review,
        &[
            "# KEM Courier Access Review",
            "## Policy Result\n\n`Allowed`",
            "- Sender signature required",
            "- Signed metadata required",
            "- Minimum mode satisfied: HybridX25519Mlkem768",
            "- Envelope age <= 1 days",
            "- Sender is approved",
            "- Recipient is approved",
        ],
    );

    kem(&dir)
        .args(["audit", "verify"])
        .assert()
        .success()
        .stdout(contains("audit log verified"));
}

#[test]
fn sealed_identity_requires_passphrase_and_active_lease_for_decrypt() {
    let dir = TempDir::new().expect("tempdir");

    generate_identity(&dir, "Sealing Sender", "sender.json");
    generate_identity(&dir, "Sealed Recipient", "recipient.json");
    export_public(&dir, "sender.json", "sender.public.json");
    export_public(&dir, "recipient.json", "recipient.public.json");

    kem(&dir)
        .args([
            "identity",
            "seal",
            "--identity",
            "recipient.json",
            "--out",
            "recipient.sealed.json",
            "--passphrase",
            PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(contains("wrote sealed identity recipient.sealed.json"));

    fs::write(dir.path().join("sealed-message.txt"), PLAINTEXT).expect("write plaintext");
    kem(&dir)
        .args([
            "encrypt",
            "--sender",
            "sender.json",
            "--recipient",
            "recipient.public.json",
            "--in",
            "sealed-message.txt",
            "--out",
            "sealed-envelope.json",
        ])
        .assert()
        .success();

    kem(&dir)
        .args([
            "identity",
            "checkout",
            "--identity",
            "recipient.sealed.json",
            "--ttl",
            "10m",
            "--reason",
            "missing passphrase should fail",
            "--out",
            "missing-passphrase.lease.json",
        ])
        .assert()
        .failure()
        .stderr(contains(
            "sealed identity checkout requires --passphrase or KEM_COURIER_PASSPHRASE",
        ));

    kem(&dir)
        .args([
            "identity",
            "checkout",
            "--identity",
            "recipient.sealed.json",
            "--ttl",
            "10m",
            "--reason",
            "approved decrypt",
            "--out",
            "recipient.lease.json",
            "--passphrase",
            PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(contains("wrote lease recipient.lease.json"));

    kem(&dir)
        .args([
            "decrypt",
            "--identity",
            "recipient.sealed.json",
            "--sender",
            "sender.public.json",
            "--in",
            "sealed-envelope.json",
            "--out",
            "no-passphrase.txt",
            "--lease",
            "recipient.lease.json",
        ])
        .assert()
        .failure()
        .stderr(contains(
            "sealed identity requires --passphrase or KEM_COURIER_PASSPHRASE",
        ));

    kem(&dir)
        .args([
            "decrypt",
            "--identity",
            "recipient.sealed.json",
            "--sender",
            "sender.public.json",
            "--in",
            "sealed-envelope.json",
            "--out",
            "no-lease.txt",
            "--passphrase",
            PASSPHRASE,
        ])
        .assert()
        .failure()
        .stderr(contains("sealed identity decrypt requires --lease"));

    kem(&dir)
        .args([
            "decrypt",
            "--identity",
            "recipient.sealed.json",
            "--sender",
            "sender.public.json",
            "--in",
            "sealed-envelope.json",
            "--out",
            "sealed-decrypted.txt",
            "--lease",
            "recipient.lease.json",
            "--passphrase",
            PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(contains("wrote plaintext sealed-decrypted.txt"));

    assert_eq!(
        fs::read(dir.path().join("sealed-decrypted.txt")).expect("read decrypted"),
        PLAINTEXT,
        "a sealed identity should decrypt only after passphrase unlock and lease checkout"
    );
}

#[test]
fn tampered_envelope_fails_signature_verification_without_writing_plaintext() {
    let dir = TempDir::new().expect("tempdir");

    generate_identity(&dir, "Tamper Sender", "sender.json");
    generate_identity(&dir, "Tamper Recipient", "recipient.json");
    export_public(&dir, "sender.json", "sender.public.json");
    export_public(&dir, "recipient.json", "recipient.public.json");
    fs::write(dir.path().join("message.txt"), PLAINTEXT).expect("write plaintext");

    kem(&dir)
        .args([
            "encrypt",
            "--sender",
            "sender.json",
            "--recipient",
            "recipient.public.json",
            "--in",
            "message.txt",
            "--out",
            "envelope.json",
        ])
        .assert()
        .success();

    kem(&dir)
        .args([
            "tamper",
            "envelope.json",
            "--field",
            "ciphertext",
            "--out",
            "tampered-envelope.json",
        ])
        .assert()
        .success()
        .stdout(contains("wrote tampered envelope tampered-envelope.json"));

    kem(&dir)
        .args([
            "decrypt",
            "--identity",
            "recipient.json",
            "--sender",
            "sender.public.json",
            "--in",
            "tampered-envelope.json",
            "--out",
            "tampered-output.txt",
        ])
        .assert()
        .failure()
        .stderr(contains("envelope signature verification failed"));

    assert!(
        !dir.path().join("tampered-output.txt").exists(),
        "signature verification must fail before any plaintext is written"
    );
}

fn kem(dir: &TempDir) -> Command {
    let mut command = Command::cargo_bin("kem-courier").expect("binary exists");
    command.current_dir(dir.path());
    command
}

fn generate_identity(dir: &TempDir, name: &str, out: &str) {
    kem(dir)
        .args(["identity", "generate", "--name", name, "--out", out])
        .assert()
        .success()
        .stdout(contains(format!("wrote identity {out}")));
}

fn export_public(dir: &TempDir, identity: &str, out: &str) {
    kem(dir)
        .args([
            "identity",
            "export-public",
            "--identity",
            identity,
            "--out",
            out,
        ])
        .assert()
        .success()
        .stdout(contains(format!("wrote public identity {out}")));
}

fn write_policy(dir: &TempDir, sender_identity: &str, recipient_identity: &str) -> PathBuf {
    let sender_fingerprint = identity_fingerprint(dir.path().join(sender_identity));
    let recipient_fingerprint = identity_fingerprint(dir.path().join(recipient_identity));
    let policy = format!(
        r#"require_sender_signature: true
require_signed_metadata: true
allow_unsigned_envelopes: false
minimum_encryption_mode: hybrid-x25519-mlkem768
max_envelope_age_days: 1
allowed_senders:
  - name: Alice Sender
    fingerprint: "{sender_fingerprint}"
allowed_recipients:
  - name: Bob Recipient
    fingerprint: "{recipient_fingerprint}"
"#,
    );
    let path = dir.path().join("policy.yaml");
    fs::write(&path, policy).expect("write policy");
    path
}

fn identity_fingerprint(path: impl AsRef<Path>) -> String {
    let json: Value = serde_json::from_str(&fs::read_to_string(path).expect("read identity"))
        .expect("identity json");
    json.pointer("/public/fingerprint")
        .and_then(Value::as_str)
        .expect("identity public fingerprint")
        .to_owned()
}

fn command_stdout(assert: assert_cmd::assert::Assert) -> String {
    String::from_utf8(assert.get_output().stdout.clone()).expect("stdout is utf8")
}

fn assert_contains_all(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            haystack.contains(needle),
            "expected output to contain {needle:?}\noutput:\n{haystack}"
        );
    }
}
