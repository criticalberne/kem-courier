use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hkdf::Hkdf;
use ml_dsa::{
    Generate, KeyExport as DsaKeyExport, KeyInit as DsaKeyInit, Keypair, MlDsa65,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyInit as KemKeyInit, TryKeyInit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

type KemDecap = <MlKem768 as Kem>::DecapsulationKey;
type KemEncap = <MlKem768 as Kem>::EncapsulationKey;
type DsaSigningKey = SigningKey<MlDsa65>;
type DsaVerifyingKey = VerifyingKey<MlDsa65>;

const VERSION: u8 = 1;
const SUITE_PQC_ONLY: &str = "KEMCOURIER_MLKEM768_AES256GCM_MLDSA65_HKDFSHA256_V1";
const SUITE_HYBRID: &str = "KEMCOURIER_MLKEM768_X25519_AES256GCM_MLDSA65_HKDFSHA256_V1";
const AUDIT_LOG: &str = "qstg.audit.jsonl";

#[derive(Parser, Debug)]
#[command(name = "qstg")]
#[command(about = "Quantum-safe AI trust gateway with KEM Courier PQC envelopes")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    Inspect(InspectArgs),
    #[command(name = "access-review")]
    AccessReview(AccessReviewArgs),
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    Ai {
        #[command(subcommand)]
        command: AiCommand,
    },
    Tamper(TamperArgs),
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    Generate(IdentityGenerateArgs),
    #[command(name = "export-public")]
    ExportPublic(ExportPublicArgs),
    Seal(SealArgs),
    Checkout(CheckoutArgs),
    Rotate(RotateArgs),
    Revoke(RevokeArgs),
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    Show,
    Verify,
}

#[derive(Subcommand, Debug)]
enum AiCommand {
    /// Evaluate an AI request through model, prompt, tool, data, and PQC policy controls.
    Evaluate(AiEvaluateArgs),
}

#[derive(Args, Debug)]
struct IdentityGenerateArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct ExportPublicArgs {
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct SealArgs {
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: String,
}

#[derive(Args, Debug)]
struct CheckoutArgs {
    #[arg(long)]
    identity: PathBuf,
    #[arg(long, default_value = "15m")]
    ttl: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct RotateArgs {
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct RevokeArgs {
    #[arg(long)]
    fingerprint: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct EncryptArgs {
    #[arg(long)]
    sender: PathBuf,
    #[arg(long)]
    recipient: PathBuf,
    #[arg(long, value_enum, default_value_t = ExchangeMode::HybridX25519Mlkem768)]
    mode: ExchangeMode,
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct DecryptArgs {
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    sender: PathBuf,
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    lease: Option<PathBuf>,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct InspectArgs {
    #[arg(value_name = "ENVELOPE")]
    envelope: PathBuf,
}

#[derive(Args, Debug)]
struct AccessReviewArgs {
    #[arg(long = "in")]
    input: PathBuf,
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long, default_value = "markdown")]
    format: String,
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct TamperArgs {
    #[arg(value_name = "ENVELOPE")]
    envelope: PathBuf,
    #[arg(long, default_value = "suite")]
    field: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct AiEvaluateArgs {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long = "access-review-out")]
    access_review_out: Option<PathBuf>,
    #[arg(long)]
    sender: Option<PathBuf>,
    #[arg(long)]
    recipient: Option<PathBuf>,
    #[arg(long = "envelope-out")]
    envelope_out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ExchangeMode::HybridX25519Mlkem768)]
    mode: ExchangeMode,
    #[arg(long, env = "QSTG_PASSPHRASE")]
    passphrase: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ExchangeMode {
    #[value(name = "pqc-only")]
    PqcOnly,
    #[value(name = "hybrid-x25519-mlkem768")]
    HybridX25519Mlkem768,
}

impl ExchangeMode {
    fn suite(self) -> &'static str {
        match self {
            ExchangeMode::PqcOnly => SUITE_PQC_ONLY,
            ExchangeMode::HybridX25519Mlkem768 => SUITE_HYBRID,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IdentityFile {
    version: u8,
    name: String,
    created_at: DateTime<Utc>,
    public: PublicIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    private: Option<PrivateIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_private: Option<SealedPrivateIdentity>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PublicIdentity {
    name: String,
    fingerprint: String,
    mlkem768_public_key: String,
    mldsa65_verify_key: String,
    x25519_public_key: String,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
struct PrivateIdentity {
    mlkem768_decapsulation_seed: String,
    mldsa65_signing_seed: String,
    x25519_private_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SealedPrivateIdentity {
    kdf: String,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LeaseFile {
    version: u8,
    lease_id: String,
    identity_fingerprint: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reason: String,
    allowed_operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationList {
    version: u8,
    revoked_keys: Vec<RevokedKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevokedKey {
    fingerprint: String,
    revoked_at: DateTime<Utc>,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Envelope {
    version: u8,
    suite: String,
    mode: ExchangeMode,
    created_at: DateTime<Utc>,
    sender: EnvelopeParty,
    recipient: EnvelopeParty,
    key_exchange: KeyExchange,
    wrapped_key: EncryptedBlob,
    payload: EncryptedBlob,
    signature: EnvelopeSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UnsignedEnvelope {
    version: u8,
    suite: String,
    mode: ExchangeMode,
    created_at: DateTime<Utc>,
    sender: EnvelopeParty,
    recipient: EnvelopeParty,
    key_exchange: KeyExchange,
    wrapped_key: EncryptedBlob,
    payload: EncryptedBlob,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EnvelopeParty {
    name: String,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyExchange {
    mlkem768_ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    x25519_ephemeral_public: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EncryptedBlob {
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EnvelopeSignature {
    algorithm: String,
    value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum DataClassification {
    Public,
    Internal,
    Confidential,
    Regulated,
}

impl DataClassification {
    fn rank(self) -> u8 {
        match self {
            DataClassification::Public => 0,
            DataClassification::Internal => 1,
            DataClassification::Confidential => 2,
            DataClassification::Regulated => 3,
        }
    }

    fn at_or_above(self, other: DataClassification) -> bool {
        self.rank() >= other.rank()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AiRequest {
    actor: String,
    model: String,
    prompt: String,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    requested_tools: Vec<String>,
    #[serde(default)]
    data_classification: Option<DataClassification>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
struct AiTrustPolicy {
    #[serde(default)]
    approved_models: Vec<String>,
    #[serde(default)]
    blocked_prompt_patterns: Vec<String>,
    #[serde(default)]
    tool_rules: Vec<AiToolRule>,
    #[serde(default)]
    require_pqc_envelope_for: Vec<DataClassification>,
    #[serde(default)]
    controls: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AiToolRule {
    name: String,
    max_classification: DataClassification,
    #[serde(default)]
    approval_required_for: Vec<DataClassification>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AiToolDecision {
    name: String,
    decision: AiDecision,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum AiDecision {
    Allowed,
    ApprovalRequired,
    Denied,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AiProvenance {
    version: u8,
    request_id: String,
    actor: String,
    model: String,
    data_classification: DataClassification,
    decision: AiDecision,
    prompt_injection_detected: bool,
    reasons: Vec<String>,
    requested_tools: Vec<String>,
    tool_decisions: Vec<AiToolDecision>,
    controls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto_suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    envelope_fingerprint: Option<String>,
    created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<EnvelopeSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AiArtifact {
    version: u8,
    request_id: String,
    actor: String,
    model: String,
    data_classification: DataClassification,
    response: String,
    created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
struct Policy {
    minimum_encryption_mode: Option<ExchangeMode>,
    require_sender_signature: Option<bool>,
    require_signed_metadata: Option<bool>,
    allow_unsigned_envelopes: Option<bool>,
    max_envelope_age_days: Option<i64>,
    allowed_senders: Option<Vec<PolicyPrincipal>>,
    allowed_recipients: Option<Vec<PolicyPrincipal>>,
    key_lifecycle: Option<KeyLifecyclePolicy>,
    revocation_list: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PolicyPrincipal {
    name: Option<String>,
    fingerprint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KeyLifecyclePolicy {
    reject_expired_identity_keys: Option<bool>,
    max_identity_age_days: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuditEvent {
    event_id: String,
    event_type: String,
    timestamp: DateTime<Utc>,
    identity_fingerprint: Option<String>,
    envelope_fingerprint: Option<String>,
    sender_fingerprint: Option<String>,
    recipient_fingerprint: Option<String>,
    policy_result: String,
    reason: Option<String>,
    details: Vec<String>,
    previous_hash: String,
    event_hash: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Identity { command } => match command {
            IdentityCommand::Generate(args) => identity_generate(args),
            IdentityCommand::ExportPublic(args) => export_public(args),
            IdentityCommand::Seal(args) => seal_identity(args),
            IdentityCommand::Checkout(args) => checkout_identity(args),
            IdentityCommand::Rotate(args) => rotate_identity(args),
            IdentityCommand::Revoke(args) => revoke_identity(args),
        },
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Inspect(args) => inspect(args),
        Command::AccessReview(args) => access_review(args),
        Command::Audit { command } => match command {
            AuditCommand::Show => audit_show(),
            AuditCommand::Verify => audit_verify(),
        },
        Command::Ai { command } => match command {
            AiCommand::Evaluate(args) => ai_evaluate(args),
        },
        Command::Tamper(args) => tamper(args),
    }
}

fn identity_generate(args: IdentityGenerateArgs) -> Result<()> {
    let (dk, ek) = MlKem768::generate_keypair();
    let signing_key = DsaSigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let x_secret = X25519StaticSecret::from(random_array::<32>()?);
    let x_public = X25519PublicKey::from(&x_secret);

    let created_at = Utc::now();
    let provisional_public = PublicIdentity {
        name: args.name.clone(),
        fingerprint: String::new(),
        mlkem768_public_key: b64(ek.to_bytes().as_ref()),
        mldsa65_verify_key: b64(verifying_key.to_bytes().as_ref()),
        x25519_public_key: b64(x_public.as_bytes()),
        created_at,
    };
    let fingerprint = public_fingerprint(&provisional_public)?;
    let public = PublicIdentity {
        fingerprint,
        ..provisional_public
    };
    let private = PrivateIdentity {
        mlkem768_decapsulation_seed: b64(dk.to_bytes().as_ref()),
        mldsa65_signing_seed: b64(signing_key.to_bytes().as_ref()),
        x25519_private_key: b64(x_secret.to_bytes().as_ref()),
    };
    let identity = IdentityFile {
        version: VERSION,
        name: args.name,
        created_at,
        public,
        private: Some(private),
        sealed_private: None,
    };
    write_json(&args.out, &identity)?;
    println!("wrote identity {}", args.out.display());
    Ok(())
}

fn export_public(args: ExportPublicArgs) -> Result<()> {
    let identity: IdentityFile = read_json(&args.identity)?;
    write_json(&args.out, &identity.public)?;
    println!("wrote public identity {}", args.out.display());
    Ok(())
}

fn seal_identity(args: SealArgs) -> Result<()> {
    let mut identity: IdentityFile = read_json(&args.identity)?;
    let private = identity
        .private
        .take()
        .ok_or_else(|| anyhow!("identity is already sealed or has no private material"))?;
    let plaintext = serde_json::to_vec(&private)?;
    let sealed_private = seal_private_bytes(&plaintext, args.passphrase.as_bytes())?;
    identity.sealed_private = Some(sealed_private);
    write_json(&args.out, &identity)?;
    println!("wrote sealed identity {}", args.out.display());
    Ok(())
}

fn checkout_identity(args: CheckoutArgs) -> Result<()> {
    let identity: IdentityFile = read_json(&args.identity)?;
    if let Some(passphrase) = args.passphrase.as_ref() {
        let _ = load_private_identity(&identity, Some(passphrase.as_str()))?;
    } else if identity.sealed_private.is_some() {
        bail!("sealed identity checkout requires --passphrase or QSTG_PASSPHRASE");
    }
    let ttl = parse_ttl(&args.ttl)?;
    let lease = LeaseFile {
        version: VERSION,
        lease_id: Uuid::new_v4().to_string(),
        identity_fingerprint: identity.public.fingerprint.clone(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + ttl,
        reason: args.reason.clone(),
        allowed_operations: vec!["decrypt".into(), "sign".into()],
    };
    write_json(&args.out, &lease)?;
    append_audit(AuditDraft {
        event_type: "identity_checkout".into(),
        identity_fingerprint: Some(identity.public.fingerprint),
        envelope_fingerprint: None,
        sender_fingerprint: None,
        recipient_fingerprint: None,
        policy_result: "allowed".into(),
        reason: Some(args.reason),
        details: vec![
            format!("lease_id={}", lease.lease_id),
            format!("expires_at={}", lease.expires_at),
        ],
    })?;
    println!("wrote lease {}", args.out.display());
    Ok(())
}

fn rotate_identity(args: RotateArgs) -> Result<()> {
    let old: IdentityFile = read_json(&args.identity)?;
    if old.sealed_private.is_some() && args.passphrase.is_none() {
        bail!("sealed identity rotation requires --passphrase or QSTG_PASSPHRASE");
    }
    let tmp = IdentityGenerateArgs {
        name: old.name,
        out: args.out.clone(),
    };
    identity_generate(tmp)?;
    println!(
        "rotated identity; previous fingerprint {}",
        old.public.fingerprint
    );
    Ok(())
}

fn revoke_identity(args: RevokeArgs) -> Result<()> {
    let list = RevocationList {
        version: VERSION,
        revoked_keys: vec![RevokedKey {
            fingerprint: args.fingerprint,
            revoked_at: Utc::now(),
            reason: args.reason,
        }],
    };
    write_json(&args.out, &list)?;
    println!("wrote revocation list {}", args.out.display());
    Ok(())
}

fn encrypt(args: EncryptArgs) -> Result<()> {
    let sender: IdentityFile = read_json(&args.sender)?;
    let recipient: PublicIdentity = read_json(&args.recipient)?;
    let sender_private = load_private_identity(&sender, args.passphrase.as_deref())?;
    let envelope = build_envelope(
        &sender,
        &sender_private,
        &recipient,
        args.mode,
        &fs::read(&args.input).with_context(|| format!("reading {}", args.input.display()))?,
    )?;
    write_json(&args.out, &envelope)?;
    let envelope_bytes = serde_json::to_vec(&envelope)?;
    append_audit(AuditDraft {
        event_type: "encrypt".into(),
        identity_fingerprint: Some(sender.public.fingerprint.clone()),
        envelope_fingerprint: Some(fingerprint_bytes(&envelope_bytes)),
        sender_fingerprint: Some(sender.public.fingerprint),
        recipient_fingerprint: Some(recipient.fingerprint),
        policy_result: "allowed".into(),
        reason: None,
        details: vec![
            format!("mode={:?}", args.mode),
            format!("out={}", args.out.display()),
        ],
    })?;
    println!("wrote envelope {}", args.out.display());
    Ok(())
}

fn build_envelope(
    sender: &IdentityFile,
    sender_private: &PrivateIdentity,
    recipient: &PublicIdentity,
    mode: ExchangeMode,
    plaintext: &[u8],
) -> Result<Envelope> {
    let signing_key = dsa_signing_key(sender_private)?;
    let recipient_ek = kem_encapsulation_key(recipient)?;
    let (kem_ct, pq_shared) = recipient_ek.encapsulate();

    let mut ikm: Vec<u8> = pq_shared.as_slice().to_vec();
    let x25519_ephemeral_public = match mode {
        ExchangeMode::PqcOnly => None,
        ExchangeMode::HybridX25519Mlkem768 => {
            let eph_secret = X25519StaticSecret::from(random_array::<32>()?);
            let eph_public = X25519PublicKey::from(&eph_secret);
            let recipient_x = x25519_public_from_b64(&recipient.x25519_public_key)?;
            let classical = eph_secret.diffie_hellman(&recipient_x);
            ikm.extend_from_slice(classical.as_bytes());
            Some(b64(eph_public.as_bytes()))
        }
    };

    let kek = derive_key(b"KEM Courier KEK v1", &ikm, mode.suite().as_bytes())?;
    ikm.zeroize();
    let fek = random_array::<32>()?;
    let aad = aad_for_encryption(mode, &sender.public, recipient);
    let payload = encrypt_blob(&fek, plaintext, &aad)?;
    let wrapped_key = encrypt_blob(&kek, &fek, &aad)?;

    let unsigned = UnsignedEnvelope {
        version: VERSION,
        suite: mode.suite().into(),
        mode,
        created_at: Utc::now(),
        sender: EnvelopeParty {
            name: sender.public.name.clone(),
            fingerprint: sender.public.fingerprint.clone(),
        },
        recipient: EnvelopeParty {
            name: recipient.name.clone(),
            fingerprint: recipient.fingerprint.clone(),
        },
        key_exchange: KeyExchange {
            mlkem768_ciphertext: b64(kem_ct.as_ref()),
            x25519_ephemeral_public,
        },
        wrapped_key,
        payload,
    };
    let canonical = canonical_bytes(&unsigned)?;
    let sig = signing_key.sign(&canonical);
    Ok(Envelope {
        version: unsigned.version,
        suite: unsigned.suite,
        mode: unsigned.mode,
        created_at: unsigned.created_at,
        sender: unsigned.sender,
        recipient: unsigned.recipient,
        key_exchange: unsigned.key_exchange,
        wrapped_key: unsigned.wrapped_key,
        payload: unsigned.payload,
        signature: EnvelopeSignature {
            algorithm: "ML-DSA-65".into(),
            value: b64(sig.to_bytes().as_ref()),
        },
    })
}

fn decrypt(args: DecryptArgs) -> Result<()> {
    let recipient_identity: IdentityFile = read_json(&args.identity)?;
    let sender_public: PublicIdentity = read_json(&args.sender)?;
    let envelope: Envelope = read_json(&args.input)?;
    let policy = if let Some(path) = args.policy.as_ref() {
        Some(read_policy(path)?)
    } else {
        None
    };
    let lease = if let Some(path) = args.lease.as_ref() {
        Some(read_json::<LeaseFile>(path)?)
    } else {
        None
    };
    if recipient_identity.sealed_private.is_some() && args.lease.is_none() {
        bail!("sealed identity decrypt requires --lease");
    }

    let mut policy_details = Vec::new();
    enforce_policy(
        policy.as_ref(),
        &envelope,
        &sender_public,
        &recipient_identity.public,
        &mut policy_details,
    )?;
    enforce_lease(lease.as_ref(), &recipient_identity.public.fingerprint)?;
    verify_envelope_signature(&envelope, &sender_public)?;

    if envelope.recipient.fingerprint != recipient_identity.public.fingerprint {
        bail!("envelope recipient does not match identity");
    }

    let private = load_private_identity(&recipient_identity, args.passphrase.as_deref())?;
    let dk = kem_decapsulation_key(&private)?;
    let kem_ct_bytes = b64d(&envelope.key_exchange.mlkem768_ciphertext)?;
    let kem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes.as_slice())
        .map_err(|_| anyhow!("invalid ML-KEM ciphertext"))?;
    let pq_shared = dk.decapsulate(&kem_ct);
    let mut ikm: Vec<u8> = pq_shared.as_slice().to_vec();
    if envelope.mode == ExchangeMode::HybridX25519Mlkem768 {
        let eph_public = envelope
            .key_exchange
            .x25519_ephemeral_public
            .as_ref()
            .ok_or_else(|| anyhow!("hybrid envelope missing x25519 ephemeral public key"))?;
        let eph_public = x25519_public_from_b64(eph_public)?;
        let recipient_x = x25519_secret_from_b64(&private.x25519_private_key)?;
        let classical = recipient_x.diffie_hellman(&eph_public);
        ikm.extend_from_slice(classical.as_bytes());
    }
    let kek = derive_key(b"KEM Courier KEK v1", &ikm, envelope.suite.as_bytes())?;
    ikm.zeroize();
    let aad = aad_for_encryption(envelope.mode, &sender_public, &recipient_identity.public);
    let fek = decrypt_blob(&kek, &envelope.wrapped_key, &aad)?;
    let fek = slice_to_array_32(&fek)?;
    let plaintext = decrypt_blob(&fek, &envelope.payload, &aad)?;
    fs::write(&args.out, plaintext).with_context(|| format!("writing {}", args.out.display()))?;

    let envelope_bytes = serde_json::to_vec(&envelope)?;
    append_audit(AuditDraft {
        event_type: "decrypt".into(),
        identity_fingerprint: Some(recipient_identity.public.fingerprint.clone()),
        envelope_fingerprint: Some(fingerprint_bytes(&envelope_bytes)),
        sender_fingerprint: Some(sender_public.fingerprint),
        recipient_fingerprint: Some(recipient_identity.public.fingerprint),
        policy_result: "allowed".into(),
        reason: lease.map(|l| l.reason),
        details: policy_details,
    })?;
    println!("wrote plaintext {}", args.out.display());
    Ok(())
}

fn inspect(args: InspectArgs) -> Result<()> {
    let envelope: Envelope = read_json(&args.envelope)?;
    println!("KEM Courier Envelope");
    println!("Version: {}", envelope.version);
    println!("Suite: {}", envelope.suite);
    println!("Mode: {:?}", envelope.mode);
    println!("Payload cipher: {}", envelope.payload.cipher);
    println!("KEM: ML-KEM-768");
    println!("Signature: {}", envelope.signature.algorithm);
    println!(
        "Sender: {} ({})",
        envelope.sender.name, envelope.sender.fingerprint
    );
    println!(
        "Recipient: {} ({})",
        envelope.recipient.name, envelope.recipient.fingerprint
    );
    println!("Created: {}", envelope.created_at);
    println!("Signed metadata: yes");
    println!(
        "Hybrid x25519: {}",
        envelope.key_exchange.x25519_ephemeral_public.is_some()
    );
    Ok(())
}

fn access_review(args: AccessReviewArgs) -> Result<()> {
    if args.format != "markdown" {
        bail!("only markdown access-review format is currently supported");
    }
    let envelope: Envelope = read_json(&args.input)?;
    let mut details = Vec::new();
    let policy_result = if let Some(path) = args.policy.as_ref() {
        let policy = read_policy(path)?;
        match enforce_policy_for_review(Some(&policy), &envelope, &mut details) {
            Ok(()) => "Allowed",
            Err(err) => {
                details.push(format!("Policy failure: {err}"));
                "Denied"
            }
        }
    } else {
        details.push("No policy supplied; structural review only".into());
        "Not evaluated"
    };
    let report = format!(
        "# KEM Courier Access Review\n\nEnvelope: `{}`\nCreated: `{}`\n\n## Cryptographic Suite\n\n- Suite: `{}`\n- Payload: `{}`\n- KEM: `ML-KEM-768`\n- Mode: `{:?}`\n- Signature: `{}`\n\n## Sender\n\n- Name: `{}`\n- Fingerprint: `{}`\n\n## Recipient\n\n- Name: `{}`\n- Fingerprint: `{}`\n\n## Policy Result\n\n`{}`\n\n## Controls\n\n{}\n",
        fingerprint_bytes(&serde_json::to_vec(&envelope)?),
        envelope.created_at,
        envelope.suite,
        envelope.payload.cipher,
        envelope.mode,
        envelope.signature.algorithm,
        envelope.sender.name,
        envelope.sender.fingerprint,
        envelope.recipient.name,
        envelope.recipient.fingerprint,
        policy_result,
        details
            .iter()
            .map(|d| format!("- {d}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    if let Some(out) = args.out {
        fs::write(&out, report).with_context(|| format!("writing {}", out.display()))?;
        println!("wrote access review {}", out.display());
    } else {
        print!("{report}");
    }
    Ok(())
}

fn ai_evaluate(args: AiEvaluateArgs) -> Result<()> {
    let request: AiRequest = read_json(&args.request)?;
    let policy = read_ai_trust_policy(&args.policy)?;
    let request_id = Uuid::new_v4().to_string();
    let classification = classify_ai_request(&request);
    let mut reasons = Vec::new();
    let mut prompt_injection_detected = detect_prompt_injection(&request, &policy);
    if prompt_injection_detected {
        reasons.push("Prompt injection or exfiltration instruction detected".into());
    }

    if !policy.approved_models.is_empty() && !policy.approved_models.contains(&request.model) {
        reasons.push(format!(
            "Model `{}` is not approved by policy",
            request.model
        ));
    } else {
        reasons.push(format!("Model `{}` is approved", request.model));
    }

    let tool_decisions = evaluate_ai_tools(&request, &policy, classification);
    for tool in tool_decisions
        .iter()
        .filter(|tool| tool.decision != AiDecision::Allowed)
    {
        reasons.push(format!("Tool `{}`: {}", tool.name, tool.reason));
    }
    if request.requested_tools.is_empty() {
        reasons.push("No tools requested".into());
    }

    let requires_pqc = policy
        .require_pqc_envelope_for
        .iter()
        .any(|minimum| classification.at_or_above(*minimum));
    if requires_pqc {
        reasons.push(format!(
            "PQC evidence envelope required for {} data",
            classification_label(classification)
        ));
    }

    let mut decision = if prompt_injection_detected
        || reasons.iter().any(|reason| reason.contains("not approved"))
        || tool_decisions
            .iter()
            .any(|tool| tool.decision == AiDecision::Denied)
    {
        AiDecision::Denied
    } else if tool_decisions
        .iter()
        .any(|tool| tool.decision == AiDecision::ApprovalRequired)
    {
        AiDecision::ApprovalRequired
    } else {
        AiDecision::Allowed
    };

    let mut envelope_fingerprint = None;
    let mut crypto_suite = None;
    if requires_pqc && decision == AiDecision::Allowed {
        let (Some(sender_path), Some(recipient_path), Some(envelope_out)) = (
            args.sender.as_ref(),
            args.recipient.as_ref(),
            args.envelope_out.as_ref(),
        ) else {
            decision = AiDecision::Denied;
            reasons.push(
                "PQC envelope was required but --sender, --recipient, or --envelope-out was missing"
                    .into(),
            );
            prompt_injection_detected = prompt_injection_detected || false;
            let provenance = build_ai_provenance(
                request_id,
                &request,
                classification,
                decision,
                prompt_injection_detected,
                reasons,
                tool_decisions,
                policy.controls.clone(),
                crypto_suite,
                envelope_fingerprint,
                None,
            )?;
            write_ai_outputs(&args, &provenance)?;
            append_ai_audit(None, &provenance)?;
            println!(
                "AI trust decision: {}",
                ai_decision_label(provenance.decision)
            );
            return Ok(());
        };

        let sender: IdentityFile = read_json(sender_path)?;
        let sender_private = load_private_identity(&sender, args.passphrase.as_deref())?;
        let recipient: PublicIdentity = read_json(recipient_path)?;
        let artifact = AiArtifact {
            version: VERSION,
            request_id: request_id.clone(),
            actor: request.actor.clone(),
            model: request.model.clone(),
            data_classification: classification,
            response: format!(
                "Approved AI response placeholder for request {request_id}; sensitive content remains inside the PQC evidence envelope."
            ),
            created_at: Utc::now(),
        };
        let envelope = build_envelope(
            &sender,
            &sender_private,
            &recipient,
            args.mode,
            &serde_json::to_vec_pretty(&artifact)?,
        )?;
        write_json(envelope_out, &envelope)?;
        let envelope_bytes = serde_json::to_vec(&envelope)?;
        envelope_fingerprint = Some(fingerprint_bytes(&envelope_bytes));
        crypto_suite = Some(envelope.suite.clone());
        append_audit(AuditDraft {
            event_type: "ai_pqc_envelope".into(),
            identity_fingerprint: Some(sender.public.fingerprint.clone()),
            envelope_fingerprint: envelope_fingerprint.clone(),
            sender_fingerprint: Some(sender.public.fingerprint),
            recipient_fingerprint: Some(recipient.fingerprint),
            policy_result: ai_decision_label(decision).into(),
            reason: Some(format!("ai_request_id={request_id}")),
            details: vec![
                format!("classification={}", classification_label(classification)),
                format!("model={}", request.model),
                format!("out={}", envelope_out.display()),
            ],
        })?;
    }

    let signature = if let Some(sender_path) = args.sender.as_ref() {
        let sender: IdentityFile = read_json(sender_path)?;
        let private = load_private_identity(&sender, args.passphrase.as_deref())?;
        Some(sign_ai_provenance(
            &sender,
            &private,
            &request_id,
            &request,
            classification,
            decision,
            prompt_injection_detected,
            &reasons,
            &tool_decisions,
            &policy.controls,
            crypto_suite.clone(),
            envelope_fingerprint.clone(),
        )?)
    } else {
        None
    };

    let provenance = build_ai_provenance(
        request_id,
        &request,
        classification,
        decision,
        prompt_injection_detected,
        reasons,
        tool_decisions,
        policy.controls,
        crypto_suite,
        envelope_fingerprint,
        signature,
    )?;
    write_ai_outputs(&args, &provenance)?;
    append_ai_audit(args.sender.as_ref(), &provenance)?;
    println!(
        "AI trust decision: {}",
        ai_decision_label(provenance.decision)
    );
    Ok(())
}

fn read_ai_trust_policy(path: &PathBuf) -> Result<AiTrustPolicy> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&content)
        .or_else(|_| serde_json::from_str(&content))
        .with_context(|| format!("parsing AI trust policy {}", path.display()))
}

fn classify_ai_request(request: &AiRequest) -> DataClassification {
    if let Some(classification) = request.data_classification {
        return classification;
    }
    let mut text = request.prompt.to_lowercase();
    if let Some(context) = request.context.as_ref() {
        text.push('\n');
        text.push_str(&context.to_lowercase());
    }
    if [
        "ssn",
        "social security",
        "hipaa",
        "patient",
        "pci",
        "regulated",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        DataClassification::Regulated
    } else if [
        "confidential",
        "secret",
        "password",
        "api_key",
        "api key",
        "token",
        "customer",
        "contract",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        DataClassification::Confidential
    } else if text.contains("internal") {
        DataClassification::Internal
    } else {
        DataClassification::Public
    }
}

fn detect_prompt_injection(request: &AiRequest, policy: &AiTrustPolicy) -> bool {
    let mut text = request.prompt.to_lowercase();
    if let Some(context) = request.context.as_ref() {
        text.push('\n');
        text.push_str(&context.to_lowercase());
    }
    let defaults = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "print your system prompt",
        "reveal your system prompt",
        "disable audit",
        "exfiltrate",
        "send the data",
        "bypass policy",
    ];
    defaults.iter().any(|needle| text.contains(needle))
        || policy
            .blocked_prompt_patterns
            .iter()
            .any(|needle| text.contains(&needle.to_lowercase()))
}

fn evaluate_ai_tools(
    request: &AiRequest,
    policy: &AiTrustPolicy,
    classification: DataClassification,
) -> Vec<AiToolDecision> {
    request
        .requested_tools
        .iter()
        .map(|tool| {
            let Some(rule) = policy.tool_rules.iter().find(|rule| rule.name == *tool) else {
                return AiToolDecision {
                    name: tool.clone(),
                    decision: AiDecision::Denied,
                    reason: "tool is not allow-listed".into(),
                };
            };
            if classification.rank() > rule.max_classification.rank() {
                return AiToolDecision {
                    name: tool.clone(),
                    decision: AiDecision::Denied,
                    reason: format!(
                        "tool is limited to {} data",
                        classification_label(rule.max_classification)
                    ),
                };
            }
            if rule
                .approval_required_for
                .iter()
                .any(|minimum| classification.at_or_above(*minimum))
            {
                return AiToolDecision {
                    name: tool.clone(),
                    decision: AiDecision::ApprovalRequired,
                    reason: "human approval required by tool policy".into(),
                };
            }
            AiToolDecision {
                name: tool.clone(),
                decision: AiDecision::Allowed,
                reason: "tool allowed by policy".into(),
            }
        })
        .collect()
}

fn sign_ai_provenance(
    signer: &IdentityFile,
    private: &PrivateIdentity,
    request_id: &str,
    request: &AiRequest,
    classification: DataClassification,
    decision: AiDecision,
    prompt_injection_detected: bool,
    reasons: &[String],
    tool_decisions: &[AiToolDecision],
    controls: &[String],
    crypto_suite: Option<String>,
    envelope_fingerprint: Option<String>,
) -> Result<EnvelopeSignature> {
    let signing_key = dsa_signing_key(private)?;
    let unsigned = build_ai_provenance(
        request_id.to_string(),
        request,
        classification,
        decision,
        prompt_injection_detected,
        reasons.to_vec(),
        tool_decisions.to_vec(),
        controls.to_vec(),
        crypto_suite,
        envelope_fingerprint,
        None,
    )?;
    let mut bytes = canonical_bytes(&unsigned)?;
    bytes.extend_from_slice(signer.public.fingerprint.as_bytes());
    let sig = signing_key.sign(&bytes);
    Ok(EnvelopeSignature {
        algorithm: "ML-DSA-65".into(),
        value: b64(sig.to_bytes().as_ref()),
    })
}

fn build_ai_provenance(
    request_id: String,
    request: &AiRequest,
    classification: DataClassification,
    decision: AiDecision,
    prompt_injection_detected: bool,
    reasons: Vec<String>,
    tool_decisions: Vec<AiToolDecision>,
    controls: Vec<String>,
    crypto_suite: Option<String>,
    envelope_fingerprint: Option<String>,
    signature: Option<EnvelopeSignature>,
) -> Result<AiProvenance> {
    Ok(AiProvenance {
        version: VERSION,
        request_id,
        actor: request.actor.clone(),
        model: request.model.clone(),
        data_classification: classification,
        decision,
        prompt_injection_detected,
        reasons,
        requested_tools: request.requested_tools.clone(),
        tool_decisions,
        controls,
        crypto_suite,
        envelope_fingerprint,
        created_at: Utc::now(),
        signature,
    })
}

fn write_ai_outputs(args: &AiEvaluateArgs, provenance: &AiProvenance) -> Result<()> {
    write_json(&args.out, provenance)?;
    if let Some(out) = args.access_review_out.as_ref() {
        fs::write(out, ai_access_review_markdown(provenance))
            .with_context(|| format!("writing {}", out.display()))?;
        println!("wrote AI access review {}", out.display());
    }
    println!("wrote AI provenance {}", args.out.display());
    Ok(())
}

fn append_ai_audit(sender_path: Option<&PathBuf>, provenance: &AiProvenance) -> Result<()> {
    let identity_fingerprint = if let Some(path) = sender_path {
        let sender: IdentityFile = read_json(path)?;
        Some(sender.public.fingerprint)
    } else {
        None
    };
    append_audit(AuditDraft {
        event_type: "ai_trust_evaluate".into(),
        identity_fingerprint,
        envelope_fingerprint: provenance.envelope_fingerprint.clone(),
        sender_fingerprint: None,
        recipient_fingerprint: None,
        policy_result: ai_decision_label(provenance.decision).into(),
        reason: Some(format!("ai_request_id={}", provenance.request_id)),
        details: provenance.reasons.clone(),
    })
}

fn ai_access_review_markdown(provenance: &AiProvenance) -> String {
    format!(
        "# Quantum-Safe AI Trust Access Review\n\nRequest: `{}`\nActor: `{}`\nModel: `{}`\nCreated: `{}`\n\n## Decision\n\n`{}`\n\n## Data Classification\n\n`{}`\n\n## AI Controls\n\n- Prompt injection detected: `{}`\n- Requested tools: `{}`\n- Signed provenance: `{}`\n- PQC envelope suite: `{}`\n- PQC envelope fingerprint: `{}`\n\n## Reasons\n\n{}\n\n## Tool Decisions\n\n{}\n\n## Control Mapping\n\n{}\n",
        provenance.request_id,
        provenance.actor,
        provenance.model,
        provenance.created_at,
        ai_decision_label(provenance.decision),
        classification_label(provenance.data_classification),
        provenance.prompt_injection_detected,
        if provenance.requested_tools.is_empty() {
            "none".into()
        } else {
            provenance.requested_tools.join(", ")
        },
        provenance.signature.is_some(),
        provenance
            .crypto_suite
            .as_deref()
            .unwrap_or("not generated"),
        provenance
            .envelope_fingerprint
            .as_deref()
            .unwrap_or("not generated"),
        provenance
            .reasons
            .iter()
            .map(|reason| format!("- {reason}"))
            .collect::<Vec<_>>()
            .join("\n"),
        provenance
            .tool_decisions
            .iter()
            .map(|tool| format!(
                "- `{}`: `{}` — {}",
                tool.name,
                ai_decision_label(tool.decision),
                tool.reason
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        provenance
            .controls
            .iter()
            .map(|control| format!("- {control}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn classification_label(classification: DataClassification) -> &'static str {
    match classification {
        DataClassification::Public => "public",
        DataClassification::Internal => "internal",
        DataClassification::Confidential => "confidential",
        DataClassification::Regulated => "regulated",
    }
}

fn ai_decision_label(decision: AiDecision) -> &'static str {
    match decision {
        AiDecision::Allowed => "allowed",
        AiDecision::ApprovalRequired => "approval-required",
        AiDecision::Denied => "denied",
    }
}

fn audit_show() -> Result<()> {
    let path = PathBuf::from(AUDIT_LOG);
    if !path.exists() {
        println!("no audit log found");
        return Ok(());
    }
    print!("{}", fs::read_to_string(path)?);
    Ok(())
}

fn audit_verify() -> Result<()> {
    let path = PathBuf::from(AUDIT_LOG);
    if !path.exists() {
        println!("no audit log found");
        return Ok(());
    }
    let content = fs::read_to_string(path)?;
    let mut previous = "GENESIS".to_string();
    for (idx, line) in content.lines().enumerate() {
        let event: AuditEvent = serde_json::from_str(line)
            .with_context(|| format!("invalid audit JSON at line {}", idx + 1))?;
        if event.previous_hash != previous {
            bail!("audit chain mismatch at line {}", idx + 1);
        }
        let expected = audit_event_hash(&event)?;
        if event.event_hash != expected {
            bail!("audit event hash mismatch at line {}", idx + 1);
        }
        previous = event.event_hash;
    }
    println!("audit log verified");
    Ok(())
}

fn tamper(args: TamperArgs) -> Result<()> {
    let mut envelope: Envelope = read_json(&args.envelope)?;
    match args.field.as_str() {
        "suite" => envelope.suite.push_str("-tampered"),
        "sender" => envelope.sender.fingerprint.push_str("-tampered"),
        "ciphertext" => envelope.payload.ciphertext.push('A'),
        other => bail!("unsupported tamper field {other}; use suite, sender, or ciphertext"),
    }
    write_json(&args.out, &envelope)?;
    println!("wrote tampered envelope {}", args.out.display());
    Ok(())
}

fn load_private_identity(
    identity: &IdentityFile,
    passphrase: Option<&str>,
) -> Result<PrivateIdentity> {
    if let Some(private) = identity.private.clone() {
        return Ok(private);
    }
    let sealed = identity
        .sealed_private
        .as_ref()
        .ok_or_else(|| anyhow!("identity has no private material"))?;
    let passphrase = passphrase
        .ok_or_else(|| anyhow!("sealed identity requires --passphrase or QSTG_PASSPHRASE"))?;
    let plaintext = open_private_bytes(sealed, passphrase.as_bytes())?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn seal_private_bytes(plaintext: &[u8], passphrase: &[u8]) -> Result<SealedPrivateIdentity> {
    let salt = random_array::<16>()?;
    let nonce = random_array::<12>()?;
    let key = derive_passphrase_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_ref = Nonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let ciphertext = cipher
        .encrypt(&nonce_ref, plaintext)
        .map_err(|_| anyhow!("failed to seal private identity"))?;
    Ok(SealedPrivateIdentity {
        kdf: "argon2id-default".into(),
        salt: b64(&salt),
        nonce: b64(&nonce),
        ciphertext: b64(&ciphertext),
    })
}

fn open_private_bytes(sealed: &SealedPrivateIdentity, passphrase: &[u8]) -> Result<Vec<u8>> {
    let salt = b64d(&sealed.salt)?;
    let nonce = b64d(&sealed.nonce)?;
    let ciphertext = b64d(&sealed.ciphertext)?;
    let key = derive_passphrase_key(passphrase, &salt)?;
    let nonce_ref = Nonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    cipher
        .decrypt(&nonce_ref, ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to open sealed private identity"))
}

fn derive_passphrase_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

fn kem_encapsulation_key(public: &PublicIdentity) -> Result<KemEncap> {
    let bytes = b64d(&public.mlkem768_public_key)?;
    let key = ml_kem::Key::<KemEncap>::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("invalid ML-KEM public key"))?;
    <KemEncap as TryKeyInit>::new(&key).map_err(|_| anyhow!("invalid ML-KEM public key"))
}

fn kem_decapsulation_key(private: &PrivateIdentity) -> Result<KemDecap> {
    let bytes = b64d(&private.mlkem768_decapsulation_seed)?;
    let seed =
        ml_kem::Seed::try_from(bytes.as_slice()).map_err(|_| anyhow!("invalid ML-KEM seed"))?;
    Ok(<KemDecap as KemKeyInit>::new(&seed))
}

fn dsa_signing_key(private: &PrivateIdentity) -> Result<DsaSigningKey> {
    let bytes = b64d(&private.mldsa65_signing_seed)?;
    let seed = ml_dsa::Seed::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA signing seed"))?;
    Ok(<DsaSigningKey as DsaKeyInit>::new(&seed))
}

fn dsa_verifying_key(public: &PublicIdentity) -> Result<DsaVerifyingKey> {
    let bytes = b64d(&public.mldsa65_verify_key)?;
    let key = ml_dsa::common::Key::<DsaVerifyingKey>::try_from(bytes.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA verify key"))?;
    Ok(<DsaVerifyingKey as DsaKeyInit>::new(&key))
}

fn verify_envelope_signature(envelope: &Envelope, sender_public: &PublicIdentity) -> Result<()> {
    if envelope.sender.fingerprint != sender_public.fingerprint {
        bail!("sender public identity does not match envelope sender fingerprint");
    }
    let verifying_key = dsa_verifying_key(sender_public)?;
    let unsigned = envelope.unsigned();
    let canonical = canonical_bytes(&unsigned)?;
    let sig_bytes = b64d(&envelope.signature.value)?;
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| anyhow!("invalid ML-DSA signature encoding"))?;
    verifying_key
        .verify(&canonical, &sig)
        .map_err(|_| anyhow!("envelope signature verification failed"))
}

fn derive_key(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = [0u8; 32];
    hk.expand(info, &mut key)
        .map_err(|_| anyhow!("HKDF expansion failed"))?;
    Ok(key)
}

fn encrypt_blob(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedBlob> {
    let nonce = random_array::<12>()?;
    let nonce_ref = Nonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let ciphertext = cipher
        .encrypt(
            &nonce_ref,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    Ok(EncryptedBlob {
        cipher: "AES-256-GCM".into(),
        nonce: b64(&nonce),
        ciphertext: b64(&ciphertext),
    })
}

fn decrypt_blob(key: &[u8; 32], blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    if blob.cipher != "AES-256-GCM" {
        bail!("unsupported cipher {}", blob.cipher);
    }
    let nonce = b64d(&blob.nonce)?;
    let ciphertext = b64d(&blob.ciphertext)?;
    let nonce_ref = Nonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(key)?;
    cipher
        .decrypt(
            &nonce_ref,
            Payload {
                msg: ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| anyhow!("AES-GCM authentication failed"))
}

fn aad_for_encryption(
    mode: ExchangeMode,
    sender: &PublicIdentity,
    recipient: &PublicIdentity,
) -> Vec<u8> {
    format!(
        "kem-courier-envelope:v1:{}:{}:{}",
        mode.suite(),
        sender.fingerprint,
        recipient.fingerprint
    )
    .into_bytes()
}

fn enforce_policy(
    policy: Option<&Policy>,
    envelope: &Envelope,
    sender: &PublicIdentity,
    recipient: &PublicIdentity,
    details: &mut Vec<String>,
) -> Result<()> {
    enforce_policy_for_review(policy, envelope, details)?;
    if envelope.sender.fingerprint != sender.fingerprint {
        bail!("sender fingerprint mismatch");
    }
    if envelope.recipient.fingerprint != recipient.fingerprint {
        bail!("recipient fingerprint mismatch");
    }
    if let Some(policy) = policy {
        if let Some(lifecycle) = policy.key_lifecycle.as_ref() {
            if let Some(max_days) = lifecycle.max_identity_age_days {
                if Utc::now() - recipient.created_at > Duration::days(max_days) {
                    bail!("recipient identity key exceeds max age policy");
                }
            }
        }
        if let Some(revocation_path) = policy.revocation_list.as_ref() {
            let revocations: RevocationList = read_json(revocation_path)?;
            let revoked: BTreeSet<_> = revocations
                .revoked_keys
                .iter()
                .map(|r| r.fingerprint.as_str())
                .collect();
            if revoked.contains(envelope.sender.fingerprint.as_str())
                || revoked.contains(envelope.recipient.fingerprint.as_str())
            {
                bail!("envelope uses revoked key");
            }
            details.push("Revocation list checked".into());
        }
    }
    Ok(())
}

fn enforce_policy_for_review(
    policy: Option<&Policy>,
    envelope: &Envelope,
    details: &mut Vec<String>,
) -> Result<()> {
    let Some(policy) = policy else {
        details.push("No policy supplied".into());
        return Ok(());
    };
    if policy.require_sender_signature.unwrap_or(true) && envelope.signature.value.is_empty() {
        bail!("sender signature required");
    }
    details.push("Sender signature required".into());
    if policy.require_signed_metadata.unwrap_or(true) && envelope.signature.algorithm != "ML-DSA-65"
    {
        bail!("signed metadata requires ML-DSA-65 signature");
    }
    details.push("Signed metadata required".into());
    if policy.allow_unsigned_envelopes == Some(true) {
        bail!("policy cannot allow unsigned envelopes in this prototype");
    }
    if let Some(min_mode) = policy.minimum_encryption_mode {
        if min_mode == ExchangeMode::HybridX25519Mlkem768
            && envelope.mode != ExchangeMode::HybridX25519Mlkem768
        {
            bail!("policy requires hybrid-x25519-mlkem768 mode");
        }
        details.push(format!("Minimum mode satisfied: {:?}", min_mode));
    }
    if let Some(max_days) = policy.max_envelope_age_days {
        if Utc::now() - envelope.created_at > Duration::days(max_days) {
            bail!("envelope exceeds max age policy");
        }
        details.push(format!("Envelope age <= {max_days} days"));
    }
    if let Some(senders) = policy.allowed_senders.as_ref() {
        require_fingerprint("sender", &envelope.sender.fingerprint, senders)?;
        details.push("Sender is approved".into());
    }
    if let Some(recipients) = policy.allowed_recipients.as_ref() {
        require_fingerprint("recipient", &envelope.recipient.fingerprint, recipients)?;
        details.push("Recipient is approved".into());
    }
    Ok(())
}

fn require_fingerprint(
    kind: &str,
    fingerprint: &str,
    principals: &[PolicyPrincipal],
) -> Result<()> {
    if principals.iter().any(|p| p.fingerprint == fingerprint) {
        Ok(())
    } else {
        bail!("{kind} fingerprint is not approved by policy")
    }
}

fn enforce_lease(lease: Option<&LeaseFile>, identity_fingerprint: &str) -> Result<()> {
    if let Some(lease) = lease {
        if lease.identity_fingerprint != identity_fingerprint {
            bail!("lease does not match recipient identity");
        }
        if lease.expires_at < Utc::now() {
            bail!("lease expired");
        }
        if !lease.allowed_operations.iter().any(|op| op == "decrypt") {
            bail!("lease does not allow decrypt");
        }
    }
    Ok(())
}

fn read_policy(path: &PathBuf) -> Result<Policy> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&content)
        .or_else(|_| serde_json::from_str(&content))
        .with_context(|| format!("parsing policy {}", path.display()))
}

fn public_fingerprint(public: &PublicIdentity) -> Result<String> {
    let mut clone = public.clone();
    clone.fingerprint.clear();
    Ok(fingerprint_bytes(&canonical_bytes(&clone)?))
}

fn fingerprint_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &PathBuf) -> Result<T> {
    let content = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&content).with_context(|| format!("parsing JSON {}", path.display()))
}

fn write_json<T: Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    let content = serde_json::to_vec_pretty(value)?;
    fs::write(path, content).with_context(|| format!("writing {}", path.display()))
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("random generation failed: {e}"))?;
    Ok(bytes)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn b64d(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| anyhow!("invalid base64url: {e}"))
}

fn slice_to_array_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte key"))
}

fn x25519_public_from_b64(s: &str) -> Result<X25519PublicKey> {
    let bytes = b64d(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid x25519 public key"))?;
    Ok(X25519PublicKey::from(arr))
}

fn x25519_secret_from_b64(s: &str) -> Result<X25519StaticSecret> {
    let bytes = b64d(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid x25519 private key"))?;
    Ok(X25519StaticSecret::from(arr))
}

fn parse_ttl(ttl: &str) -> Result<Duration> {
    let (number, suffix) = ttl.split_at(ttl.len().saturating_sub(1));
    let value: i64 = number
        .parse()
        .with_context(|| format!("invalid ttl {ttl}"))?;
    match suffix {
        "m" => Ok(Duration::minutes(value)),
        "h" => Ok(Duration::hours(value)),
        "d" => Ok(Duration::days(value)),
        _ => bail!("ttl must end with m, h, or d"),
    }
}

impl Envelope {
    fn unsigned(&self) -> UnsignedEnvelope {
        UnsignedEnvelope {
            version: self.version,
            suite: self.suite.clone(),
            mode: self.mode,
            created_at: self.created_at,
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            key_exchange: self.key_exchange.clone(),
            wrapped_key: self.wrapped_key.clone(),
            payload: self.payload.clone(),
        }
    }
}

struct AuditDraft {
    event_type: String,
    identity_fingerprint: Option<String>,
    envelope_fingerprint: Option<String>,
    sender_fingerprint: Option<String>,
    recipient_fingerprint: Option<String>,
    policy_result: String,
    reason: Option<String>,
    details: Vec<String>,
}

fn append_audit(draft: AuditDraft) -> Result<()> {
    let previous_hash = last_audit_hash()?.unwrap_or_else(|| "GENESIS".into());
    let mut event = AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        event_type: draft.event_type,
        timestamp: Utc::now(),
        identity_fingerprint: draft.identity_fingerprint,
        envelope_fingerprint: draft.envelope_fingerprint,
        sender_fingerprint: draft.sender_fingerprint,
        recipient_fingerprint: draft.recipient_fingerprint,
        policy_result: draft.policy_result,
        reason: draft.reason,
        details: draft.details,
        previous_hash,
        event_hash: String::new(),
    };
    event.event_hash = audit_event_hash(&event)?;
    let mut line = serde_json::to_string(&event)?;
    line.push('\n');
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

fn last_audit_hash() -> Result<Option<String>> {
    let path = PathBuf::from(AUDIT_LOG);
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path)?;
    let Some(line) = content.lines().last() else {
        return Ok(None);
    };
    let event: AuditEvent = serde_json::from_str(line)?;
    Ok(Some(event.event_hash))
}

fn audit_event_hash(event: &AuditEvent) -> Result<String> {
    let mut clone = event.clone();
    clone.event_hash.clear();
    Ok(fingerprint_bytes(&serde_json::to_vec(&clone)?))
}
