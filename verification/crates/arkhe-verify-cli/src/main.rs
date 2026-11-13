use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "arkhe-verify")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify an experimental release; local approval never starts execution.
    VerifyRelease {
        artifact: String,
        attestation: String,
        trust: String,
        #[arg(long)]
        approval: Option<String>,
        #[arg(long)]
        now: u64,
        #[arg(long, default_value_t = 0)]
        high_water: u64,
    },
    ReleasePolicyDigest {
        trust: String,
    },
    /// Verify a custody chain for one asset offline: signatures, links,
    /// custody hand-over and state continuity. Does not verify the asset itself.
    VerifyCustody {
        asset_id: String,
        chain: String,
    },
    /// Check an AbsenceRecord digest against its expectation and window offline.
    /// This does not re-derive that the window was silent.
    VerifyAbsence {
        expectation: String,
        window: u64,
        record_hash: String,
        #[arg(long)]
        now: u64,
    },
    /// Inspect the restricted binary GGUF profile; '-' reads a bounded stdin snapshot.
    /// This command computes digests and does not verify authenticity.
    InspectGguf {
        gguf_file: String,
    },
    Blake3 {
        hex: String,
    },
    VerifyGguf {
        json_file: String,
    },
    /// Verify the restricted Stage 10 binary GGUF laboratory profile offline.
    VerifyGgufArtifact {
        gguf_file: String,
        bundle_file: String,
        trust_file: String,
    },
    VerifyC2pa {
        json_file: String,
    },
    /// Manage the offline entitlement for paid kits.
    License {
        #[command(subcommand)]
        command: LicenseCommand,
    },
}

#[derive(Subcommand)]
enum LicenseCommand {
    /// Exchange a checkout license key for a signed offline entitlement (one network call).
    Activate {
        key: String,
        /// Issuer base URL; defaults to ARKHE_LICENSE_ISSUER.
        #[arg(long)]
        issuer: Option<String>,
        /// Instance label recorded by the checkout provider; defaults to the host name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Install an entitlement token file issued out of band (air-gapped hosts).
    Install { token_file: String },
    /// Verify the installed entitlement offline and print it.
    Status,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ReleasePolicyDigest { trust } => {
            let trust = serde_json::from_slice(&bounded_release_read(&trust, 32768)?)?;
            println!(
                "{}",
                arkhe_verify_core::release::policy_digest(&trust).map_err(anyhow::Error::msg)?
            );
        }
        Command::VerifyAbsence {
            expectation,
            window,
            record_hash,
            now,
        } => {
            let spec: arkhe_verify_core::absence::ExpectationSpec =
                serde_json::from_slice(&bounded_release_read(&expectation, 32768)?)?;
            let verdict = arkhe_verify_core::absence::verify(&spec, window, &record_hash, now)
                .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&verdict)?);
        }
        Command::VerifyCustody { asset_id, chain } => {
            use arkhe_verify_core::custody::{verify_chain, SignedTransfer, MAX_CHAIN};
            let chain: Vec<SignedTransfer> =
                serde_json::from_slice(&bounded_release_read(&chain, MAX_CHAIN * 9000)?)?;
            let verdict = verify_chain(&asset_id, &chain).map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&verdict)?);
        }
        Command::VerifyRelease {
            artifact,
            attestation,
            trust,
            approval,
            now,
            high_water,
        } => {
            use arkhe_verify_core::release::{verify, Envelope, Trust, MAX_ARTIFACT};
            let bytes = bounded_release_read(&artifact, MAX_ARTIFACT)?;
            let attestation: Envelope =
                serde_json::from_slice(&bounded_release_read(&attestation, 32768)?)?;
            let trust: Trust = serde_json::from_slice(&bounded_release_read(&trust, 32768)?)?;
            let approval: Option<Envelope> = approval
                .map(|p| -> anyhow::Result<_> {
                    Ok(serde_json::from_slice(&bounded_release_read(&p, 32768)?)?)
                })
                .transpose()?;
            let result = verify(
                &bytes,
                &attestation,
                &trust,
                approval.as_ref(),
                now,
                high_water,
            )
            .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::InspectGguf { gguf_file } => {
            use arkhe_verify_core::gguf::supply_chain::{statement, MAX_ARTIFACT_BYTES};
            use std::io::Read;
            let reader: Box<dyn Read> = if gguf_file == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(
                    std::fs::File::open(&gguf_file).with_context(|| format!("open {gguf_file}"))?,
                )
            };
            let mut bytes = Vec::new();
            reader
                .take(MAX_ARTIFACT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= MAX_ARTIFACT_BYTES, "GGUF exceeds size limit");
            println!(
                "{}",
                serde_json::to_string_pretty(&statement(&bytes, String::new())?)?
            );
        }
        Command::Blake3 { hex } => {
            let bytes = hex::decode(hex)?;
            println!(
                "{}",
                hex::encode(arkhe_verify_core::hash::blake3_256(&bytes))
            );
        }
        Command::VerifyGguf { json_file } => {
            let raw =
                std::fs::read_to_string(&json_file).with_context(|| format!("read {json_file}"))?;
            let v: serde_json::Value = serde_json::from_str(&raw)?;
            let cbor = arkhe_verify_core::gguf::canonical::canonicalize_metadata(&v)?;
            println!("{}", hex::encode(cbor));
        }
        Command::VerifyGgufArtifact {
            gguf_file,
            bundle_file,
            trust_file,
        } => {
            use arkhe_verify_core::gguf::supply_chain::{
                verify, Bundle, Trust, MAX_ARTIFACT_BYTES,
            };
            use std::io::Read;
            fn bounded_read(path: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
                let mut bytes = Vec::new();
                std::fs::File::open(path)
                    .with_context(|| format!("open {path}"))?
                    .take(limit as u64 + 1)
                    .read_to_end(&mut bytes)?;
                anyhow::ensure!(bytes.len() <= limit, "input exceeds size limit: {path}");
                Ok(bytes)
            }
            let bytes = bounded_read(&gguf_file, MAX_ARTIFACT_BYTES)?;
            let bundle: Bundle = serde_json::from_slice(&bounded_read(&bundle_file, 1024 * 1024)?)?;
            let trust: Trust = serde_json::from_slice(&bounded_read(&trust_file, 16384)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verify(&bytes, &bundle, &trust)?)?
            );
        }
        Command::VerifyC2pa { json_file } => {
            let raw =
                std::fs::read_to_string(&json_file).with_context(|| format!("read {json_file}"))?;
            let v: serde_json::Value = serde_json::from_str(&raw)?;
            let cbor = arkhe_verify_core::c2pa::claim::canonicalize_claim_v2(&v)?;
            println!("{}", hex::encode(cbor));
        }
        Command::License { command } => license(command)?,
    }
    Ok(())
}

/// Issuer keys are fixed at build time (comma-separated hex) so a user cannot
/// trust a self-made key at run time.
fn trusted_issuers() -> anyhow::Result<Vec<[u8; 32]>> {
    option_env!("ARKHE_LICENSE_PUBKEYS")
        .unwrap_or("")
        .split(',')
        .filter(|k| !k.trim().is_empty())
        .map(|k| {
            hex::decode(k.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("issuer key must be 32 bytes"))
        })
        .collect()
}

fn license_path() -> anyhow::Result<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("ARKHE_LICENSE_FILE") {
        return Ok(p.into());
    }
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join(".config")))
        .context("no APPDATA, XDG_CONFIG_HOME or HOME to store the entitlement")?;
    Ok(base.join("arkhe").join("license.json"))
}

fn check_entitlement(raw: &[u8]) -> anyhow::Result<arkhe_verify_core::entitlement::Entitlement> {
    let trusted = trusted_issuers()?;
    anyhow::ensure!(
        !trusted.is_empty(),
        "this build has no trusted license issuer (ARKHE_LICENSE_PUBKEYS unset at build time)"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let allow_test = cfg!(debug_assertions) || option_env!("ARKHE_LICENSE_ALLOW_TEST").is_some();
    arkhe_verify_core::entitlement::verify(raw, &trusted, now, allow_test)
        .map_err(anyhow::Error::msg)
}

fn store_entitlement(raw: &[u8]) -> anyhow::Result<()> {
    let e = check_entitlement(raw)?;
    let path = license_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, raw).with_context(|| format!("write {}", path.display()))?;
    eprintln!(
        "installed {} {} entitlement at {}",
        e.product,
        e.tier,
        path.display()
    );
    println!("{}", serde_json::to_string_pretty(&e)?);
    Ok(())
}

fn license(command: LicenseCommand) -> anyhow::Result<()> {
    use arkhe_verify_core::entitlement::MAX_TOKEN;
    use std::io::Read;
    match command {
        LicenseCommand::Activate { key, issuer, name } => {
            let issuer = issuer
                .or_else(|| std::env::var("ARKHE_LICENSE_ISSUER").ok())
                .context("pass --issuer or set ARKHE_LICENSE_ISSUER")?;
            let name = name
                .or_else(|| std::env::var("COMPUTERNAME").ok())
                .or_else(|| std::env::var("HOSTNAME").ok())
                .unwrap_or_else(|| "arkhe-verify".into());
            let body = serde_json::json!({ "key": key.trim(), "instance_name": name });
            let url = format!("{}/v1/activate", issuer.trim_end_matches('/'));
            let response = match ureq::post(&url)
                .timeout(std::time::Duration::from_secs(30))
                .set("content-type", "application/json")
                .send_string(&body.to_string())
            {
                Ok(r) => r,
                Err(ureq::Error::Status(code, r)) => anyhow::bail!(
                    "activation refused ({code}): {}",
                    r.into_string().unwrap_or_default()
                ),
                Err(e) => return Err(anyhow::Error::new(e).context("contact license issuer")),
            };
            let mut raw = Vec::new();
            response
                .into_reader()
                .take(MAX_TOKEN as u64 + 1)
                .read_to_end(&mut raw)?;
            store_entitlement(&raw)?;
        }
        LicenseCommand::Install { token_file } => {
            store_entitlement(&bounded_release_read(&token_file, MAX_TOKEN)?)?;
        }
        LicenseCommand::Status => {
            let path = license_path()?;
            let raw = std::fs::read(&path).with_context(|| {
                format!(
                    "no entitlement at {}; run `license activate`",
                    path.display()
                )
            })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&check_entitlement(&raw)?)?
            );
        }
    }
    Ok(())
}

fn bounded_release_read(path: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("open {path}"))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "release input exceeds limit");
    Ok(bytes)
}
