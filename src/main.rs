//! `frostsig` command-line interface.
//!
//! Educational software: not audited, not for protecting real assets.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use frostsig::bench::{self, BenchConfig};
use frostsig::sim::{self, Fault, KeygenMode, Preloaded, SimConfig, SimReport};
use frostsig::wire::{Decode, Encode};
use frostsig::{
    Ciphersuite, Ed25519Sha512, Error, KeyPackage, PublicKeyPackage, Ristretto255Sha512, Signature,
    VerifyingKey,
};

const KEY_FORMAT: &str = "frostsig-key-v1";
const GROUP_FORMAT: &str = "frostsig-group-v1";
const DISCLAIMER: &str = "frostsig is educational software: unaudited, not for real assets.";

#[derive(Parser, Debug)]
#[command(
    name = "frostsig",
    version,
    about = "FROST threshold Schnorr signatures (RFC 9591) - educational implementation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Simulate key generation and signing with every participant on its own thread.
    Simulate(SimulateArgs),
    /// Generate a key set (dealer or DKG, over simulated channels) and write it to a directory.
    Keygen(KeygenArgs),
    /// Sign with a key set written by `keygen`, over simulated channels.
    Sign(SignArgs),
    /// Verify a signature (Ed25519 signatures are also checked with ed25519-dalek).
    Verify(VerifyArgs),
    /// Recompute the RFC 9591 Appendix E test vectors.
    Vectors,
    /// Time every protocol phase for growing group sizes.
    Bench(BenchArgs),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Suite {
    Ed25519,
    Ristretto255,
}

#[derive(Args, Debug)]
struct GroupArgs {
    /// Ciphersuite.
    #[arg(long, value_enum, default_value = "ed25519")]
    suite: Suite,
    /// Threshold t (minimum signers).
    #[arg(short = 't', long, default_value_t = 2)]
    threshold: u16,
    /// Number of participants n.
    #[arg(short = 'n', long, default_value_t = 3)]
    participants: u16,
    /// Key generation: `dealer` or `dkg`.
    #[arg(long, default_value = "dealer")]
    keygen: String,
    /// Seed for a reproducible run (demo only; omit for OS randomness).
    #[arg(long)]
    seed: Option<u64>,
    /// Per-reply timeout in milliseconds.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,
}

#[derive(Args, Debug)]
struct SimulateArgs {
    #[command(flatten)]
    group: GroupArgs,
    /// Preferred signer ids, comma separated (default: 1..=t).
    #[arg(long, value_delimiter = ',')]
    signers: Option<Vec<u16>>,
    /// Message to sign; repeat for several sessions.
    #[arg(short, long = "message")]
    messages: Vec<String>,
    /// Inject a fault, `ID=KIND` with KIND one of bad-share, bad-proof, silent, bad-dkg-share:VICTIM.
    #[arg(long = "fault")]
    faults: Vec<String>,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct KeygenArgs {
    #[command(flatten)]
    group: GroupArgs,
    /// Output directory (created if missing).
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct SignArgs {
    /// Directory written by `keygen`.
    #[arg(long)]
    keys: PathBuf,
    /// Message to sign.
    #[arg(short, long)]
    message: String,
    /// Signer ids, comma separated (default: the lowest t available).
    #[arg(long, value_delimiter = ',')]
    signers: Option<Vec<u16>>,
    /// Seed for a reproducible run (demo only).
    #[arg(long)]
    seed: Option<u64>,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Ciphersuite.
    #[arg(long, value_enum, default_value = "ed25519")]
    suite: Suite,
    /// Group public key, hex.
    #[arg(long)]
    public_key: String,
    /// Message (UTF-8).
    #[arg(short, long)]
    message: String,
    /// Signature, hex (R || z).
    #[arg(long)]
    signature: String,
}

#[derive(Args, Debug)]
struct BenchArgs {
    /// Ciphersuite.
    #[arg(long, value_enum, default_value = "ed25519")]
    suite: Suite,
    /// Group sizes n, comma separated.
    #[arg(long, value_delimiter = ',', default_value = "4,8,16,32,64")]
    sizes: Vec<u16>,
    /// Samples per measurement.
    #[arg(long, default_value_t = 15)]
    iterations: u32,
    /// Largest n for which the DKG is timed.
    #[arg(long, default_value_t = 32)]
    dkg_max_n: u16,
}

#[derive(Serialize, Deserialize, Debug)]
struct KeyFile {
    format: String,
    note: String,
    suite: Suite,
    identifier: u16,
    min_signers: u16,
    max_signers: u16,
    key_package: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GroupFile {
    format: String,
    suite: Suite,
    min_signers: u16,
    max_signers: u16,
    verifying_key: String,
    public_key_package: String,
}

type CliResult<T> = Result<T, String>;

/// Call a generic command for the selected suite.
macro_rules! dispatch {
    ($suite:expr, $f:ident, $($arg:expr),*) => {
        match $suite {
            Suite::Ed25519 => $f::<Ed25519Sha512>($($arg),*),
            Suite::Ristretto255 => $f::<Ristretto255Sha512>($($arg),*),
        }
    };
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Simulate(a) => dispatch!(a.group.suite, simulate, &a),
        Command::Keygen(a) => dispatch!(a.group.suite, keygen, &a),
        Command::Sign(a) => sign_cmd(&a),
        Command::Verify(a) => dispatch!(a.suite, verify, &a),
        Command::Vectors => vectors(),
        Command::Bench(a) => dispatch!(a.suite, bench_cmd, &a),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn suite_of<C: Ciphersuite>() -> Suite {
    if C::WIRE_ID == Ed25519Sha512::WIRE_ID {
        Suite::Ed25519
    } else {
        Suite::Ristretto255
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn base_config(g: &GroupArgs) -> CliResult<SimConfig> {
    let mut c = SimConfig::new(g.threshold, g.participants);
    c.keygen = g.keygen.parse::<KeygenMode>().map_err(err)?;
    c.seed = g.seed;
    c.timeout = Duration::from_millis(g.timeout_ms);
    Ok(c)
}

fn parse_faults(specs: &[String]) -> CliResult<BTreeMap<u16, Fault>> {
    specs
        .iter()
        .map(|s| {
            let (id, kind) =
                s.split_once('=').ok_or_else(|| format!("fault `{s}` must look like ID=KIND"))?;
            let id: u16 = id.parse().map_err(|_| format!("bad participant id in `{s}`"))?;
            Ok((id, kind.parse::<Fault>().map_err(err)?))
        })
        .collect()
}

fn print_report(report: &SimReport, json: bool) -> CliResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report).map_err(err)?);
    } else {
        println!("{DISCLAIMER}");
        print!("{}", report.render());
    }
    Ok(())
}

fn simulate<C: Ciphersuite>(a: &SimulateArgs) -> CliResult<ExitCode> {
    let mut config = base_config(&a.group)?;
    config.signers = a.signers.clone();
    config.faults = parse_faults(&a.faults)?;
    config.messages = if a.messages.is_empty() {
        vec![b"hello from frostsig".to_vec()]
    } else {
        a.messages.iter().map(|m| m.as_bytes().to_vec()).collect()
    };
    let out = sim::run::<C>(&config, None).map_err(err)?;
    print_report(&out.report, a.json)?;
    Ok(ExitCode::SUCCESS)
}

fn write_private(path: &Path, contents: &str) -> CliResult<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(contents.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))
}

fn keygen<C: Ciphersuite>(a: &KeygenArgs) -> CliResult<ExitCode> {
    let config = base_config(&a.group)?;
    let out = sim::run::<C>(&config, None).map_err(err)?;
    let Some(public) = out.public else {
        print_report(&out.report, false)?;
        return Err("key generation did not complete; nothing written".into());
    };
    fs::create_dir_all(&a.out).map_err(|e| format!("{}: {e}", a.out.display()))?;
    let group = GroupFile {
        format: GROUP_FORMAT.into(),
        suite: suite_of::<C>(),
        min_signers: public.min_signers(),
        max_signers: public.max_signers(),
        verifying_key: hex::encode(public.verifying_key().serialize().map_err(err)?),
        public_key_package: hex::encode(public.to_bytes()),
    };
    let group_path = a.out.join("group.json");
    fs::write(&group_path, serde_json::to_string_pretty(&group).map_err(err)? + "\n").map_err(err)?;
    for (id, key) in &out.keys {
        let file = KeyFile {
            format: KEY_FORMAT.into(),
            note: "SECRET signing share in plaintext - demo use only".into(),
            suite: suite_of::<C>(),
            identifier: *id,
            min_signers: public.min_signers(),
            max_signers: public.max_signers(),
            key_package: hex::encode(key.to_bytes()),
        };
        let path = a.out.join(format!("participant-{id}.json"));
        write_private(&path, &(serde_json::to_string_pretty(&file).map_err(err)? + "\n"))?;
    }
    println!("{DISCLAIMER}");
    println!(
        "{} {}-of-{} group via {}",
        C::NAME,
        public.min_signers(),
        public.max_signers(),
        out.report.keygen
    );
    println!("group public key: {}", group.verifying_key);
    println!(
        "wrote {} and {} participant key files to {}",
        group_path.display(),
        out.keys.len(),
        a.out.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> CliResult<T> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn sign_cmd(a: &SignArgs) -> CliResult<ExitCode> {
    let group: GroupFile = read_json(&a.keys.join("group.json"))?;
    if group.format != GROUP_FORMAT {
        return Err(format!("unsupported group file format `{}`", group.format));
    }
    dispatch!(group.suite, sign_with, a, &group)
}

fn sign_with<C: Ciphersuite>(a: &SignArgs, group: &GroupFile) -> CliResult<ExitCode> {
    let public = PublicKeyPackage::<C>::from_bytes(&hex::decode(&group.public_key_package).map_err(err)?)
        .map_err(err)?;
    let mut keys = BTreeMap::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(&a.keys)
        .map_err(|e| format!("{}: {e}", a.keys.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("participant-")))
        .collect();
    entries.sort();
    for path in entries {
        let file: KeyFile = read_json(&path)?;
        if file.format != KEY_FORMAT || file.suite != group.suite {
            return Err(format!("{}: not a {} key file for this group", path.display(), KEY_FORMAT));
        }
        let key = KeyPackage::<C>::from_bytes(&hex::decode(&file.key_package).map_err(err)?).map_err(err)?;
        if key.verifying_key() != public.verifying_key()
            || public.verifying_share(key.identifier()).map_err(err)? != key.verifying_share()
        {
            return Err(format!("{}: key does not belong to this group", path.display()));
        }
        keys.insert(file.identifier, key);
    }
    let mut config = SimConfig::new(public.min_signers(), public.max_signers());
    config.signers = a.signers.clone();
    config.messages = vec![a.message.as_bytes().to_vec()];
    config.seed = a.seed;
    let out = sim::run::<C>(&config, Some(Preloaded { keys, public })).map_err(err)?;
    print_report(&out.report, a.json)?;
    Ok(if out.report.all_verified() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn verify<C: Ciphersuite>(a: &VerifyArgs) -> CliResult<ExitCode> {
    let pk: [u8; 32] = hex::decode(&a.public_key)
        .map_err(err)?
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let sig: [u8; 64] = hex::decode(&a.signature)
        .map_err(err)?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let msg = a.message.as_bytes();
    let own = VerifyingKey::<C>::deserialize(&pk)
        .and_then(|vk| Signature::<C>::from_bytes(&sig).and_then(|s| vk.verify(msg, &s)));
    println!("verify (frostsig, {}): {}", C::NAME, if own.is_ok() { "OK" } else { "FAILED" });
    if let Err(e) = &own {
        println!("  reason: {e}");
    }
    let reference = C::reference_verify(&pk, msg, &sig);
    if let Some(ok) = reference {
        println!("verify (ed25519-dalek strict): {}", if ok { "OK" } else { "FAILED" });
    }
    Ok(if own.is_ok() && reference != Some(false) { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn vectors() -> CliResult<ExitCode> {
    let results = frostsig::vectors::check_bundled().map_err(|e: Error| e.to_string())?;
    let mut failures = 0;
    for (suite, checks) in &results {
        println!("{suite} (RFC 9591 Appendix E)");
        for c in checks {
            println!("  [{}] {}", if c.passed { "PASS" } else { "FAIL" }, c.step);
            if !c.passed {
                failures += 1;
            }
        }
    }
    let total: usize = results.iter().map(|(_, c)| c.len()).sum();
    println!("{} of {total} checks passed", total - failures);
    Ok(if failures == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

fn bench_cmd<C: Ciphersuite>(a: &BenchArgs) -> CliResult<ExitCode> {
    if a.sizes.iter().any(|&n| n < 2) {
        return Err("every size must be at least 2".into());
    }
    let config = BenchConfig { sizes: a.sizes.clone(), iterations: a.iterations, dkg_max_n: a.dkg_max_n };
    let rows = bench::run::<C>(&config).map_err(err)?;
    print!("{}", bench::render_markdown(C::NAME, a.iterations, &rows));
    Ok(ExitCode::SUCCESS)
}
