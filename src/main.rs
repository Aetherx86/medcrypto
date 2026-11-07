use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use medcrypto::blockchain::{BlockchainConsentRegistry, EntityRole};
use medcrypto::compliance::{AuditLedger, KeyManager};
use medcrypto::consortium::{
    bootstrap_consortium, export_node_keys, import_node_keys, query_status, run_daemon,
    BootstrapNode, NodeConfig, NodeKeyRecord,
};
use medcrypto::fhe::{
    to_bytes, BfvCiphertext, BfvEngine, CKKSEngine, Ciphertext, CkksPreset, GaloisKey, PublicKey,
    SecretKey,
};
use medcrypto::fhir::client::{fetch_observations, ClientOptions};
use medcrypto::fhir::pipeline::Row;
use medcrypto::fhir::{
    build_table, parse_bundle, CohortTable, Imputation, ParsedBundle, PipelineOptions,
    Winsorization,
};
use medcrypto::models::PatientRecord;
use medcrypto::packing::vertical::{AnalyteStatistics, BfvCohortFile};
use medcrypto::packing::{CohortFile, RecordEnvelope, BFV_FORMAT};
use medcrypto::quantum::QuantumAuditor;
use medcrypto::signatures::{
    verify as signature_verify, HybridPublicKey, HybridSignature, HybridSigningKey,
};
use medcrypto::zkp::{
    backend_for_profile, HashBasedBackend, Profile, ProofChoice, StarkCoprocessorBackend,
    ThresholdProof, ZKPEngine, ZkPredicateProver,
};
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};

mod license;

#[derive(Parser)]
#[command(name = "medcrypto")]
#[command(author = "Jeong Hoon Kim")]
#[command(version)]
#[command(about = "Privacy-preserving healthcare data sharing: RNS-CKKS and RNS-BFV, threshold decryption, range proofs, hybrid ML-DSA signatures, FHIR ingestion and a consortium daemon", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, ValueEnum)]
enum PackMode {
    /// One ciphertext per patient, each under a key of its own that can be destroyed
    Horizontal,
    /// One ciphertext per analyte, for statistics over the whole cohort
    Vertical,
    /// No encryption: the cleaned table that a consortium daemon takes as input. It holds patient data
    Table,
}

#[derive(Clone, Copy, ValueEnum)]
enum WinsorizeArg {
    Off,
    /// Clamp to the catalog's clinical limits
    Clinical,
    /// Clamp to the cohort's 1st and 99th percentiles
    P1p99,
}

#[derive(Clone, Copy, ValueEnum)]
enum ImputeArg {
    /// Leave results missing, so that statistics exclude them
    None,
    Median,
    Mean,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackendArg {
    /// The fast range proof, which is not post-quantum
    Pedersen,
    /// A built-in range proof resting only on SHA-256, which is post-quantum and about 1.4 MB
    Hash,
    /// An external post-quantum prover
    Stark,
}

#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum SchemeArg {
    /// Approximate real numbers
    Ckks,
    /// Exact integers, by a fixed-point factor
    Bfv,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Development,
    Production,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the native desktop graphical user interface (GUI)
    Gui,

    /// Show a hospital node's DID and encryption parameters
    InitNode {
        #[arg(short, long, default_value = "did:med:hospital:central-general")]
        did: String,
        #[arg(short, long, default_value = "HospitalNode")]
        role: String,
    },

    /// Generate a secret key, public key, rotation keys and relinearization key
    Keygen {
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Ring degree: 8192 or 16384
        #[arg(long, default_value_t = 8192)]
        poly_degree: usize,
    },

    /// Encrypt one patient's vitals into a CKKS ciphertext
    Encrypt {
        #[arg(short, long, default_value = "P-10023")]
        patient_id: String,
        #[arg(long, default_value_t = 54.0)]
        age: f64,
        #[arg(long, default_value_t = 5.8)]
        hba1c: f64,
        #[arg(long, default_value_t = 110.0)]
        glucose: f64,
        #[arg(long, default_value_t = 128.0)]
        systolic: f64,
        /// A public key file. Without one, a new key set is written next to the output
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Decrypt a ciphertext file
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
    },

    /// Transpose patient records into vertically packed ciphertexts
    BatchPack {
        /// A directory of JSON files: PatientRecord, a list of them, or FHIR Bundles
        #[arg(short, long)]
        input_dir: PathBuf,
        /// Patients per ciphertext, up to the slot count
        #[arg(short, long, default_value_t = 4096)]
        batch_size: usize,
        #[arg(short, long)]
        output: PathBuf,
        /// A public key file. Without one, a new key set is written next to the output
        #[arg(long)]
        public_key: Option<PathBuf>,
        /// LOINC codes to take from FHIR Bundles in the directory
        #[arg(long)]
        loinc_filter: Option<String>,
        /// The site's secret for pseudonyms, created if it does not exist
        #[arg(long)]
        pseudonym_key: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = SchemeArg::Ckks)]
        scheme: SchemeArg,
        /// For BFV: what values are multiplied by to make integers, so 10 keeps one decimal place
        #[arg(long, default_value_t = 10)]
        fixed_point: u64,
        /// For BFV: the size of the plaintext modulus, which every sum has to stay below
        #[arg(long, default_value_t = 50)]
        plain_bits: u32,
    },

    /// Fetch from a FHIR R4 server or read a bundle, normalize, and encrypt
    IngestFhir {
        /// The server's base URL. Set MEDCRYPTO_FHIR_TOKEN for a bearer token
        #[arg(short, long, conflicts_with = "bundle")]
        endpoint: Option<String>,
        /// A FHIR Bundle file, instead of a server
        #[arg(long)]
        bundle: Option<PathBuf>,
        /// Comma-separated LOINC codes
        #[arg(short, long)]
        loinc_filter: String,
        #[arg(short, long, value_enum, default_value_t = PackMode::Vertical)]
        mode: PackMode,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(short, long, default_value_t = 4096)]
        batch_size: usize,
        #[arg(long, value_enum, default_value_t = WinsorizeArg::Clinical)]
        winsorize: WinsorizeArg,
        #[arg(long, value_enum, default_value_t = ImputeArg::None)]
        impute: ImputeArg,
        /// A public key file. Without one, a new key set is written next to the output
        #[arg(long)]
        public_key: Option<PathBuf>,
        /// The site's secret for pseudonyms, created if it does not exist
        #[arg(long)]
        pseudonym_key: Option<PathBuf>,
        /// The envelope key store, for horizontal mode
        #[arg(long, default_value = "medcrypto-keystore.json")]
        key_store: PathBuf,
        /// Allow http:// to a remote server, which sends patient data in the clear
        #[arg(long)]
        allow_insecure_http: bool,
        #[arg(long, value_enum, default_value_t = SchemeArg::Ckks)]
        scheme: SchemeArg,
        /// For BFV: what values are multiplied by to make integers, so 10 keeps one decimal place
        #[arg(long, default_value_t = 10)]
        fixed_point: u64,
        /// For BFV: the size of the plaintext modulus, which every sum has to stay below
        #[arg(long, default_value_t = 50)]
        plain_bits: u32,
    },

    /// Encrypt integers with BFV
    BfvEncrypt {
        /// Comma-separated integers
        #[arg(long, allow_hyphen_values = true)]
        values: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value_t = 20)]
        plain_bits: u32,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Decrypt a BFV ciphertext file exactly, and report the noise budget left
    BfvDecrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
    },

    /// Combine several sites' vertically packed cohorts
    CohortMerge {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Compute count, mean and variance from a vertically packed cohort, with a single secret key
    CohortStats {
        #[arg(short, long)]
        input: PathBuf,
        /// The directory that keygen wrote
        #[arg(short, long)]
        keys: PathBuf,
        /// Results from fewer patients than this are withheld
        #[arg(long, default_value_t = 11)]
        min_cell_size: u64,
    },

    /// Generate a zero-knowledge proof that a value is within a threshold
    Prove {
        #[arg(short, long, default_value = "hba1c")]
        metric: String,
        #[arg(short, long, default_value_t = 58)]
        value: u64,
        #[arg(short, long, default_value_t = 65)]
        threshold: u64,
        /// Prove value >= threshold, instead of value <= threshold
        #[arg(long)]
        lower_bound: bool,
        #[arg(long, value_enum, default_value_t = BackendArg::Pedersen)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = ProfileArg::Development)]
        profile: ProfileArg,
        /// The guest program, for the stark backend
        #[arg(long)]
        guest_elf: Option<PathBuf>,
        /// The prover executable, for the stark backend
        #[arg(long)]
        runner: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a zero-knowledge proof
    Verify {
        #[arg(short, long)]
        proof_file: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendArg::Pedersen)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = ProfileArg::Development)]
        profile: ProfileArg,
        #[arg(long)]
        guest_elf: Option<PathBuf>,
        #[arg(long)]
        runner: Option<PathBuf>,
    },

    /// Encrypt one record into an envelope that can be erased by destroying its key
    PackRecord {
        #[arg(short, long)]
        record_id: String,
        /// Comma-separated numbers
        #[arg(long)]
        values: String,
        /// Comma-separated names, one per value
        #[arg(long)]
        features: String,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long, default_value = "medcrypto-keystore.json")]
        key_store: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Open an envelope and decrypt it, if its key still exists
    OpenRecord {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(long)]
        secret_key: PathBuf,
        #[arg(long, default_value = "medcrypto-keystore.json")]
        key_store: PathBuf,
    },

    /// Destroy a record's key for good (GDPR Article 17 cryptographic shredding)
    Shred {
        #[arg(short, long)]
        record_id: String,
        #[arg(long, default_value = "medcrypto-keystore.json")]
        key_store: PathBuf,
    },

    /// Generate a hybrid Ed25519 and ML-DSA-65 signing key
    SignKeygen {
        #[arg(short, long)]
        output_dir: PathBuf,
    },

    /// Sign a file with both algorithms
    Sign {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// What this signature is for, so that it cannot be reused for something else
        #[arg(long, default_value = "medcrypto-file")]
        context: String,
    },

    /// Check a file's signature. Both algorithms have to pass
    VerifySignature {
        #[arg(long)]
        public_key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        signature: PathBuf,
        #[arg(long, default_value = "medcrypto-file")]
        context: String,
    },

    /// Check parameters against the Homomorphic Encryption Standard
    QuantumAudit {
        #[arg(long, default_value_t = 8192)]
        poly_degree: usize,
    },

    /// Create a certificate authority and everything each consortium member needs
    ConsortiumInit {
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long, default_value = "medcrypto-consortium")]
        consortium_id: String,
        /// Each as id=https://host:port, with the id a lowercase DNS label
        #[arg(long, required = true, value_delimiter = ',')]
        nodes: Vec<String>,
        /// How many nodes it takes to decrypt
        #[arg(short, long)]
        threshold: u32,
        #[arg(long, default_value_t = 8192)]
        poly_degree: usize,
    },

    /// Write this node's public keys, to bring a roster from before 0.3.0 up to date
    ConsortiumExportKey {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Add exported keys to a roster. Key shares, certificates and identities all stay as they are
    ConsortiumImportKeys {
        #[arg(short, long)]
        roster: PathBuf,
        #[arg(required = true)]
        keys: Vec<PathBuf>,
    },

    /// Run or query the consortium aggregation daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Run the whole multi-hospital flow on sample data
    Demo,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Run until interrupted
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Ask a node how it is doing
    Status {
        /// This node's own configuration
        #[arg(short, long)]
        config: PathBuf,
        /// The node to ask, which defaults to this one
        #[arg(long)]
        node: Option<String>,
    },
}

type CliResult = Result<(), String>;

fn main() {
    license::enforce_license_or_exit("medcrypto");
    let cli = Cli::parse();
    let result = match cli.command {
        None | Some(Commands::Gui) => {
            println!("Launching MedCrypto Native Desktop GUI...");
            medcrypto::gui::run_gui().map_err(|e| format!("could not start the GUI: {e}"))
        }
        Some(Commands::InitNode { did, role }) => init_node(&did, &role),
        Some(Commands::Keygen {
            output_dir,
            poly_degree,
        }) => engine_for(poly_degree).and_then(|engine| write_keys(&engine, &output_dir)),
        Some(Commands::Encrypt {
            patient_id,
            age,
            hba1c,
            glucose,
            systolic,
            public_key,
            output,
        }) => encrypt(
            &patient_id,
            age,
            hba1c,
            glucose,
            systolic,
            public_key,
            output,
        ),
        Some(Commands::Decrypt { input, secret_key }) => decrypt(&input, &secret_key),
        Some(Commands::BatchPack {
            input_dir,
            batch_size,
            output,
            public_key,
            loinc_filter,
            pseudonym_key,
            scheme,
            fixed_point,
            plain_bits,
        }) => batch_pack(
            &input_dir,
            batch_size,
            &output,
            public_key,
            loinc_filter,
            pseudonym_key,
            SchemeConfig {
                scheme,
                fixed_point,
                plain_bits,
            },
        ),
        Some(Commands::IngestFhir {
            endpoint,
            bundle,
            loinc_filter,
            mode,
            output,
            batch_size,
            winsorize,
            impute,
            public_key,
            pseudonym_key,
            key_store,
            allow_insecure_http,
            scheme,
            fixed_point,
            plain_bits,
        }) => ingest_fhir(IngestArgs {
            endpoint,
            bundle,
            loinc_filter,
            mode,
            output,
            batch_size,
            winsorize,
            impute,
            public_key,
            pseudonym_key,
            key_store,
            allow_insecure_http,
            scheme: SchemeConfig {
                scheme,
                fixed_point,
                plain_bits,
            },
        }),
        Some(Commands::CohortMerge { inputs, output }) => cohort_merge(&inputs, &output),
        Some(Commands::CohortStats {
            input,
            keys,
            min_cell_size,
        }) => cohort_stats(&input, &keys, min_cell_size),
        Some(Commands::Prove {
            metric,
            value,
            threshold,
            lower_bound,
            backend,
            profile,
            guest_elf,
            runner,
            output,
        }) => prove(
            &metric,
            value,
            threshold,
            lower_bound,
            backend,
            profile,
            guest_elf,
            runner,
            output,
        ),
        Some(Commands::Verify {
            proof_file,
            backend,
            profile,
            guest_elf,
            runner,
        }) => verify(&proof_file, backend, profile, guest_elf, runner),
        Some(Commands::PackRecord {
            record_id,
            values,
            features,
            public_key,
            key_store,
            output,
        }) => pack_record(
            &record_id,
            &values,
            &features,
            &public_key,
            &key_store,
            &output,
        ),
        Some(Commands::OpenRecord {
            input,
            secret_key,
            key_store,
        }) => open_record(&input, &secret_key, &key_store),
        Some(Commands::Shred {
            record_id,
            key_store,
        }) => shred(&record_id, &key_store),
        Some(Commands::SignKeygen { output_dir }) => sign_keygen(&output_dir),
        Some(Commands::Sign {
            key,
            input,
            output,
            context,
        }) => sign_file(&key, &input, &output, &context),
        Some(Commands::VerifySignature {
            public_key,
            input,
            signature,
            context,
        }) => verify_signature(&public_key, &input, &signature, &context),
        Some(Commands::QuantumAudit { poly_degree }) => {
            engine_for(poly_degree).map(|e| quantum_audit(&e))
        }
        Some(Commands::ConsortiumInit {
            out,
            consortium_id,
            nodes,
            threshold,
            poly_degree,
        }) => consortium_init(&out, &consortium_id, &nodes, threshold, poly_degree),
        Some(Commands::ConsortiumExportKey { config, output }) => NodeConfig::load(&config)
            .and_then(|c| export_node_keys(&c))
            .and_then(|record| {
                write_json(&output, &record)?;
                println!(
                    "[SUCCESS] Public keys of {} written to {}",
                    record.node_id,
                    output.display()
                );
                Ok(())
            }),
        Some(Commands::ConsortiumImportKeys { roster, keys }) => keys
            .iter()
            .map(|path| read_json::<NodeKeyRecord>(path))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|records| import_node_keys(&roster, &records))
            .map(|changed| {
                println!(
                    "[SUCCESS] {changed} node(s) updated in {}. Give all nodes this roster.",
                    roster.display()
                );
            }),
        Some(Commands::BfvEncrypt {
            values,
            public_key,
            plain_bits,
            output,
        }) => bfv_encrypt(&values, &public_key, plain_bits, &output),
        Some(Commands::BfvDecrypt { input, secret_key }) => bfv_decrypt(&input, &secret_key),
        Some(Commands::Daemon { action }) => daemon(action),
        Some(Commands::Demo) => {
            run_interactive_demo();
            Ok(())
        }
    };
    if let Err(message) = result {
        eprintln!("{} {message}", "[ERROR]".red().bold());
        std::process::exit(1);
    }
}

fn engine_for(poly_degree: usize) -> Result<CKKSEngine, String> {
    CkksPreset::from_degree(poly_degree)
        .map(CKKSEngine::from_preset)
        .ok_or_else(|| format!("poly degree {poly_degree}: use 8192 or 16384"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> CliResult {
    let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("{parent:?}: {e}"))?;
    }
    fs::write(path, text).map_err(|e| format!("{path:?}: {e}"))
}

fn write_secret_json<T: serde::Serialize>(path: &Path, value: &T) -> CliResult {
    let text = serde_json::to_string(value).map_err(|e| e.to_string())?;
    medcrypto::consortium::write_private_file(path, text.as_bytes())
        .map_err(|e| format!("{path:?}: {e}"))
}

/// Which engine a key was made for: the parameter identifier says, so nothing else needs to be given.
fn engine_for_param_id(param_id: u64) -> Result<CKKSEngine, String> {
    [CkksPreset::N8192, CkksPreset::N16384]
        .into_iter()
        .map(CKKSEngine::from_preset)
        .find(|e| e.context().param_id() == param_id)
        .ok_or_else(|| format!("no known parameter set has the identifier {param_id}"))
}

fn write_keys(engine: &CKKSEngine, directory: &Path) -> CliResult {
    let (secret, public) = engine.keygen();
    println!(
        "Generating rotation and relinearization keys for N = {}...",
        engine.context().poly_degree
    );
    let galois = engine.galois_keygen(&secret, &engine.sum_rotation_steps());
    let relin = engine.relin_keygen(&secret);
    write_secret_json(&directory.join("secret-key.json"), &secret)?;
    write_json(&directory.join("public-key.json"), &public)?;
    write_json(&directory.join("galois-keys.json"), &galois)?;
    write_json(&directory.join("relin-key.json"), &relin)?;
    println!("[SUCCESS] Keys written to {}", directory.display());
    println!("          secret-key.json stays private. The others can be shared.");
    Ok(())
}

fn load_public_key(path: &Path) -> Result<(CKKSEngine, PublicKey), String> {
    let key: PublicKey = read_json(path)?;
    let engine = engine_for_param_id(key.param_id)?;
    engine
        .validate_public_key(&key)
        .map_err(|e| format!("{path:?}: {e}"))?;
    Ok((engine, key))
}

/// The public key given, or a new key set next to the output so that a first run just works.
fn public_key_or_new(
    given: Option<PathBuf>,
    output: &Path,
) -> Result<(CKKSEngine, PublicKey), String> {
    match given {
        Some(path) => load_public_key(&path),
        None => {
            let mut name = output.file_name().unwrap_or_default().to_os_string();
            name.push(".keys");
            let directory = output.with_file_name(name);
            let path = directory.join("public-key.json");
            if !path.exists() {
                eprintln!(
                    "{} no --public-key given, so creating keys in {}",
                    "[NOTE]".yellow(),
                    directory.display()
                );
                write_keys(&CKKSEngine::default(), &directory)?;
            }
            load_public_key(&path)
        }
    }
}

/// The site's pseudonym key, created at first use.
fn pseudonym_key(given: Option<PathBuf>, output: &Path) -> Result<Vec<u8>, String> {
    let path = given.unwrap_or_else(|| {
        let mut name = output.file_name().unwrap_or_default().to_os_string();
        name.push(".pseudonym-key");
        output.with_file_name(name)
    });
    if path.exists() {
        let text = fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
        return hex::decode(text.trim()).map_err(|e| format!("{path:?}: {e}"));
    }
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    medcrypto::consortium::write_private_file(&path, hex::encode(&key).as_bytes())
        .map_err(|e| format!("{path:?}: {e}"))?;
    eprintln!(
        "{} created the pseudonym key {}. Keep it, or pseudonyms will change.",
        "[NOTE]".yellow(),
        path.display()
    );
    Ok(key)
}

fn init_node(did: &str, role: &str) -> CliResult {
    println!(
        "{}",
        "==========================================================".cyan()
    );
    println!(
        "{}",
        "  MedCrypto: Initializing Healthcare Node Cryptography   "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "==========================================================".cyan()
    );
    let mut registry = BlockchainConsentRegistry::new();
    let role_enum = match role {
        "Patient" => EntityRole::Patient,
        "Physician" => EntityRole::Physician,
        _ => EntityRole::HospitalNode,
    };
    let engine = CKKSEngine::default();
    let (_secret, public) = engine.keygen();
    let fingerprint: Vec<u8> = public
        .b
        .preview(4)
        .iter()
        .flat_map(|c| c.to_be_bytes())
        .collect();
    let fingerprint = hex::encode(fingerprint);
    registry.register_did(did, role_enum, &fingerprint);
    let context = engine.context();
    println!("Node DID:          {}", did.green().bold());
    println!("Role:              {}", role.yellow());
    println!(
        "CKKS Ring Degree:  N={} ({} slots)",
        context.poly_degree,
        context.slots()
    );
    println!(
        "RNS Modulus Chain: {} primes + special prime, {} bits",
        context.moduli_chain.len(),
        context.total_modulus_bits()
    );
    println!("Public Key Print:  0x{}", &fingerprint[..16]);
    println!("\n[SUCCESS] Node identity shown. This key is throwaway: use `keygen` to keep one.");
    Ok(())
}

fn encrypt(
    patient_id: &str,
    age: f64,
    hba1c: f64,
    glucose: f64,
    systolic: f64,
    public_key: Option<PathBuf>,
    output: Option<PathBuf>,
) -> CliResult {
    let record = PatientRecord::mock_patient(patient_id, age, hba1c, glucose, systolic);
    let key_location = output
        .clone()
        .unwrap_or_else(|| PathBuf::from("ciphertext.json"));
    let (engine, key) = public_key_or_new(public_key, &key_location)?;
    let ciphertext = engine
        .encrypt(&key, &record.to_vector())
        .map_err(|e| e.to_string())?;
    if let Some(path) = output {
        write_json(&path, &ciphertext)?;
        println!("[SUCCESS] Ciphertext written to {}", path.display());
    } else {
        println!("{}", "--- Encrypted CKKS Ciphertext Summary ---".bold());
        println!("Patient Pseudo-ID: {}", record.pseudo_id);
        println!("Ciphertext Scale:  2^{:.0}", ciphertext.scale.log2());
        println!(
            "Encrypted Slots:   {} clinical dimensions",
            ciphertext.num_slots
        );
        println!("Level:             {}", ciphertext.level());
        println!(
            "Size:              {} bytes",
            to_bytes(&ciphertext).map_err(|e| e.to_string())?.len()
        );
    }
    Ok(())
}

fn decrypt(input: &Path, secret_key: &Path) -> CliResult {
    let ciphertext: Ciphertext = read_json(input)?;
    let secret: SecretKey = read_json(secret_key)?;
    let engine = engine_for_param_id(ciphertext.param_id)?;
    engine
        .validate_ciphertext(&ciphertext)
        .map_err(|e| format!("{input:?}: {e}"))?;
    engine
        .validate_secret_key(&secret)
        .map_err(|e| format!("{secret_key:?}: {e}"))?;
    let values = engine
        .decrypt(&secret, &ciphertext)
        .map_err(|e| e.to_string())?;
    let shown: Vec<String> = values.iter().map(|v| format!("{v:.4}")).collect();
    println!("{}", shown.join(", "));
    Ok(())
}

fn table_from_records(records: &[PatientRecord]) -> CohortTable {
    let columns = [
        ("age", "Age", "a"),
        ("systolic_bp", "Systolic blood pressure", "mm[Hg]"),
        ("diastolic_bp", "Diastolic blood pressure", "mm[Hg]"),
        ("fasting_glucose", "Fasting glucose", "mg/dL"),
        ("hba1c", "Hemoglobin A1c (NGSP)", "%"),
        ("bmi", "Body mass index", "kg/m2"),
        ("egfr", "Estimated GFR", "mL/min/{1.73_m2}"),
        ("ldl_cholesterol", "LDL cholesterol", "mg/dL"),
    ];
    CohortTable {
        columns: columns
            .iter()
            .map(
                |(analyte, display, unit)| medcrypto::fhir::pipeline::Column {
                    analyte: analyte.to_string(),
                    display: display.to_string(),
                    unit: unit.to_string(),
                },
            )
            .collect(),
        rows: records
            .iter()
            .map(|r| Row {
                pseudo_id: r.pseudo_id.clone(),
                values: r.to_vector().into_iter().map(Some).collect(),
            })
            .collect(),
        quality: Vec::new(),
    }
}

fn split_codes(text: &str) -> Vec<String> {
    text.split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect()
}

/// Which homomorphic scheme to pack a cohort with.
#[derive(Clone, Copy)]
struct SchemeConfig {
    scheme: SchemeArg,
    fixed_point: u64,
    plain_bits: u32,
}

fn write_vertical(
    engine: &CKKSEngine,
    key: &PublicKey,
    table: &CohortTable,
    batch_size: usize,
    output: &Path,
    scheme: SchemeConfig,
) -> CliResult {
    println!(
        "Encrypting {} patients and {} analytes with {}...",
        table.rows.len(),
        table.columns.len(),
        if scheme.scheme == SchemeArg::Bfv {
            "BFV"
        } else {
            "CKKS"
        }
    );
    let (slots, batches) = match scheme.scheme {
        SchemeArg::Ckks => {
            let (cohort, slots) =
                CohortFile::pack(engine, key, table, batch_size).map_err(|e| e.to_string())?;
            write_json(output, &cohort)?;
            let batches = cohort.columns.first().map_or(0, |c| c.batches.len());
            (slots, batches)
        }
        SchemeArg::Bfv => {
            let bfv = bfv_engine_for(engine.context().param_id(), scheme.plain_bits)?;
            let (cohort, slots) =
                BfvCohortFile::pack(&bfv, key, table, batch_size, scheme.fixed_point)
                    .map_err(|e| e.to_string())?;
            write_json(output, &cohort)?;
            let batches = cohort.columns.first().map_or(0, |c| c.batches.len());
            (slots, batches)
        }
    };
    let mut name = output.file_name().unwrap_or_default().to_os_string();
    name.push(".slots");
    let slot_path = output.with_file_name(name);
    write_secret_json(&slot_path, &slots)?;
    println!(
        "[SUCCESS] {} batch(es) per analyte written to {}",
        batches,
        output.display()
    );
    println!(
        "          {} maps slots to patients, and stays inside the hospital.",
        slot_path.display()
    );
    print_quality(table);
    Ok(())
}

fn bfv_engine_for(param_id: u64, plain_bits: u32) -> Result<BfvEngine, String> {
    let preset = [CkksPreset::N8192, CkksPreset::N16384]
        .into_iter()
        .find(|p| CKKSEngine::from_preset(*p).context().param_id() == param_id)
        .ok_or_else(|| format!("no known parameter set has the identifier {param_id}"))?;
    BfvEngine::new(preset, plain_bits).map_err(|e| e.to_string())
}

fn bfv_encrypt(values: &str, public_key: &Path, plain_bits: u32, output: &Path) -> CliResult {
    let key: PublicKey = read_json(public_key)?;
    let bfv = bfv_engine_for(key.param_id, plain_bits)?;
    let values = values
        .split(',')
        .map(|v| v.trim().parse::<i64>().map_err(|e| format!("{v}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let ciphertext = bfv.encrypt(&key, &values).map_err(|e| e.to_string())?;
    write_json(output, &ciphertext)?;
    println!(
        "[SUCCESS] {} integers encrypted into {}",
        values.len(),
        output.display()
    );
    println!(
        "          Results wrap around modulo t = {}.",
        bfv.plain_modulus()
    );
    Ok(())
}

fn bfv_decrypt(input: &Path, secret_key: &Path) -> CliResult {
    let ciphertext: BfvCiphertext = read_json(input)?;
    let secret: SecretKey = read_json(secret_key)?;
    let bfv = bfv_engine_for(
        ciphertext.param_id,
        64 - ciphertext.plain_modulus.leading_zeros(),
    )?;
    bfv.validate_ciphertext(&ciphertext)
        .map_err(|e| format!("{input:?}: {e}"))?;
    let values = bfv
        .decrypt(&secret, &ciphertext)
        .map_err(|e| e.to_string())?;
    let budget = bfv
        .noise_budget_bits(&secret, &ciphertext)
        .map_err(|e| e.to_string())?;
    let shown: Vec<String> = values.iter().map(i64::to_string).collect();
    println!("{}", shown.join(", "));
    eprintln!("Noise budget left: {budget:.0} bits");
    if budget < 1.0 {
        return Err("the noise budget has run out, so these values are wrong".to_string());
    }
    Ok(())
}

fn print_quality(table: &CohortTable) {
    if table.quality.is_empty() {
        return;
    }
    let mut out = Table::new();
    out.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            "Analyte",
            "Unit",
            "Results",
            "Unknown unit",
            "Implausible",
            "Winsorized",
            "Missing",
            "Imputed",
        ]);
    for (q, c) in table.quality.iter().zip(&table.columns) {
        out.add_row(vec![
            q.analyte.clone(),
            c.unit.clone(),
            q.observations.to_string(),
            q.unknown_unit.to_string(),
            q.implausible.to_string(),
            q.winsorized.to_string(),
            q.missing.to_string(),
            q.imputed.to_string(),
        ]);
    }
    println!("{out}");
}

fn batch_pack(
    input_dir: &Path,
    batch_size: usize,
    output: &Path,
    public_key: Option<PathBuf>,
    loinc_filter: Option<String>,
    pseudonym: Option<PathBuf>,
    scheme: SchemeConfig,
) -> CliResult {
    let mut records: Vec<PatientRecord> = Vec::new();
    let mut bundles = ParsedBundle::default();
    let mut names: Vec<PathBuf> = fs::read_dir(input_dir)
        .map_err(|e| format!("{input_dir:?}: {e}"))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    for path in names {
        let text = fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))?;
        if value.get("resourceType").is_some() {
            bundles.merge(parse_bundle(&text).map_err(|e| format!("{path:?}: {e}"))?);
        } else if value.is_array() {
            records.extend(
                serde_json::from_value::<Vec<PatientRecord>>(value)
                    .map_err(|e| format!("{path:?}: {e}"))?,
            );
        } else {
            records.push(serde_json::from_value(value).map_err(|e| format!("{path:?}: {e}"))?);
        }
    }
    let table = if !bundles.observations.is_empty() {
        if !records.is_empty() {
            return Err("the directory mixes PatientRecord files and FHIR Bundles".to_string());
        }
        let codes = split_codes(&loinc_filter.ok_or("FHIR Bundles need --loinc-filter")?);
        let key = pseudonym_key(pseudonym, output)?;
        build_table(
            &bundles,
            &codes,
            &PipelineOptions {
                winsorization: Winsorization::Clinical,
                imputation: Imputation::None,
                pseudonym_key: key,
            },
        )
        .map_err(|e| e.to_string())?
    } else {
        table_from_records(&records)
    };
    let (engine, key) = public_key_or_new(public_key, output)?;
    write_vertical(&engine, &key, &table, batch_size, output, scheme)
}

struct IngestArgs {
    endpoint: Option<String>,
    bundle: Option<PathBuf>,
    loinc_filter: String,
    mode: PackMode,
    output: PathBuf,
    batch_size: usize,
    winsorize: WinsorizeArg,
    impute: ImputeArg,
    public_key: Option<PathBuf>,
    pseudonym_key: Option<PathBuf>,
    key_store: PathBuf,
    allow_insecure_http: bool,
    scheme: SchemeConfig,
}

fn ingest_fhir(args: IngestArgs) -> CliResult {
    let codes = split_codes(&args.loinc_filter);
    let parsed = match (&args.endpoint, &args.bundle) {
        (Some(endpoint), None) => {
            println!("Fetching from {endpoint}...");
            fetch_observations(
                endpoint,
                &codes,
                &ClientOptions {
                    bearer_token: std::env::var("MEDCRYPTO_FHIR_TOKEN").ok(),
                    allow_insecure_http: args.allow_insecure_http,
                    ..ClientOptions::default()
                },
            )
            .map_err(|e| e.to_string())?
        }
        (None, Some(path)) => {
            let text = fs::read_to_string(path).map_err(|e| format!("{path:?}: {e}"))?;
            parse_bundle(&text).map_err(|e| format!("{path:?}: {e}"))?
        }
        _ => return Err("give either --endpoint or --bundle".to_string()),
    };
    println!(
        "Parsed {} patients and {} observations. Left out: {} by status, {} incomplete, {} other resources.",
        parsed.patients.len(), parsed.observations.len(),
        parsed.skipped_status, parsed.skipped_incomplete, parsed.skipped_other
    );
    let table = build_table(
        &parsed,
        &codes,
        &PipelineOptions {
            winsorization: match args.winsorize {
                WinsorizeArg::Off => Winsorization::Off,
                WinsorizeArg::Clinical => Winsorization::Clinical,
                WinsorizeArg::P1p99 => Winsorization::Percentile {
                    lower: 1.0,
                    upper: 99.0,
                },
            },
            imputation: match args.impute {
                ImputeArg::None => Imputation::None,
                ImputeArg::Median => Imputation::Median,
                ImputeArg::Mean => Imputation::Mean,
            },
            pseudonym_key: pseudonym_key(args.pseudonym_key, &args.output)?,
        },
    )
    .map_err(|e| e.to_string())?;
    if let PackMode::Table = args.mode {
        write_secret_json(&args.output, &table)?;
        println!("[SUCCESS] The cleaned table is in {}. It holds patient data, so keep it inside the hospital.", args.output.display());
        print_quality(&table);
        return Ok(());
    }
    let (engine, key) = public_key_or_new(args.public_key, &args.output)?;
    match args.mode {
        PackMode::Table => unreachable!("handled above"),
        PackMode::Vertical => write_vertical(
            &engine,
            &key,
            &table,
            args.batch_size,
            &args.output,
            args.scheme,
        ),
        PackMode::Horizontal => {
            let mut keys = KeyManager::open(&args.key_store)?;
            let features: Vec<String> = table.columns.iter().map(|c| c.analyte.clone()).collect();
            let mut envelopes = Vec::with_capacity(table.rows.len());
            for row in &table.rows {
                // A missing value is NaN in plain data but has no meaning in a slot, so these go in as 0 with a
                // parallel presence entry for each feature.
                let values: Vec<f64> = row.values.iter().map(|v| v.unwrap_or(0.0)).collect();
                let presence: Vec<f64> =
                    row.values.iter().map(|v| v.map_or(0.0, |_| 1.0)).collect();
                let mut names = features.clone();
                names.extend(features.iter().map(|f| format!("{f}.present")));
                let packed = [values, presence].concat();
                envelopes.push(
                    RecordEnvelope::seal(&engine, &key, &mut keys, &row.pseudo_id, names, &packed)
                        .map_err(|e| e.to_string())?,
                );
            }
            // The keys go to disk before the envelopes, which would be useless without them.
            keys.save()?;
            write_json(&args.output, &envelopes)?;
            println!(
                "[SUCCESS] {} envelopes written to {}",
                envelopes.len(),
                args.output.display()
            );
            print_quality(&table);
            Ok(())
        }
    }
}

fn load_cohort(path: &Path) -> Result<(CKKSEngine, CohortFile), String> {
    let cohort: CohortFile = read_json(path)?;
    let engine = engine_for_param_id(cohort.param_id)?;
    cohort
        .validate(&engine)
        .map_err(|e| format!("{path:?}: {e}"))?;
    Ok((engine, cohort))
}

/// Whether a cohort file was packed with BFV, from its format field.
fn is_bfv_cohort(path: &Path) -> Result<bool, String> {
    #[derive(serde::Deserialize)]
    struct Format {
        format: String,
    }
    Ok(read_json::<Format>(path)?.format == BFV_FORMAT)
}

fn load_bfv_cohort(path: &Path) -> Result<(BfvEngine, BfvCohortFile), String> {
    let cohort: BfvCohortFile = read_json(path)?;
    let bfv = bfv_engine_for(cohort.param_id, cohort.plain_bits)?;
    cohort
        .validate(&bfv)
        .map_err(|e| format!("{path:?}: {e}"))?;
    Ok((bfv, cohort))
}

fn cohort_merge(inputs: &[PathBuf], output: &Path) -> CliResult {
    if is_bfv_cohort(&inputs[0])? {
        let (_, mut merged) = load_bfv_cohort(&inputs[0])?;
        for path in &inputs[1..] {
            let (_, next) = load_bfv_cohort(path)?;
            merged = merged.merge(next).map_err(|e| format!("{path:?}: {e}"))?;
        }
        write_json(output, &merged)?;
    } else {
        let (_, mut merged) = load_cohort(&inputs[0])?;
        for path in &inputs[1..] {
            let (_, next) = load_cohort(path)?;
            merged = merged.merge(next).map_err(|e| format!("{path:?}: {e}"))?;
        }
        write_json(output, &merged)?;
    }
    println!(
        "[SUCCESS] {} cohorts merged into {}",
        inputs.len(),
        output.display()
    );
    Ok(())
}

fn bfv_cohort_stats(input: &Path, keys: &Path, min_cell_size: u64) -> CliResult {
    let (bfv, cohort) = load_bfv_cohort(input)?;
    let secret: SecretKey = read_json(&keys.join("secret-key.json"))?;
    let galois: GaloisKey = read_json(&keys.join("galois-keys.json"))?;
    println!("Summing slots homomorphically, with exact results...");
    let aggregates = cohort.aggregate(&bfv, &galois).map_err(|e| e.to_string())?;
    let mut out = Table::new();
    out.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Analyte", "Unit", "Count", "Mean", "Std. deviation"]);
    for aggregate in &aggregates {
        let first = |ct: &BfvCiphertext| -> Result<i64, String> {
            Ok(bfv.decrypt(&secret, ct).map_err(|e| e.to_string())?[0])
        };
        let count = first(&aggregate.count)?;
        if (count as u64) < min_cell_size {
            out.add_row(vec![
                aggregate.column.analyte.clone(),
                aggregate.column.unit.clone(),
                format!("fewer than {min_cell_size}"),
                "withheld".to_string(),
                "withheld".to_string(),
            ]);
            continue;
        }
        let stats = AnalyteStatistics::from_exact_totals(
            &aggregate.column,
            first(&aggregate.sum)?,
            first(&aggregate.sum_of_squares)?,
            count,
            cohort.fixed_point,
        );
        out.add_row(vec![
            stats.analyte,
            stats.unit,
            stats.count.to_string(),
            format!("{:.3}", stats.mean),
            stats
                .standard_deviation
                .map_or("-".to_string(), |s| format!("{s:.3}")),
        ]);
    }
    println!("{out}");
    Ok(())
}

fn cohort_stats(input: &Path, keys: &Path, min_cell_size: u64) -> CliResult {
    if is_bfv_cohort(input)? {
        return bfv_cohort_stats(input, keys, min_cell_size);
    }
    let (engine, cohort) = load_cohort(input)?;
    let secret: SecretKey = read_json(&keys.join("secret-key.json"))?;
    let galois: GaloisKey = read_json(&keys.join("galois-keys.json"))?;
    engine
        .validate_secret_key(&secret)
        .map_err(|e| e.to_string())?;
    engine
        .validate_galois_key(&galois)
        .map_err(|e| e.to_string())?;
    println!("Summing slots homomorphically...");
    let aggregates = cohort
        .aggregate(&engine, &galois)
        .map_err(|e| e.to_string())?;
    let mut out = Table::new();
    out.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Analyte", "Unit", "Count", "Mean", "Std. deviation"]);
    for aggregate in &aggregates {
        let first = |ct: &Ciphertext| -> Result<f64, String> {
            Ok(engine.decrypt(&secret, ct).map_err(|e| e.to_string())?[0])
        };
        let count = first(&aggregate.count)?;
        if count.round() < min_cell_size as f64 {
            out.add_row(vec![
                aggregate.column.analyte.clone(),
                aggregate.column.unit.clone(),
                format!("fewer than {min_cell_size}"),
                "withheld".to_string(),
                "withheld".to_string(),
            ]);
            continue;
        }
        let stats = AnalyteStatistics::from_totals(
            &aggregate.column,
            first(&aggregate.sum)?,
            first(&aggregate.sum_of_squares)?,
            count,
        );
        out.add_row(vec![
            stats.analyte,
            stats.unit,
            stats.count.to_string(),
            format!("{:.3}", stats.mean),
            stats
                .standard_deviation
                .map_or("-".to_string(), |s| format!("{s:.3}")),
        ]);
    }
    println!("{out}");
    Ok(())
}

fn proof_backend(
    backend: BackendArg,
    profile: ProfileArg,
    guest_elf: Option<PathBuf>,
    runner: Option<PathBuf>,
) -> Result<Box<dyn medcrypto::zkp::ZkPredicateProver>, String> {
    let profile = match profile {
        ProfileArg::Development => Profile::Development,
        ProfileArg::Production => Profile::Production,
    };
    let choice = match backend {
        BackendArg::Pedersen => ProofChoice::Pedersen,
        BackendArg::Hash => ProofChoice::HashBased,
        BackendArg::Stark => ProofChoice::Stark(StarkCoprocessorBackend::new(
            guest_elf.ok_or("the stark backend needs --guest-elf")?,
            runner.ok_or("the stark backend needs --runner")?,
        )),
    };
    backend_for_profile(profile, choice).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
fn prove(
    metric: &str,
    value: u64,
    threshold: u64,
    lower_bound: bool,
    backend: BackendArg,
    profile: ProfileArg,
    guest_elf: Option<PathBuf>,
    runner: Option<PathBuf>,
    output: Option<PathBuf>,
) -> CliResult {
    let prover = proof_backend(backend, profile, guest_elf, runner)?;
    let proof = ZKPEngine::prove_threshold_with(prover.as_ref(), value, threshold, !lower_bound)
        .map_err(|e| format!("no proof made: {e}"))?;
    println!(
        "{}",
        "==========================================================".green()
    );
    println!(
        "{}",
        "   Zero-Knowledge Proof Generated Successfully            "
            .bold()
            .green()
    );
    println!(
        "{}",
        "==========================================================".green()
    );
    println!("Metric Target:    {}", metric.bold());
    println!(
        "Claim:            value {} {threshold} (the value itself stays hidden)",
        if lower_bound { ">=" } else { "<=" }
    );
    println!("Backend:          {}", proof.proof.backend);
    println!("Commitment:       0x{}", proof.commitment());
    println!("Proof Hash:       0x{}", proof.proof_hash);
    if let Some(path) = output {
        write_json(&path, &proof)?;
        println!("\nProof saved to {}", path.display());
    }
    Ok(())
}

fn verify(
    proof_file: &Path,
    backend: BackendArg,
    profile: ProfileArg,
    guest_elf: Option<PathBuf>,
    runner: Option<PathBuf>,
) -> CliResult {
    let proof: ThresholdProof = read_json(proof_file)?;
    let verifier = proof_backend(backend, profile, guest_elf, runner)?;
    if ZKPEngine::verify_threshold_with(verifier.as_ref(), &proof) {
        println!("{}", "[VERIFIED] The proof is valid.".bold().green());
        println!(
            "The committed value is {} {}, with nothing else revealed about it.",
            if proof.is_upper_bound {
                "at most"
            } else {
                "at least"
            },
            proof.threshold
        );
        Ok(())
    } else {
        Err("[FAILED] The proof does not verify.".to_string())
    }
}

fn pack_record(
    record_id: &str,
    values: &str,
    features: &str,
    public_key: &Path,
    key_store: &Path,
    output: &Path,
) -> CliResult {
    let (engine, key) = load_public_key(public_key)?;
    let values = values
        .split(',')
        .map(|v| v.trim().parse::<f64>().map_err(|e| format!("{v}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let features = split_codes(features);
    let mut keys = KeyManager::open(key_store)?;
    let envelope = RecordEnvelope::seal(&engine, &key, &mut keys, record_id, features, &values)
        .map_err(|e| e.to_string())?;
    keys.save()?;
    write_json(output, &envelope)?;
    println!("[SUCCESS] Envelope written to {}", output.display());
    println!(
        "          Its key is {} in {}",
        envelope.envelope.key_id,
        key_store.display()
    );
    Ok(())
}

fn open_record(input: &Path, secret_key: &Path, key_store: &Path) -> CliResult {
    let envelope: RecordEnvelope = read_json(input)?;
    let secret: SecretKey = read_json(secret_key)?;
    let engine = engine_for_param_id(secret.param_id)?;
    engine
        .validate_secret_key(&secret)
        .map_err(|e| e.to_string())?;
    let keys = KeyManager::open(key_store)?;
    let ciphertext = envelope.open(&engine, &keys).map_err(|e| e.to_string())?;
    let values = engine
        .decrypt(&secret, &ciphertext)
        .map_err(|e| e.to_string())?;
    for (name, value) in envelope.features.iter().zip(&values) {
        println!("{name}: {value:.4}");
    }
    Ok(())
}

fn shred(record_id: &str, key_store: &Path) -> CliResult {
    let mut keys = KeyManager::open(key_store)?;
    let key_id = KeyManager::key_id_for(record_id);
    let certificate = keys
        .shred_key(&key_id, record_id)
        .map_err(|e| format!("{e} (no key for {record_id} in {})", key_store.display()))?;
    println!(
        "{}",
        "==========================================================".red()
    );
    println!(
        "{}",
        "  GDPR Article 17: Cryptographic Shredding Completed     "
            .bold()
            .red()
    );
    println!(
        "{}",
        "==========================================================".red()
    );
    println!("Record ID:        {}", certificate.record_id);
    println!("Destroyed Key ID: {}", certificate.key_id);
    println!("Timestamp:        {}", certificate.timestamp);
    println!("Legal Basis:      {}", certificate.regulatory_basis);
    println!("Audit Digest:     0x{}", certificate.audit_signature);
    println!(
        "\n[CONFIRMED] The key is gone from {}.",
        key_store.display()
    );
    println!("Envelopes for this record can no longer be opened. Backups of the key store must be handled");
    println!("separately, and any vertical batch holding this patient must be packed again without them.");
    Ok(())
}

fn sign_keygen(directory: &Path) -> CliResult {
    let key = HybridSigningKey::generate();
    medcrypto::consortium::write_private_file(
        &directory.join("signing-key.hex"),
        hex::encode(key.seed()).as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    write_json(&directory.join("signing-public.json"), key.public_key())?;
    println!(
        "[SUCCESS] Ed25519 and ML-DSA-65 keys written to {}",
        directory.display()
    );
    println!("          signing-key.hex stays private. signing-public.json can be shared.");
    Ok(())
}

fn sign_file(key: &Path, input: &Path, output: &Path, context: &str) -> CliResult {
    let text = fs::read_to_string(key).map_err(|e| format!("{key:?}: {e}"))?;
    let seed: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{key:?} is not 32 bytes of hex"))?;
    let message = fs::read(input).map_err(|e| format!("{input:?}: {e}"))?;
    let signature = HybridSigningKey::from_seed(&seed).sign(context.as_bytes(), &message)?;
    write_json(output, &signature)?;
    println!(
        "[SUCCESS] Signed {} into {}",
        input.display(),
        output.display()
    );
    Ok(())
}

fn verify_signature(public_key: &Path, input: &Path, signature: &Path, context: &str) -> CliResult {
    let public: HybridPublicKey = read_json(public_key)?;
    let signature: HybridSignature = read_json(signature)?;
    let message = fs::read(input).map_err(|e| format!("{input:?}: {e}"))?;
    if signature_verify(&public, context.as_bytes(), &message, &signature) {
        println!(
            "{}",
            "[VERIFIED] Both the Ed25519 and the ML-DSA-65 signature hold."
                .bold()
                .green()
        );
        Ok(())
    } else {
        Err("[FAILED] The signature does not verify.".to_string())
    }
}

fn quantum_audit(engine: &CKKSEngine) {
    let report = QuantumAuditor::evaluate_context(engine.context());
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Security Parameter").fg(Color::Cyan),
            Cell::new("Specification / Assessment").fg(Color::Yellow),
        ]);
    let limit = |l: Option<u32>| l.map_or("not covered".to_string(), |x| format!("{x} bits"));
    table.add_row(vec!["Algorithm Family", &report.algorithm_family]);
    table.add_row(vec!["Underlying Hard Problem", &report.hard_problem]);
    table.add_row(vec![
        "Ring Dimension (N)",
        &report.ring_dimension_n.to_string(),
    ]);
    table.add_row(vec![
        "Total Modulus (QP)",
        &format!("{} bits", report.modulus_bits_qp),
    ]);
    table.add_row(vec![
        "HE Standard Limit, Quantum 128",
        &limit(report.limit_bits_quantum_128),
    ]);
    table.add_row(vec![
        "HE Standard Limit, Classical 128",
        &limit(report.limit_bits_classical_128),
    ]);
    table.add_row(vec!["Assessment", &report.security_assessment]);
    table.add_row(vec![
        "Hash Chains Against Grover",
        &format!("{} bits", report.grover_security_bits),
    ]);
    table.add_row(vec![
        "Pedersen Proofs Against Shor",
        if report.zkp_commitment_quantum_safe {
            "safe"
        } else {
            "broken by a quantum computer"
        },
    ]);
    println!("{}", "\n>>> Post-Quantum Security Audit <<<".bold().cyan());
    println!("{table}");
    println!("\n{}", "Notes:".bold());
    for note in &report.post_quantum_recommendations {
        println!("  * {note}");
    }
}

fn consortium_init(
    out: &Path,
    id: &str,
    nodes: &[String],
    threshold: u32,
    poly_degree: usize,
) -> CliResult {
    let nodes = nodes
        .iter()
        .map(|text| {
            let (id, endpoint) = text
                .split_once('=')
                .ok_or_else(|| format!("{text}: expected id=https://host:port"))?;
            let port = endpoint
                .rsplit(':')
                .next()
                .unwrap_or("7443")
                .trim_end_matches('/');
            Ok(BootstrapNode {
                id: id.to_string(),
                endpoint: endpoint.to_string(),
                listen: format!("0.0.0.0:{port}"),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let roster = bootstrap_consortium(out, id, &nodes, threshold, poly_degree)?;
    println!(
        "[SUCCESS] {}-of-{} consortium written to {}",
        roster.threshold_k,
        roster.nodes.len(),
        out.display()
    );
    println!("          Give each hospital its own directory, along with ca.pem, roster.json and studies.json.");
    println!("          ca-key.pem and each node's keys were all made here. For real institutions, see the README.");
    Ok(())
}

fn daemon(action: DaemonAction) -> CliResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        match action {
            DaemonAction::Run { config } => {
                let config = NodeConfig::load(&config)?;
                println!("Node {} listening on {}", config.node_id, config.listen);
                let handle = run_daemon(config).await?;
                tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
                println!("Stopping...");
                handle.stop().await
            }
            DaemonAction::Status { config, node } => {
                let config = NodeConfig::load(&config)?;
                let target = node.unwrap_or_else(|| config.node_id.clone());
                let status = query_status(&config, &target).await?;
                println!("Node:      {}", status.node_id);
                println!(
                    "Keys:      {}",
                    if status.keys_ready {
                        "ready"
                    } else {
                        "key generation running"
                    }
                );
                println!("Running:   {:?}", status.jobs_running);
                println!("Finished:  {:?}", status.jobs_finished);
                println!("Failed:    {:?}", status.jobs_failed);
                Ok(())
            }
        }
    })
}

fn step(title: &str) {
    println!("\n{}", title.bold().yellow());
}

fn run_interactive_demo() {
    use medcrypto::fhe::threshold::{
        aggregate_public, aggregate_secret, combine, combine_bfv, partial_decrypt,
        partial_decrypt_bfv, DkgParty, ThresholdConfig, BFV_SMUDGING_BITS, DEFAULT_SMUDGING_BITS,
    };
    println!(
        "{}",
        "========================================================================="
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "   MEDCRYPTO: CROSS-HOSPITAL PRIVACY-PRESERVING SHARING ENGINE DEMO"
            .bold()
            .cyan()
    );
    println!("{}", "   (All data here is synthetic.)".bold().cyan());
    println!(
        "{}",
        "========================================================================="
            .bold()
            .cyan()
    );

    step("[STEP 1] Consent registry (simulated locally)");
    let mut chain = BlockchainConsentRegistry::new();
    let (hospital_a, hospital_b) = ("did:med:hospital:hospital-a", "did:med:hospital:hospital-b");
    let (patient, doctor) = ("did:med:patient:8f92b1a", "did:med:doctor:dr-choi");
    chain.register_did(hospital_a, EntityRole::HospitalNode, "0x1111222233334444");
    chain.register_did(hospital_b, EntityRole::HospitalNode, "0x5555666677778888");
    chain.register_did(patient, EntityRole::Patient, "0x9999aaaabbbbcccc");
    chain.register_did(doctor, EntityRole::Physician, "0xddddeeeeffff0000");
    chain.grant_consent(
        patient,
        doctor,
        vec!["VITALS_ZKP".to_string()],
        chrono::Utc::now() + chrono::Duration::days(30),
    );
    println!(
        "  * Consent recorded. Authorized for VITALS_ZKP: {}",
        chain.is_authorized(patient, doctor, "VITALS_ZKP")
    );

    step("[STEP 2] Range proof: HbA1c <= 6.5%, with the value hidden");
    let proof = ZKPEngine::prove_threshold(59, 65, true).expect("5.9 is below 6.5");
    println!(
        "  * Proof size: {} bytes, commitment 0x{}...",
        proof.proof.payload.len() / 2,
        &proof.commitment()[..16]
    );
    println!(
        "  * Verifier's verdict: {}",
        if ZKPEngine::verify_threshold(&proof) {
            "VALID".green().bold()
        } else {
            "INVALID".red().bold()
        }
    );
    println!(
        "  * A false claim cannot even be made: {}",
        ZKPEngine::prove_threshold(82, 65, true).unwrap_err()
    );

    step("[STEP 3] Distributed key generation among three hospitals, 2-of-3");
    let engine = CKKSEngine::default();
    let context = engine.context();
    println!(
        "  * N = {}, {} slots, {} modulus bits",
        context.poly_degree,
        context.slots(),
        context.total_modulus_bits()
    );
    let mut rng = medcrypto::fhe::ckks::os_seeded_rng();
    let config = ThresholdConfig::new(3, 2).expect("2-of-3 is possible");
    let seed = [7u8; 32];
    let parties: Vec<DkgParty> = (1..=3)
        .map(|i| DkgParty::new(&engine, config, i, &mut rng).expect("valid party"))
        .collect();
    let publics: Vec<_> = parties
        .iter()
        .map(|p| p.public_share(&seed, &engine.sum_rotation_steps(), &mut rng))
        .collect();
    let keys = aggregate_public(&engine, config, &seed, &publics).expect("all shares are here");
    let secrets: Vec<_> = parties.iter().map(|p| p.secret_shares(&mut rng)).collect();
    let shares: Vec<_> = (1..=3u32)
        .map(|to| {
            let mine: Vec<_> = secrets.iter().map(|s| s[to as usize - 1].clone()).collect();
            aggregate_secret(&engine, config, to, &mine).expect("all shares are here")
        })
        .collect();
    println!("  * Nobody ever holds the whole secret key.");

    step("[STEP 4] Vertical packing and homomorphic statistics");
    let cohort = |prefix: &str, base: f64| -> CohortTable {
        table_from_records(
            &(0..200)
                .map(|i| {
                    PatientRecord::mock_patient(
                        &format!("{prefix}-{i}"),
                        40.0 + (i % 30) as f64,
                        base + (i % 10) as f64 * 0.1,
                        100.0,
                        120.0,
                    )
                })
                .collect::<Vec<_>>(),
        )
    };
    let (table_a, table_b) = (cohort("A", 5.0), cohort("B", 6.0));
    let (file_a, _) = CohortFile::pack(&engine, &keys.public_key, &table_a, 4096).expect("fits");
    let (file_b, _) = CohortFile::pack(&engine, &keys.public_key, &table_b, 4096).expect("fits");
    let merged = file_a.merge(file_b).expect("same analytes");
    let aggregates = merged
        .aggregate(&engine, &keys.galois_key)
        .expect("keys match");
    println!(
        "  * Two hospitals' cohorts, 200 patients each, summed on ciphertexts by anyone at all."
    );

    step("[STEP 5] Threshold decryption of the totals only, by hospitals 1 and 3");
    let set = [1u32, 3];
    let open = |ct: &Ciphertext, rng: &mut rand_chacha::ChaCha20Rng| -> f64 {
        let partials: Vec<_> = set
            .iter()
            .map(|&p| {
                partial_decrypt(
                    &engine,
                    &shares[p as usize - 1],
                    ct,
                    &set,
                    DEFAULT_SMUDGING_BITS,
                    rng,
                )
                .expect("valid set")
            })
            .collect();
        combine(&engine, config, ct, &partials).expect("valid partials")[0]
    };
    let mut out = Table::new();
    out.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Analyte").fg(Color::Cyan),
            Cell::new("Count"),
            Cell::new("True mean"),
            Cell::new("Decrypted mean").fg(Color::Green),
        ]);
    for (index, aggregate) in aggregates.iter().enumerate() {
        let count = open(&aggregate.count, &mut rng);
        let stats = AnalyteStatistics::from_totals(
            &aggregate.column,
            open(&aggregate.sum, &mut rng),
            open(&aggregate.sum_of_squares, &mut rng),
            count,
        );
        let truth: f64 = table_a
            .rows
            .iter()
            .chain(&table_b.rows)
            .map(|r| r.values[index].expect("present"))
            .sum::<f64>()
            / 400.0;
        out.add_row(vec![
            Cell::new(stats.analyte),
            Cell::new(stats.count),
            Cell::new(format!("{truth:.3}")),
            Cell::new(format!("{:.3}", stats.mean)).fg(Color::Green),
        ]);
    }
    println!("{out}");

    step("[STEP 6] Tamper-evident audit trail");
    let mut audit = AuditLedger::new();
    audit.append(
        doctor,
        hospital_a,
        "cohort",
        "CLINICAL_TRIAL_SCREENING",
        "ZKP_VERIFY",
        &proof.proof_hash,
    );
    audit.append(
        doctor,
        hospital_b,
        "cohort",
        "EPIDEMIOLOGICAL_STUDY",
        "FHE_THRESHOLD_RELEASE",
        "digest",
    );
    println!(
        "  * {} entries, chain intact: {}",
        audit.entries.len(),
        audit.verify_integrity()
    );

    step("[STEP 7] GDPR Article 17: cryptographic shredding");
    let mut keychain = KeyManager::new();
    let (secret, public) = engine.keygen();
    let names = vec!["hba1c".to_string(), "glucose".to_string()];
    let envelope = RecordEnvelope::seal(
        &engine,
        &public,
        &mut keychain,
        "patient-8f92",
        names,
        &[5.9, 108.0],
    )
    .expect("fits");
    let opened = envelope.open(&engine, &keychain).expect("key exists");
    println!(
        "  * Before erasure, the record opens: {:.3?}",
        engine.decrypt(&secret, &opened).expect("our key")
    );
    keychain
        .shred_key(&envelope.envelope.key_id, "patient-8f92")
        .expect("key exists");
    println!(
        "  * After erasure: {}",
        envelope.open(&engine, &keychain).unwrap_err()
    );

    step("[STEP 8] BFV: an exact count, under the same collective keys and 2-of-3 decryption");
    let bfv = BfvEngine::new(CkksPreset::N8192, 50).expect("a valid modulus");
    let flags_a: Vec<i64> = (0..300).map(|i| (i % 3 == 0) as i64).collect();
    let flags_b: Vec<i64> = (0..500).map(|i| (i % 5 == 0) as i64).collect();
    let site_a = bfv.encrypt(&keys.public_key, &flags_a).expect("fits");
    let site_b = bfv.encrypt(&keys.public_key, &flags_b).expect("fits");
    let counted = bfv
        .sum_rows(
            &bfv.add(&site_a, &site_b).expect("same parameters"),
            &keys.galois_key,
        )
        .expect("keys match");
    let partials: Vec<_> = set
        .iter()
        .map(|&p| {
            partial_decrypt_bfv(
                &bfv,
                &shares[p as usize - 1],
                &counted,
                &set,
                BFV_SMUDGING_BITS,
                &mut rng,
            )
            .expect("valid set")
        })
        .collect();
    println!(
        "  * Patients meeting a criterion at two sites: {} (the true count is 200)",
        combine_bfv(&bfv, config, &counted, &partials).expect("valid partials")[0]
    );

    step("[STEP 9] Hybrid signature: Ed25519 and ML-DSA-65 together");
    let signer = HybridSigningKey::generate();
    let signature = signer
        .sign(b"demo", b"released statistics")
        .expect("signing works");
    println!(
        "  * Signature of {} + {} bytes. Valid: {}",
        signature.ed25519.len(),
        signature.ml_dsa_65.len(),
        signature_verify(
            signer.public_key(),
            b"demo",
            b"released statistics",
            &signature
        )
    );
    let mut stripped = signature.clone();
    stripped.ml_dsa_65.clear();
    println!(
        "  * With the ML-DSA part removed. Valid: {}",
        signature_verify(
            signer.public_key(),
            b"demo",
            b"released statistics",
            &stripped
        )
    );

    step("[STEP 10] Post-quantum status");
    let report = QuantumAuditor::evaluate_context(engine.context());
    println!("  * {}", report.security_assessment);
    println!("  * Signatures on consortium messages are hybrid, with ML-DSA-65.");
    let hash_proof = HashBasedBackend
        .prove_range(59, 0, 65)
        .expect("5.9 is below 6.5");
    println!(
        "  * Range proof resting only on SHA-256: {} KiB, valid: {}",
        hash_proof.payload.len() / 2048,
        HashBasedBackend.verify_range(&hash_proof, 0, 65)
    );
    println!("  * TLS key exchange is hybrid X25519 and ML-KEM-768.");
    println!("  * TLS certificates and the Pedersen backend are not post-quantum, so production refuses Pedersen.");

    println!(
        "\n{}",
        "Demo finished. This shows that the flow works: it is not a compliance certification."
            .bold()
            .green()
    );
}
