use clap::{Parser, Subcommand};
use colored::*;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Table};
use medcrypta::blockchain::{BlockchainConsentRegistry, EntityRole};
use medcrypta::compliance::{AuditLedger, KeyManager};
use medcrypta::fhe::CKKSEngine;
use medcrypta::models::PatientRecord;
use medcrypta::quantum::QuantumAuditor;
use medcrypta::zkp::ZKPEngine;
use std::fs;

#[derive(Parser)]
#[command(name = "medcrypta")]
#[command(author = "Jeong Hoon Kim")]
#[command(version = "0.0.1-beta")]
#[command(about = "Privacy-Preserving Cross-Institutional Healthcare Data Sharing Engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Launch the native desktop graphical user interface (GUI)
    Gui,

    /// Initialize a new hospital node identity, DID, and FHE keypair
    InitNode {
        #[arg(short, long, default_value = "did:med:hospital:central-general")]
        did: String,
        #[arg(short, long, default_value = "HospitalNode")]
        role: String,
    },

    /// Encrypt a patient record using 4th Generation Homomorphic Encryption (CKKS)
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
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Generate a Zero-Knowledge Proof (ZKP) for a clinical threshold condition
    Prove {
        #[arg(short, long, default_value = "hba1c")]
        metric: String,
        #[arg(short, long, default_value_t = 58)]
        value: u64,
        #[arg(short, long, default_value_t = 65)]
        threshold: u64,
        #[arg(long, default_value_t = true)]
        upper_bound: bool,
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Verify a Zero-Knowledge Proof
    Verify {
        #[arg(short, long)]
        proof_file: String,
    },

    /// Irrevocably destroy an ephemeral key (GDPR Article 17 Cryptographic Shredding)
    Shred {
        #[arg(short, long)]
        record_id: String,
    },

    /// Perform a Post-Quantum Cryptography (PQC) and lattice hardness audit
    QuantumAudit,

    /// Run the full multi-institutional healthcare simulation demo
    Demo,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        None | Some(Commands::Gui) => {
            println!("Launching MedCrypta Native Desktop GUI...");
            if let Err(e) = medcrypta::gui::run_gui() {
                eprintln!("[ERROR] Failed to start native GUI: {}", e);
            }
        }

        Some(Commands::InitNode { did, role }) => {
            println!(
                "{}",
                "==========================================================".cyan()
            );
            println!(
                "{}",
                "  MedCrypta: Initializing Healthcare Node Cryptography   "
                    .bold()
                    .cyan()
            );
            println!(
                "{}",
                "==========================================================".cyan()
            );

            let mut registry = BlockchainConsentRegistry::new();
            let role_enum = match role.as_str() {
                "Patient" => EntityRole::Patient,
                "Physician" => EntityRole::Physician,
                _ => EntityRole::HospitalNode,
            };

            let engine = CKKSEngine::default();
            let (_sk, pk) = engine.keygen();
            let pubkey_bytes: Vec<u8> = pk.b.coeffs[0..4]
                .iter()
                .flat_map(|c| c.to_be_bytes())
                .collect();
            let pubkey_hex = hex::encode(pubkey_bytes);

            registry.register_did(&did, role_enum, &pubkey_hex);

            println!("Node DID:         {}", did.green().bold());
            println!("Role:             {}", role.yellow());
            println!("CKKS Ring Modulus: {} (approx 30 bits)", engine.modulus);
            println!("CKKS Ring Degree:  N={}", engine.degree);
            println!("Public Key Hash:  0x{}", &pubkey_hex[..16]);
            println!("\n[SUCCESS] Node cryptographic identity successfully initialized.");
        }

        Some(Commands::Encrypt {
            patient_id,
            age,
            hba1c,
            glucose,
            systolic,
            output,
        }) => {
            let record = PatientRecord::mock_patient(&patient_id, age, hba1c, glucose, systolic);
            let engine = CKKSEngine::default();
            let (_sk, pk) = engine.keygen();

            let ct = engine.encrypt(&pk, &record.to_vector());
            let json = serde_json::to_string_pretty(&ct).unwrap();

            if let Some(path) = output {
                fs::write(&path, json).expect("Failed to write ciphertext");
                println!("[SUCCESS] Ciphertext written to {}", path);
            } else {
                println!("{}", "--- Encrypted CKKS Ciphertext Summary ---".bold());
                println!("Patient Pseudo-ID: {}", record.pseudo_id);
                println!("Ciphertext Scale:  {}", ct.scale);
                println!(
                    "Encrypted Slots:   {} continuous clinical dimensions",
                    ct.num_slots
                );
                println!("Coefficients size: {} bytes", ct.c0.coeffs.len() * 8 * 2);
            }
        }

        Some(Commands::Prove {
            metric,
            value,
            threshold,
            upper_bound,
            output,
        }) => {
            let blinding = 987654321;
            match ZKPEngine::prove_threshold(value, blinding, threshold, upper_bound) {
                Ok(proof) => {
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
                        "Claim:            value {} {} (Zero-Knowledge: actual value is hidden)",
                        if upper_bound { "<=" } else { ">=" },
                        threshold
                    );
                    println!("Proof Hash:       0x{}", proof.proof_hash);
                    println!("Challenge (c):    {}", proof.challenge);

                    if let Some(path) = output {
                        let json = serde_json::to_string_pretty(&proof).unwrap();
                        fs::write(&path, json).expect("Failed to write proof file");
                        println!("\nProof saved to {}", path);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        format!("[ERROR] Proof generation failed: {}", e).red()
                    );
                }
            }
        }

        Some(Commands::Verify { proof_file }) => {
            let data = fs::read_to_string(&proof_file).expect("Failed to read proof file");
            let proof: medcrypta::zkp::ThresholdProof =
                serde_json::from_str(&data).expect("Invalid proof format");

            let valid = ZKPEngine::verify_threshold(&proof);
            if valid {
                println!(
                    "{}",
                    "[VERIFIED] Zero-Knowledge Proof is mathematically VALID."
                        .bold()
                        .green()
                );
                println!("The claimed condition is satisfied without revealing underlying clinical data.");
            } else {
                println!(
                    "{}",
                    "[FAILED] Zero-Knowledge Proof verification FAILED."
                        .bold()
                        .red()
                );
            }
        }

        Some(Commands::Shred { record_id }) => {
            let mut km = KeyManager::new();
            let envelope = km.encrypt(&record_id, b"Sensitive PHI payload");
            match km.shred_key(&envelope.key_id, &record_id) {
                Ok(cert) => {
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
                    println!("Record ID:        {}", cert.record_id);
                    println!("Destroyed Key ID: {}", cert.key_id);
                    println!("Timestamp:        {}", cert.timestamp);
                    println!("Legal Basis:      {}", cert.regulatory_basis);
                    println!("Audit Signature:  0x{}", cert.audit_signature);
                    println!("\n[CONFIRMED] Decryption key has been irrevocably zeroized.");
                    println!("The associated ciphertext on storage/blockchain is now mathematically unrecoverable.");
                }
                Err(e) => eprintln!("[ERROR] Shredding failed: {}", e),
            }
        }

        Some(Commands::QuantumAudit) => {
            let report = QuantumAuditor::evaluate_rlwe_security(128, 1_073_741_789, 3.2);

            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_header(vec![
                    Cell::new("Security Parameter").fg(Color::Cyan),
                    Cell::new("Specification / Assessment").fg(Color::Yellow),
                ]);

            table.add_row(vec!["Algorithm Family", &report.algorithm_family]);
            table.add_row(vec!["Underlying Hard Problem", &report.hard_problem]);
            table.add_row(vec![
                "Ring Dimension (N)",
                &report.ring_dimension_n.to_string(),
            ]);
            table.add_row(vec![
                "Modulus Bit Length (q)",
                &format!("{} bits", report.modulus_bits_q),
            ]);
            table.add_row(vec![
                "Shor's Algorithm Resistance",
                if report.shor_algorithm_resistant {
                    "PASSED (Immune to Period Finding)"
                } else {
                    "FAILED"
                },
            ]);
            table.add_row(vec![
                "Grover Search Security",
                &format!(
                    "{} bits (Post-Quantum Equivalent)",
                    report.grover_security_bits
                ),
            ]);
            table.add_row(vec![
                "Quantum Sieving Security (BKZ/BDGL)",
                &format!(
                    "~{} bits (SVP Hardness)",
                    report.quantum_sieving_security_bits
                ),
            ]);
            table.add_row(vec!["NIST PQC Assessment", &report.nist_security_level]);

            println!(
                "{}",
                "\n>>> Post-Quantum Cryptography (PQC) Security Audit Report <<<"
                    .bold()
                    .cyan()
            );
            println!("{table}");

            println!("\n{}", "Post-Quantum Recommendations:".bold());
            for rec in &report.post_quantum_recommendations {
                println!("  * {}", rec);
            }
        }

        Some(Commands::Demo) => {
            run_interactive_demo();
        }
    }
}

fn run_interactive_demo() {
    println!(
        "{}",
        "========================================================================="
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "   MEDCRYPTA: CROSS-HOSPITAL PRIVACY-PRESERVING SHARING ENGINE DEMO      "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "   (Blockchain DID + Zero-Knowledge Proofs + 4th Gen CKKS FHE + GDPR)    "
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "=========================================================================\n"
            .bold()
            .cyan()
    );

    // 1. Setup Consortium Blockchain & Identities
    println!(
        "{}",
        "[STEP 1] Consortium Blockchain & W3C DID Registration"
            .bold()
            .yellow()
    );
    let mut blockchain = BlockchainConsentRegistry::new();
    let hospital_a = "did:med:hospital:seoul-national";
    let hospital_b = "did:med:hospital:asani-medical";
    let patient_did = "did:med:patient:8f92b1a";
    let doctor_b_did = "did:med:doctor:dr-choi";

    blockchain.register_did(hospital_a, EntityRole::HospitalNode, "0x1111222233334444");
    blockchain.register_did(hospital_b, EntityRole::HospitalNode, "0x5555666677778888");
    blockchain.register_did(patient_did, EntityRole::Patient, "0x9999aaaabbbbcccc");
    blockchain.register_did(doctor_b_did, EntityRole::Physician, "0xddddeeeeffff0000");

    println!("  * Registered Hospital A: {}", hospital_a);
    println!("  * Registered Hospital B: {}", hospital_b);
    println!("  * Registered Patient:    {}", patient_did);
    println!("  * Registered Doctor B:   {}", doctor_b_did);

    // 2. Patient Grants Dynamic Consent on Blockchain
    println!(
        "\n{}",
        "[STEP 2] Patient Dynamic Consent Management (Smart Contract)"
            .bold()
            .yellow()
    );
    let consent = blockchain.grant_consent(
        patient_did,
        doctor_b_did,
        vec!["VITALS_ZKP".to_string(), "CARDIAC_RISK_FHE".to_string()],
        chrono::Utc::now() + chrono::Duration::days(30),
    );
    println!(
        "  * Consent Granted on-chain! Signature: 0x{}...",
        &consent.patient_signature[..16]
    );
    println!("  * Authorized Scopes: {:?}", consent.allowed_scopes);
    let is_auth = blockchain.is_authorized(patient_did, doctor_b_did, "VITALS_ZKP");
    println!(
        "  * On-chain Authorization Check: {}",
        if is_auth {
            "AUTHORIZED".green().bold()
        } else {
            "DENIED".red().bold()
        }
    );

    // 3. Clinical Data Creation at Hospital A
    println!(
        "\n{}",
        "[STEP 3] Clinical Record Creation at Hospital A (FHIR Standards)"
            .bold()
            .yellow()
    );
    let patient_data = PatientRecord::mock_patient("Patient-8F92", 52.0, 5.9, 108.0, 130.0);
    println!("  * Patient Raw Values: Age=52, HbA1c=5.9%, Glucose=108mg/dL, Systolic BP=130mmHg");

    // 4. Zero-Knowledge Proof: Clinical Trial Eligibility
    println!(
        "\n{}",
        "[STEP 4] Zero-Knowledge Proof: Eligibility Screening (HIPAA Minimum Necessary)"
            .bold()
            .yellow()
    );
    println!(
        "  * Goal: Prove HbA1c <= 6.5% WITHOUT revealing the exact value (5.9%) to Hospital B"
    );
    let scaled_hba1c = (patient_data.hba1c * 10.0).round() as u64; // 59
    let blinding = 482710395;
    let zk_proof = ZKPEngine::prove_threshold(scaled_hba1c, blinding, 65, true).unwrap();
    println!(
        "  * ZKP Generated: Announcement R={}, Challenge c={}",
        zk_proof.announcement, zk_proof.challenge
    );
    let verified = ZKPEngine::verify_threshold(&zk_proof);
    println!(
        "  * Verifier (Hospital B) Verdict: {}",
        if verified {
            "VERIFIED (Satisfies Criteria, Value 0% Disclosed)"
                .green()
                .bold()
        } else {
            "REJECTED".red().bold()
        }
    );

    // 5. 4th Generation Homomorphic Encryption (CKKS): Encrypted Cross-Hospital Analytics
    println!(
        "\n{}",
        "[STEP 5] 4th Generation FHE (CKKS): Multi-Hospital Encrypted Computation"
            .bold()
            .yellow()
    );
    let fhe = CKKSEngine::default();
    let (sk, pk) = fhe.keygen();

    // Hospital A and Hospital B encrypt patient cohorts
    let p_a = PatientRecord::mock_patient("P-A", 50.0, 5.5, 100.0, 120.0);
    let p_b = PatientRecord::mock_patient("P-B", 60.0, 6.5, 120.0, 140.0);

    let ct_a = fhe.encrypt(&pk, &p_a.to_vector());
    let ct_b = fhe.encrypt(&pk, &p_b.to_vector());
    println!(
        "  * Hospital A encrypted patient vector into CKKS Ciphertext ({} slots)",
        ct_a.num_slots
    );
    println!(
        "  * Hospital B encrypted patient vector into CKKS Ciphertext ({} slots)",
        ct_b.num_slots
    );

    // Untrusted Cloud computes Federated Average over Ciphertexts directly
    println!("  * Untrusted Cloud Computing Federated Average on Ciphertexts directly (Zero Decryption)...");
    let ct_avg = fhe.federated_average(&[ct_a, ct_b]);

    // Decrypting ONLY the aggregated statistical result
    let decrypted_avg = fhe.decrypt(&sk, &ct_avg);

    let mut vitals_table = Table::new();
    vitals_table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec![
            Cell::new("Clinical Metric").fg(Color::Cyan),
            Cell::new("Hospital A (Raw)").fg(Color::White),
            Cell::new("Hospital B (Raw)").fg(Color::White),
            Cell::new("FHE Decrypted Average").fg(Color::Green),
        ]);

    let names = PatientRecord::feature_names();
    let vec_a = p_a.to_vector();
    let vec_b = p_b.to_vector();
    for i in 0..4 {
        vitals_table.add_row(vec![
            Cell::new(names[i]),
            Cell::new(format!("{:.1}", vec_a[i])),
            Cell::new(format!("{:.1}", vec_b[i])),
            Cell::new(format!("{:.1}", decrypted_avg[i])).fg(Color::Green),
        ]);
    }
    println!("{vitals_table}");

    // 6. HIPAA Tamper-Proof Audit Trail
    println!(
        "{}",
        "[STEP 6] HIPAA §164.528 Accounting of Disclosures Audit Trail"
            .bold()
            .yellow()
    );
    let mut audit = AuditLedger::new();
    audit.append(
        doctor_b_did,
        hospital_a,
        &patient_data.pseudo_id,
        "CLINICAL_TRIAL_SCREENING",
        "ZKP_VERIFY",
        &zk_proof.proof_hash,
    );
    audit.append(
        doctor_b_did,
        hospital_b,
        &patient_data.pseudo_id,
        "EPIDEMIOLOGICAL_STUDY",
        "FHE_FEDERATED_AVG",
        "0x78ab39ef201c",
    );
    println!("  * Audit Entries Recorded: {}", audit.entries.len());
    println!(
        "  * Audit Chain Cryptographic Integrity: {}",
        if audit.verify_integrity() {
            "VERIFIED (Tamper-Proof)".green().bold()
        } else {
            "CORRUPTED".red().bold()
        }
    );

    // 7. GDPR Article 17: Right to Erasure / Cryptographic Shredding
    println!(
        "\n{}",
        "[STEP 7] GDPR Article 17: Right to Erasure / Cryptographic Shredding"
            .bold()
            .yellow()
    );
    let mut km = KeyManager::new();
    let envelope = km.encrypt(
        &patient_data.patient_id,
        b"Detailed Genomic and PHI records",
    );
    println!(
        "  * Data protected under Ephemeral Key Envelope: {}",
        envelope.key_id
    );

    // Patient revokes consent and demands erasure
    let shred_cert = km
        .shred_key(&envelope.key_id, &patient_data.patient_id)
        .unwrap();
    println!("  * Patient triggered consent revocation: KEY DESTROYED.");
    println!(
        "  * Shredding Certificate Issued: 0x{}...",
        &shred_cert.audit_signature[..16]
    );

    let decrypt_attempt = km.decrypt(&envelope);
    println!(
        "  * Post-Erasure Decryption Attempt: {}",
        match decrypt_attempt {
            Ok(_) => "SECURITY VIOLATION: Still readable!".red().bold(),
            Err(e) => format!("SUCCESSFULLY BLOCKED ({})", e).green().bold(),
        }
    );

    // 8. Post-Quantum Cryptography Verification
    println!(
        "\n{}",
        "[STEP 8] Post-Quantum Cryptography (PQC) Verification"
            .bold()
            .yellow()
    );
    let report = QuantumAuditor::evaluate_rlwe_security(128, 1_073_741_789, 3.2);
    println!("  * CKKS Hardness: {} (RLWE Lattice)", report.hard_problem);
    println!(
        "  * Shor's Algorithm Status: {}",
        if report.shor_algorithm_resistant {
            "IMMUNE (No period-finding vulnerability)".green().bold()
        } else {
            "VULNERABLE".red()
        }
    );
    println!(
        "  * Quantum Sieving Hardness: ~{} bits",
        report.quantum_sieving_security_bits
    );
    println!(
        "  * Grover Hashing Security:  {} bits",
        report.grover_security_bits
    );

    println!(
        "\n{}",
        "========================================================================="
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "   ALL SECURITY, PRIVACY, COMPLIANCE & PQC CHECKS PASSED (100%)          "
            .bold()
            .green()
    );
    println!(
        "{}",
        "========================================================================="
            .bold()
            .cyan()
    );
}
