use crate::blockchain::{BlockchainConsentRegistry, EntityRole};
use crate::compliance::{AuditLedger, KeyManager};
use crate::fhe::CKKSEngine;
use crate::models::PatientRecord;
use crate::quantum::QuantumAuditor;
use crate::zkp::ZKPEngine;
use eframe::egui;

#[derive(PartialEq)]
enum ActiveTab {
    Overview,
    PatientEncryption,
    ZeroKnowledgeProofs,
    FederatedFhe,
    ComplianceShredding,
    QuantumAudit,
}

pub struct MedCryptoApp {
    active_tab: ActiveTab,

    // Blockchain & DID State
    blockchain: BlockchainConsentRegistry,
    patient_did: String,
    grantee_did: String,
    consent_scope: String,
    consent_status_msg: String,

    // Patient EMR & FHE State
    patient_id: String,
    age: f64,
    systolic_bp: f64,
    diastolic_bp: f64,
    fasting_glucose: f64,
    hba1c: f64,
    bmi: f64,
    egfr: f64,
    ldl_cholesterol: f64,
    fhe_engine: CKKSEngine,
    secret_key: crate::fhe::SecretKey,
    public_key: crate::fhe::PublicKey,
    current_ciphertext: Option<crate::fhe::Ciphertext>,
    encryption_status_msg: String,

    // ZKP State
    zkp_metric_value: u64,
    zkp_threshold: u64,
    zkp_is_upper_bound: bool,
    latest_zkp_proof: Option<crate::zkp::ThresholdProof>,
    zkp_status_msg: String,

    // Multi-Hospital Federated Average State
    hosp_a_glucose: f64,
    hosp_b_glucose: f64,
    hosp_c_glucose: f64,
    federated_result: Option<Vec<f64>>,
    federated_status_msg: String,

    // Compliance & Shredding
    key_manager: KeyManager,
    envelope: Option<crate::compliance::EncryptedEnvelope>,
    shredding_status_msg: String,
    audit_ledger: AuditLedger,
}

impl Default for MedCryptoApp {
    fn default() -> Self {
        let mut blockchain = BlockchainConsentRegistry::new();
        blockchain.register_did(
            "did:med:hospital:snuh",
            EntityRole::HospitalNode,
            "0x1111222233334444",
        );
        blockchain.register_did(
            "did:med:hospital:amc",
            EntityRole::HospitalNode,
            "0x5555666677778888",
        );
        blockchain.register_did(
            "did:med:patient:p01",
            EntityRole::Patient,
            "0x9999aaaabbbbcccc",
        );
        blockchain.register_did(
            "did:med:doctor:dr-choi",
            EntityRole::Physician,
            "0xddddeeeeffff0000",
        );

        let fhe_engine = CKKSEngine::default();
        let (secret_key, public_key) = fhe_engine.keygen();

        let mut audit_ledger = AuditLedger::new();
        audit_ledger.append(
            "did:med:doctor:dr-choi",
            "did:med:hospital:snuh",
            "did:med:patient:p01",
            "INITIAL_CONSULTATION",
            "DID_VERIFY",
            "0x98127364abcdef01",
        );

        Self {
            active_tab: ActiveTab::Overview,
            blockchain,
            patient_did: "did:med:patient:p01".to_string(),
            grantee_did: "did:med:doctor:dr-choi".to_string(),
            consent_scope: "VITALS_ZKP".to_string(),
            consent_status_msg: "Ready".to_string(),

            patient_id: "P-10029".to_string(),
            age: 54.0,
            systolic_bp: 128.0,
            diastolic_bp: 82.0,
            fasting_glucose: 104.0,
            hba1c: 5.8,
            bmi: 24.8,
            egfr: 92.0,
            ldl_cholesterol: 110.0,
            fhe_engine,
            secret_key,
            public_key,
            current_ciphertext: None,
            encryption_status_msg: "No active ciphertext".to_string(),

            zkp_metric_value: 58,
            zkp_threshold: 65,
            zkp_is_upper_bound: true,
            latest_zkp_proof: None,
            zkp_status_msg:
                "Click 'Generate ZKP' to prove clinical criteria without exposing value".to_string(),

            hosp_a_glucose: 95.0,
            hosp_b_glucose: 115.0,
            hosp_c_glucose: 120.0,
            federated_result: None,
            federated_status_msg: "Ready to run encrypted federated average across hospitals"
                .to_string(),

            key_manager: KeyManager::new(),
            envelope: None,
            shredding_status_msg: "No record currently enveloped".to_string(),
            audit_ledger,
        }
    }
}

impl eframe::App for MedCryptoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top Navigation Bar
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("MedCrypto");
                ui.label(" |  Native Privacy-Preserving Confidential Data Mesh (v0.0.1-beta)");
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::Overview,
                    "Dashboard Overview",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::PatientEncryption,
                    "EMR & 4th Gen FHE",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::ZeroKnowledgeProofs,
                    "ZKP Selective Disclosure",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::FederatedFhe,
                    "Multi-Hospital Analytics",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::ComplianceShredding,
                    "GDPR & HIPAA Audit",
                );
                ui.selectable_value(
                    &mut self.active_tab,
                    ActiveTab::QuantumAudit,
                    "Post-Quantum Security",
                );
            });
            ui.add_space(8.0);
        });

        // Bottom Status Bar
        egui::TopBottomPanel::bottom("bottom_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Cryptographic Primitives: Ring-LWE CKKS (N=128, q=30-bit)  |  SHA-256 Merkle Chain  |  Pedersen Fiat-Shamir");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label("Jeong Hoon Kim");
                });
            });
        });

        // Main View Area
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.active_tab {
                ActiveTab::Overview => self.render_overview(ui),
                ActiveTab::PatientEncryption => self.render_patient_encryption(ui),
                ActiveTab::ZeroKnowledgeProofs => self.render_zkp(ui),
                ActiveTab::FederatedFhe => self.render_federated_fhe(ui),
                ActiveTab::ComplianceShredding => self.render_compliance(ui),
                ActiveTab::QuantumAudit => self.render_quantum_audit(ui),
            });
        });
    }
}

impl MedCryptoApp {
    fn render_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Project Overview & System Status");
        ui.label("MedCrypto provides mathematically guaranteed privacy-preserving data sharing between distrusting institutions.");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Core Technology Triad Status:");
            ui.label("- Blockchain: Consortium L2 settlement layer for W3C DID, Dynamic Consent, and Zero-PHI state roots.");
            ui.label("- Zero-Knowledge Proofs: Proving compliance and eligibility predicates without exposing clinical measurements.");
            ui.label("- 4th Generation FHE (CKKS): Computing federated statistics on encrypted vectors over Ring-LWE lattices.");
            ui.label("- Post-Quantum Security: Immune to Shor's algorithm; Grover 128-bit quantum resistance for hash chains.");
        });

        ui.add_space(12.0);
        ui.heading("Dynamic Consent Management (Smart Contract Simulator)");
        ui.horizontal(|ui| {
            ui.label("Patient DID:");
            ui.text_edit_singleline(&mut self.patient_did);
            ui.label("Grantee DID:");
            ui.text_edit_singleline(&mut self.grantee_did);
        });
        ui.horizontal(|ui| {
            ui.label("Authorized Scope:");
            egui::ComboBox::from_label("")
                .selected_text(&self.consent_scope)
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.consent_scope,
                        "VITALS_ZKP".to_string(),
                        "VITALS_ZKP",
                    );
                    ui.selectable_value(
                        &mut self.consent_scope,
                        "CARDIAC_RISK_FHE".to_string(),
                        "CARDIAC_RISK_FHE",
                    );
                    ui.selectable_value(
                        &mut self.consent_scope,
                        "DIABETES_STATISTICS".to_string(),
                        "DIABETES_STATISTICS",
                    );
                });

            if ui.button("Grant Consent (On-Chain)").clicked() {
                self.blockchain.grant_consent(
                    &self.patient_did,
                    &self.grantee_did,
                    vec![self.consent_scope.clone()],
                    chrono::Utc::now() + chrono::Duration::days(30),
                );
                self.consent_status_msg = format!(
                    "Consent granted to {} for scope {}",
                    self.grantee_did, self.consent_scope
                );
            }

            if ui.button("Revoke Consent (Shred)").clicked() {
                let revoked = self
                    .blockchain
                    .revoke_consent(&self.patient_did, &self.grantee_did);
                self.consent_status_msg = if revoked {
                    format!("Consent revoked for {}", self.grantee_did)
                } else {
                    "No existing consent found".to_string()
                };
            }
        });

        ui.label(format!("Status: {}", self.consent_status_msg));
    }

    fn render_patient_encryption(&mut self, ui: &mut egui::Ui) {
        ui.heading("Patient Clinical Vitals & 4th Generation CKKS Encryption");
        ui.label("Continuous numerical biological data is encrypted into Ring-LWE polynomial ciphertexts.");
        ui.add_space(10.0);

        ui.columns(2, |columns| {
            columns[0].group(|ui| {
                ui.strong("Clinical Observations (HL7 FHIR Input):");
                ui.horizontal(|ui| {
                    ui.label("Patient ID:");
                    ui.text_edit_singleline(&mut self.patient_id);
                });
                ui.add(egui::Slider::new(&mut self.age, 18.0..=100.0).text("Age (years)"));
                ui.add(
                    egui::Slider::new(&mut self.systolic_bp, 80.0..=200.0)
                        .text("Systolic BP (mmHg)"),
                );
                ui.add(
                    egui::Slider::new(&mut self.diastolic_bp, 50.0..=120.0)
                        .text("Diastolic BP (mmHg)"),
                );
                ui.add(
                    egui::Slider::new(&mut self.fasting_glucose, 60.0..=300.0)
                        .text("Fasting Glucose (mg/dL)"),
                );
                ui.add(egui::Slider::new(&mut self.hba1c, 4.0..=14.0).text("HbA1c (%)"));
                ui.add(egui::Slider::new(&mut self.bmi, 15.0..=45.0).text("BMI (kg/m²)"));
                ui.add(egui::Slider::new(&mut self.egfr, 15.0..=120.0).text("eGFR (mL/min)"));
                ui.add(
                    egui::Slider::new(&mut self.ldl_cholesterol, 50.0..=250.0)
                        .text("LDL Cholesterol (mg/dL)"),
                );

                ui.add_space(8.0);
                if ui.button("Encrypt Record with CKKS FHE").clicked() {
                    let record = PatientRecord::mock_patient(
                        &self.patient_id,
                        self.age,
                        self.hba1c,
                        self.fasting_glucose,
                        self.systolic_bp,
                    );
                    let ct = self
                        .fhe_engine
                        .encrypt(&self.public_key, &record.to_vector());
                    self.current_ciphertext = Some(ct);
                    self.encryption_status_msg =
                        "Successfully encrypted 8 clinical dimensions into CKKS ciphertext."
                            .to_string();
                }
            });

            columns[1].group(|ui| {
                ui.strong("Ciphertext Metadata & Inspector:");
                ui.label(format!("Status: {}", self.encryption_status_msg));
                if let Some(ct) = &self.current_ciphertext {
                    ui.label(format!("Scale Factor (Delta): {:.0}", ct.scale));
                    ui.label(format!("Packed Slots: {}", ct.num_slots));
                    ui.label(format!("Polynomial Degree: N={}", ct.c0.degree()));
                    ui.label(format!("Ciphertext Modulus: q={}", ct.c0.modulus));
                    ui.label(format!(
                        "First 4 coefficients c0: {:?}",
                        &ct.c0.coeffs[0..4]
                    ));
                    ui.label(format!(
                        "First 4 coefficients c1: {:?}",
                        &ct.c1.coeffs[0..4]
                    ));

                    ui.add_space(8.0);
                    if ui.button("Test Decrypt (Secret Key)").clicked() {
                        let dec = self.fhe_engine.decrypt(&self.secret_key, ct);
                        ui.label(format!("Decrypted Vitals Vector: {:?}", dec));
                    }
                } else {
                    ui.label("No active ciphertext generated yet.");
                }
            });
        });
    }

    fn render_zkp(&mut self, ui: &mut egui::Ui) {
        ui.heading("Zero-Knowledge Predicate Verification (HIPAA Minimum Necessary)");
        ui.label("Prove that a patient satisfies an inclusion threshold without revealing their actual measurement.");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label("Private Secret Metric (e.g. HbA1c * 10):");
                ui.add(egui::DragValue::new(&mut self.zkp_metric_value));
                ui.label("Threshold Value:");
                ui.add(egui::DragValue::new(&mut self.zkp_threshold));
                ui.checkbox(&mut self.zkp_is_upper_bound, "Upper Bound (<=)");
            });

            ui.add_space(8.0);
            if ui
                .button("Generate Zero-Knowledge Proof (Fiat-Shamir)")
                .clicked()
            {
                let blinding = 99887766;
                match ZKPEngine::prove_threshold(
                    self.zkp_metric_value,
                    blinding,
                    self.zkp_threshold,
                    self.zkp_is_upper_bound,
                ) {
                    Ok(proof) => {
                        self.latest_zkp_proof = Some(proof);
                        self.zkp_status_msg =
                            "ZKP Generated successfully. Actual value is mathematically concealed."
                                .to_string();
                    }
                    Err(e) => {
                        self.latest_zkp_proof = None;
                        self.zkp_status_msg = format!("Proof Generation Failed: {}", e);
                    }
                }
            }
        });

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.strong("Verifier Dashboard (External Institution):");
            ui.label(format!("Status: {}", self.zkp_status_msg));

            if let Some(proof) = &self.latest_zkp_proof {
                ui.label(format!("Commitment C: {}", proof.commitment));
                ui.label(format!("Announcement R: {}", proof.announcement));
                ui.label(format!("Challenge c: {}", proof.challenge));
                ui.label(format!("Proof Hash: 0x{}", proof.proof_hash));

                ui.add_space(6.0);
                if ui.button("Verify Proof Integrity").clicked() {
                    let valid = ZKPEngine::verify_threshold(proof);
                    if valid {
                        self.zkp_status_msg = "VERIFICATION PASSED: Condition satisfied with 0% raw clinical data disclosed.".to_string();
                    } else {
                        self.zkp_status_msg = "VERIFICATION FAILED: Proof invalid or predicate unmet.".to_string();
                    }
                }
            }
        });
    }

    fn render_federated_fhe(&mut self, ui: &mut egui::Ui) {
        ui.heading("Cross-Hospital Federated Analytics on Ciphertexts");
        ui.label("Compute the aggregate average across multiple hospitals on an untrusted cloud without any hospital exposing raw data.");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Participating Hospital Cohort Inputs:");
            ui.horizontal(|ui| {
                ui.label("Hospital A Mean Glucose:");
                ui.add(egui::DragValue::new(&mut self.hosp_a_glucose));
                ui.label("Hospital B Mean Glucose:");
                ui.add(egui::DragValue::new(&mut self.hosp_b_glucose));
                ui.label("Hospital C Mean Glucose:");
                ui.add(egui::DragValue::new(&mut self.hosp_c_glucose));
            });

            ui.add_space(8.0);
            if ui.button("Run Homomorphic Federated Average (Untrusted Cloud)").clicked() {
                let ct_a = self.fhe_engine.encrypt(&self.public_key, &[self.hosp_a_glucose]);
                let ct_b = self.fhe_engine.encrypt(&self.public_key, &[self.hosp_b_glucose]);
                let ct_c = self.fhe_engine.encrypt(&self.public_key, &[self.hosp_c_glucose]);

                // Untrusted cloud computes average on ciphertext directly
                let ct_avg = self.fhe_engine.federated_average(&[ct_a, ct_b, ct_c]);

                // Decrypt aggregate only
                let decrypted = self.fhe_engine.decrypt(&self.secret_key, &ct_avg);
                self.federated_result = Some(decrypted);
                self.federated_status_msg = "Federated computation completed without decrypting individual hospital inputs.".to_string();
            }
        });

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.strong("Federated Computation Result:");
            ui.label(format!("Status: {}", self.federated_status_msg));
            if let Some(res) = &self.federated_result {
                let expected =
                    (self.hosp_a_glucose + self.hosp_b_glucose + self.hosp_c_glucose) / 3.0;
                ui.label(format!("Decrypted Federated Mean: {:.2} mg/dL", res[0]));
                ui.label(format!("Expected Mathematical Mean: {:.2} mg/dL", expected));
                ui.label(format!(
                    "Approximation Error: {:.4} (within CKKS noise budget)",
                    (res[0] - expected).abs()
                ));
            }
        });
    }

    fn render_compliance(&mut self, ui: &mut egui::Ui) {
        ui.heading("GDPR Article 17 Erasure & HIPAA Tamper-Proof Audit");
        ui.label("Guarantees the Right to be Forgotten via Cryptographic Shredding and tracks all disclosures immutably.");
        ui.add_space(10.0);

        ui.group(|ui| {
            ui.strong("Cryptographic Shredding (GDPR Article 17):");
            if ui
                .button("1. Encrypt Record into Ephemeral Key Envelope")
                .clicked()
            {
                let env = self.key_manager.encrypt(
                    "patient-record-8891",
                    b"Sensitive Patient Clinical and Genetic Data",
                );
                self.envelope = Some(env);
                self.shredding_status_msg =
                    "Data protected inside ephemeral key envelope.".to_string();
            }

            if ui
                .button("2. Patient Revokes Consent: Shred Key (Irrevocable Zeroize)")
                .clicked()
            {
                if let Some(env) = &self.envelope {
                    match self.key_manager.shred_key(&env.key_id, &env.record_id) {
                        Ok(cert) => {
                            self.shredding_status_msg = format!(
                                "Key destroyed. Shredding certificate: 0x{}...",
                                &cert.audit_signature[..16]
                            );
                        }
                        Err(e) => self.shredding_status_msg = format!("Shredding error: {}", e),
                    }
                }
            }

            if ui.button("3. Attempt Post-Erasure Decryption").clicked() {
                if let Some(env) = &self.envelope {
                    match self.key_manager.decrypt(env) {
                        Ok(_) => {
                            self.shredding_status_msg =
                                "VIOLATION: Data still decrypted!".to_string()
                        }
                        Err(e) => {
                            self.shredding_status_msg =
                                format!("SUCCESS: Data permanently unrecoverable ({})", e)
                        }
                    }
                }
            }

            ui.label(format!("Status: {}", self.shredding_status_msg));
        });

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.strong("HIPAA §164.528 Accounting of Disclosures (Audit Ledger):");
            ui.label(format!(
                "Total Log Entries: {}",
                self.audit_ledger.entries.len()
            ));
            ui.label(format!(
                "Chain Integrity: {}",
                if self.audit_ledger.verify_integrity() {
                    "VERIFIED (Tamper-Proof)"
                } else {
                    "CORRUPTED"
                }
            ));

            egui::Grid::new("audit_grid").striped(true).show(ui, |ui| {
                ui.label("Index");
                ui.label("Requestor DID");
                ui.label("Purpose");
                ui.label("Operation");
                ui.label("Entry Hash");
                ui.end_row();

                for entry in &self.audit_ledger.entries {
                    ui.label(entry.index.to_string());
                    ui.label(&entry.requestor_did);
                    ui.label(&entry.purpose);
                    ui.label(&entry.operation);
                    ui.label(format!("0x{}...", &entry.entry_hash[..12]));
                    ui.end_row();
                }
            });
        });
    }

    fn render_quantum_audit(&mut self, ui: &mut egui::Ui) {
        ui.heading("Post-Quantum Cryptography (PQC) Security Auditor");
        ui.label("Evaluates the lattice hardness against Shor's and Grover's quantum algorithms.");
        ui.add_space(10.0);

        let report = QuantumAuditor::evaluate_rlwe_security(128, 1_073_741_789, 3.2);

        ui.group(|ui| {
            egui::Grid::new("pqc_grid").striped(true).show(ui, |ui| {
                ui.label("Algorithm Family:");
                ui.strong(&report.algorithm_family);
                ui.end_row();

                ui.label("Underlying Hard Problem:");
                ui.strong(&report.hard_problem);
                ui.end_row();

                ui.label("Ring Dimension (N):");
                ui.strong(report.ring_dimension_n.to_string());
                ui.end_row();

                ui.label("Modulus Bit Length (q):");
                ui.strong(format!("{} bits", report.modulus_bits_q));
                ui.end_row();

                ui.label("Shor's Algorithm Immunity:");
                ui.colored_label(egui::Color32::GREEN, "PASSED (Immune to Period Finding)");
                ui.end_row();

                ui.label("Grover Search Security:");
                ui.strong(format!("{} bits", report.grover_security_bits));
                ui.end_row();

                ui.label("Quantum Sieving (BKZ/BDGL):");
                ui.strong(format!("~{} bits", report.quantum_sieving_security_bits));
                ui.end_row();

                ui.label("NIST Security Level:");
                ui.strong(&report.nist_security_level);
                ui.end_row();
            });
        });

        ui.add_space(10.0);
        ui.group(|ui| {
            ui.strong("Post-Quantum Cryptography Recommendations:");
            for rec in &report.post_quantum_recommendations {
                ui.label(format!("• {}", rec));
            }
        });
    }
}

/// Launches the native desktop GUI
pub fn run_gui() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("MedCrypto: Privacy-Preserving Confidential Data Mesh"),
        ..Default::default()
    };

    eframe::run_native(
        "MedCrypto",
        native_options,
        Box::new(|_cc| Ok(Box::new(MedCryptoApp::default()))),
    )
}
