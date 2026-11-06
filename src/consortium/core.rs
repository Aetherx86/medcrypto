//! The protocol as a plain state machine, so that it can be tested and reasoned about without a network.
//!
//! 1. Key generation. Each node publishes its public shares and sends every other node a secret share. Once a
//!    node has them all, it holds the collective keys and its share of the secret, and persists them.
//! 2. Contribution. When a study is approved, each participant filters its table by consent, encrypts what is
//!    left, and sends it to everybody.
//! 3. Aggregation. With every participant's cohort in hand, each node computes the encrypted totals. That
//!    computation is deterministic, so all honest nodes get identical bytes, and they announce their hash.
//! 4. Release. When `k` nodes announce the same hash, the lowest `k` of those publish partial decryptions of
//!    the counts. If a count reaches the study's minimum cell size, its sums go through the same step.
//!    Anything smaller is suppressed.

use super::consent::ConsentSource;
use super::roster::Roster;
use super::write_private_file;
use crate::compliance::AuditLedger;
use crate::packing::vertical::{AnalyteStatistics, CohortColumn, CohortFile, EncryptedAggregate};
use crate::packing::CURRENT_FORMAT;
use medcrypto_fhe::ckks::os_seeded_rng;
use medcrypto_fhe::threshold::{
    aggregate_public, aggregate_secret, combine, partial_decrypt, CollectiveKeys, DkgParty,
    DkgPublicShare, DkgSecretShare, PartialDecryption, ThresholdConfig, ThresholdKeyShare,
};
use medcrypto_fhe::{from_bytes, to_bytes, CKKSEngine, Ciphertext, CkksPreset};
use medcrypto_fhir::pipeline::{Column, Row};
use medcrypto_fhir::CohortTable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// What nodes say to each other.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    DkgPublic(DkgPublicShare),
    DkgSecret(DkgSecretShare),
    Contribution {
        job: String,
        cohort: CohortFile,
    },
    Ready {
        job: String,
        digest: String,
    },
    Partial {
        job: String,
        phase: Phase,
        digest: String,
        active_set: Vec<u32>,
        items: Vec<PartialDecryption>,
    },
}

/// Which totals a partial decryption is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    Counts,
    Sums,
}

/// A study as the participants agreed on it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Study {
    pub id: String,
    /// A new epoch is a new run of the same study.
    pub epoch: u64,
    /// The consent scope that a patient has to have granted.
    pub scope: String,
    /// Analytes by id, as in the FHIR crate's catalog.
    pub analytes: Vec<String>,
    /// Node ids that contribute data.
    pub participants: Vec<String>,
    /// Results from fewer patients than this are suppressed.
    pub min_cell_size: u64,
}

impl Study {
    pub fn job_id(&self) -> String {
        let digest = Sha256::new()
            .chain_update(b"medcrypto-job-v1")
            .chain_update((self.id.len() as u64).to_le_bytes())
            .chain_update(self.id.as_bytes())
            .chain_update(self.epoch.to_le_bytes())
            .finalize();
        hex::encode(&digest[..16])
    }
}

/// One analyte's released result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ReleasedAnalyte {
    Released(AnalyteStatistics),
    Suppressed { analyte: String, min_cell_size: u64 },
}

/// What a finished job leaves behind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobResult {
    pub job: String,
    pub study_id: String,
    pub epoch: u64,
    pub participants: Vec<String>,
    pub aggregate_digest: String,
    pub analytes: Vec<ReleasedAnalyte>,
}

/// A message to send, and who to.
#[derive(Debug)]
pub struct Outgoing {
    pub to: String,
    pub message: Message,
}

/// A snapshot for the status call.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NodeStatus {
    pub keys_ready: bool,
    pub running: Vec<String>,
    pub finished: Vec<String>,
    pub failed: Vec<String>,
}

type PartialKey = (Phase, String, Vec<u32>);

#[derive(Default)]
struct JobState {
    study: Option<Study>,
    contributed: bool,
    contributions: BTreeMap<String, CohortFile>,
    aggregate: Option<Vec<EncryptedAggregate>>,
    digest: Option<String>,
    ready: BTreeMap<u32, String>,
    partials: BTreeMap<PartialKey, BTreeMap<u32, Vec<PartialDecryption>>>,
    sent: BTreeSet<(Phase, Vec<u32>)>,
    counts: Option<Vec<f64>>,
    finished: bool,
    failed: Option<String>,
}

/// The state machine. Everything in it runs on one thread.
pub struct ConsortiumCore {
    engine: CKKSEngine,
    roster: Roster,
    me: String,
    party: u32,
    config: ThresholdConfig,
    data_dir: PathBuf,
    studies_path: PathBuf,
    consent: Box<dyn ConsentSource>,
    dkg_party: Option<DkgParty>,
    dkg_public: BTreeMap<u32, DkgPublicShare>,
    dkg_secret: BTreeMap<u32, DkgSecretShare>,
    keys: Option<(CollectiveKeys, ThresholdKeyShare)>,
    jobs: BTreeMap<String, JobState>,
    outbox: Vec<Outgoing>,
    audit: AuditLedger,
}

impl ConsortiumCore {
    pub fn new(
        roster: Roster,
        me: &str,
        data_dir: PathBuf,
        studies_path: PathBuf,
        consent: Box<dyn ConsentSource>,
    ) -> Result<Self, String> {
        let party = roster
            .node(me)
            .ok_or_else(|| format!("{me} is not in the roster"))?
            .party;
        let preset = CkksPreset::from_degree(roster.poly_degree)
            .ok_or_else(|| format!("poly degree {}", roster.poly_degree))?;
        let config = ThresholdConfig::new(roster.nodes.len() as u32, roster.threshold_k)
            .map_err(|e| e.to_string())?;
        std::fs::create_dir_all(data_dir.join("cohorts")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(data_dir.join("jobs")).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(data_dir.join("results")).map_err(|e| e.to_string())?;
        let audit_path = data_dir.join("audit.json");
        let audit = if audit_path.exists() {
            let text = std::fs::read_to_string(&audit_path).map_err(|e| e.to_string())?;
            let ledger: AuditLedger = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            if !ledger.verify_integrity() {
                return Err(format!("{audit_path:?} fails its integrity check"));
            }
            ledger
        } else {
            AuditLedger::new()
        };
        Ok(Self {
            engine: CKKSEngine::from_preset(preset),
            roster,
            me: me.to_string(),
            party,
            config,
            data_dir,
            studies_path,
            consent,
            dkg_party: None,
            dkg_public: BTreeMap::new(),
            dkg_secret: BTreeMap::new(),
            keys: None,
            jobs: BTreeMap::new(),
            outbox: Vec::new(),
            audit,
        })
    }

    fn share_path(&self) -> PathBuf {
        self.data_dir.join("threshold-share.bin")
    }

    fn keys_path(&self) -> PathBuf {
        self.data_dir.join("collective-keys.bin")
    }

    /// Loads finished key generation from disk, or starts it. Call once, before anything else.
    pub fn start(&mut self) -> Result<(), String> {
        if self.share_path().exists() && self.keys_path().exists() {
            let share: ThresholdKeyShare =
                from_bytes(&std::fs::read(self.share_path()).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let keys: CollectiveKeys =
                from_bytes(&std::fs::read(self.keys_path()).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            self.engine
                .validate_public_key(&keys.public_key)
                .map_err(|e| e.to_string())?;
            self.engine
                .validate_galois_key(&keys.galois_key)
                .map_err(|e| e.to_string())?;
            self.keys = Some((keys, share));
            return Ok(());
        }
        let mut rng = os_seeded_rng();
        let party = DkgParty::new(&self.engine, self.config, self.party, &mut rng)
            .map_err(|e| e.to_string())?;
        let seed = self.roster.crs_seed_bytes()?;
        let public = party.public_share(&seed, &self.engine.sum_rotation_steps(), &mut rng);
        for share in party.secret_shares(&mut rng) {
            if share.to == self.party {
                self.dkg_secret.insert(self.party, share);
            } else {
                let to = self
                    .roster
                    .by_party(share.to)
                    .expect("checked by the roster")
                    .id
                    .clone();
                self.outbox.push(Outgoing {
                    to,
                    message: Message::DkgSecret(share),
                });
            }
        }
        self.broadcast(Message::DkgPublic(public.clone()));
        self.dkg_public.insert(self.party, public);
        self.dkg_party = Some(party);
        self.try_finish_dkg()
    }

    fn broadcast(&mut self, message: Message) {
        let others: Vec<String> = self
            .roster
            .nodes
            .iter()
            .filter(|n| n.id != self.me)
            .map(|n| n.id.clone())
            .collect();
        for to in others {
            self.outbox.push(Outgoing {
                to,
                message: message.clone(),
            });
        }
    }

    /// What is waiting to be sent.
    pub fn take_outgoing(&mut self) -> Vec<Outgoing> {
        std::mem::take(&mut self.outbox)
    }

    pub fn status(&self) -> NodeStatus {
        let mut status = NodeStatus {
            keys_ready: self.keys.is_some(),
            ..NodeStatus::default()
        };
        for (id, job) in &self.jobs {
            if job.finished {
                status.finished.push(id.clone());
            } else if job.failed.is_some() {
                status.failed.push(id.clone());
            } else if job.study.is_some() {
                status.running.push(id.clone());
            }
        }
        status
    }

    pub fn public_keys(&self) -> Option<&CollectiveKeys> {
        self.keys.as_ref().map(|(k, _)| k)
    }

    fn try_finish_dkg(&mut self) -> Result<(), String> {
        if self.keys.is_some()
            || self.dkg_public.len() != self.roster.nodes.len()
            || self.dkg_secret.len() != self.roster.nodes.len()
        {
            return Ok(());
        }
        let seed = self.roster.crs_seed_bytes()?;
        let public: Vec<DkgPublicShare> = self.dkg_public.values().cloned().collect();
        let keys = aggregate_public(&self.engine, self.config, &seed, &public)
            .map_err(|e| e.to_string())?;
        let secret: Vec<DkgSecretShare> = self.dkg_secret.values().cloned().collect();
        let share = aggregate_secret(&self.engine, self.config, self.party, &secret)
            .map_err(|e| e.to_string())?;
        write_private_file(
            &self.share_path(),
            &to_bytes(&share).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        write_private_file(
            &self.keys_path(),
            &to_bytes(&keys).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        self.keys = Some((keys, share));
        self.dkg_party = None;
        self.dkg_public.clear();
        self.dkg_secret.clear();
        Ok(())
    }

    /// Takes in one authenticated message. Errors are about that message, and do not stop the node.
    pub fn handle(&mut self, sender: &str, message: Message) -> Result<(), String> {
        let sender_party = self
            .roster
            .node(sender)
            .ok_or_else(|| format!("{sender} is not in the roster"))?
            .party;
        match message {
            Message::DkgPublic(share) => {
                if self.keys.is_some() {
                    return Ok(());
                }
                if share.party != sender_party {
                    return Err(format!(
                        "{sender} sent a public share for party {}",
                        share.party
                    ));
                }
                self.dkg_public.entry(share.party).or_insert(share);
                self.try_finish_dkg()
            }
            Message::DkgSecret(share) => {
                if self.keys.is_some() {
                    return Ok(());
                }
                if share.from != sender_party || share.to != self.party {
                    return Err(format!("{sender} sent a misaddressed secret share"));
                }
                self.dkg_secret.entry(share.from).or_insert(share);
                self.try_finish_dkg()
            }
            Message::Contribution { job, cohort } => {
                cohort.validate(&self.engine).map_err(|e| e.to_string())?;
                self.jobs
                    .entry(job.clone())
                    .or_default()
                    .contributions
                    .entry(sender.to_string())
                    .or_insert(cohort);
                self.advance(&job);
                Ok(())
            }
            Message::Ready { job, digest } => {
                self.jobs
                    .entry(job.clone())
                    .or_default()
                    .ready
                    .entry(sender_party)
                    .or_insert(digest);
                self.advance(&job);
                Ok(())
            }
            Message::Partial {
                job,
                phase,
                digest,
                active_set,
                items,
            } => {
                if !active_set.contains(&sender_party)
                    || items
                        .iter()
                        .any(|p| p.party != sender_party || p.active_set != active_set)
                {
                    return Err(format!("{sender} sent an inconsistent partial decryption"));
                }
                self.jobs
                    .entry(job.clone())
                    .or_default()
                    .partials
                    .entry((phase, digest, active_set))
                    .or_default()
                    .entry(sender_party)
                    .or_insert(items);
                self.advance(&job);
                Ok(())
            }
        }
    }

    fn load_studies(&self) -> Result<Vec<Study>, String> {
        let text = std::fs::read_to_string(&self.studies_path)
            .map_err(|e| format!("{:?}: {e}", self.studies_path))?;
        serde_json::from_str(&text).map_err(|e| format!("{:?}: {e}", self.studies_path))
    }

    /// The periodic step: look for newly approved studies, and move running jobs along.
    pub fn tick(&mut self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.keys.is_none() {
            return problems;
        }
        let studies = match self.load_studies() {
            Ok(s) => s,
            Err(e) => {
                problems.push(e);
                return problems;
            }
        };
        for study in studies {
            let job = study.job_id();
            let result_path = self.data_dir.join("results").join(format!("{job}.json"));
            if result_path.exists() {
                let state = self.jobs.entry(job.clone()).or_default();
                state.finished = true;
                continue;
            }
            let state = self.jobs.entry(job.clone()).or_default();
            if state.failed.is_some() || state.finished {
                continue;
            }
            if state.study.is_none() {
                // Nothing moves until this node's own consent source approves the study.
                match self.consent.study_active(&study.id, study.epoch) {
                    Ok(true) => {
                        self.jobs.get_mut(&job).expect("just added").study = Some(study);
                    }
                    Ok(false) => continue,
                    Err(e) => {
                        problems.push(format!("consent lookup for {}: {e}", study.id));
                        continue;
                    }
                }
            }
            if let Err(e) = self.contribute(&job) {
                problems.push(format!("job {job}: {e}"));
                self.jobs.get_mut(&job).expect("just added").failed = Some(e);
                continue;
            }
            self.advance(&job);
        }
        for (id, job) in &self.jobs {
            if let Some(reason) = &job.failed {
                problems.push(format!("job {id} failed: {reason}"));
            }
        }
        problems
    }

    /// Encrypts this node's consented patients for a job and sends them out, exactly once.
    fn contribute(&mut self, job: &str) -> Result<(), String> {
        let state = self.jobs.get_mut(job).expect("the job exists");
        let study = state.study.clone().expect("the study is set");
        if state.contributed || !study.participants.contains(&self.me) {
            return Ok(());
        }
        // A restart in the middle of a job must not produce a second, different encryption of the same data,
        // since peers would keep the first and the hashes would never match. So that job is given up.
        let marker = self.data_dir.join("jobs").join(format!("{job}.started"));
        if marker.exists() {
            return Err("this node restarted during the job; start a new epoch".to_string());
        }
        let cohort = self.build_contribution(&study)?;
        std::fs::write(&marker, b"").map_err(|e| e.to_string())?;
        let state = self.jobs.get_mut(job).expect("the job exists");
        state.contributed = true;
        state.contributions.insert(self.me.clone(), cohort.clone());
        self.broadcast(Message::Contribution {
            job: job.to_string(),
            cohort,
        });
        self.record_audit(&study, "FHE_COHORT_CONTRIBUTED", job)?;
        Ok(())
    }

    /// This node's table, cut down to the study's analytes and to patients whose consent covers it.
    fn build_contribution(&mut self, study: &Study) -> Result<CohortFile, String> {
        let path = self
            .data_dir
            .join("cohorts")
            .join(format!("{}.json", study.id));
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
        let table: CohortTable =
            serde_json::from_str(&text).map_err(|e| format!("{path:?}: {e}"))?;
        let mut indices = Vec::with_capacity(study.analytes.len());
        for analyte in &study.analytes {
            let index = table
                .columns
                .iter()
                .position(|c| &c.analyte == analyte)
                .ok_or_else(|| format!("{path:?} has no column for {analyte}"))?;
            indices.push(index);
        }
        let mut rows = Vec::new();
        for row in &table.rows {
            // A failed lookup is the same as no consent.
            if matches!(
                self.consent
                    .patient_authorized(&row.pseudo_id, &study.scope),
                Ok(true)
            ) {
                rows.push(Row {
                    pseudo_id: row.pseudo_id.clone(),
                    values: indices.iter().map(|&i| row.values[i]).collect(),
                });
            }
        }
        let columns: Vec<Column> = indices.iter().map(|&i| table.columns[i].clone()).collect();
        if rows.is_empty() {
            // This site still takes part, so that the others do not wait forever, and adds nothing.
            return Ok(CohortFile {
                format: CURRENT_FORMAT.to_string(),
                param_id: self.engine.context().param_id(),
                batch_size: self.engine.slots(),
                columns: columns
                    .into_iter()
                    .map(|column| CohortColumn {
                        column,
                        batches: Vec::new(),
                    })
                    .collect(),
                quality: Vec::new(),
            });
        }
        let filtered = CohortTable {
            columns,
            rows,
            quality: Vec::new(),
        };
        let (keys, _) = self.keys.as_ref().ok_or("no keys yet")?;
        let (cohort, _) = CohortFile::pack(
            &self.engine,
            &keys.public_key,
            &filtered,
            self.engine.slots(),
        )
        .map_err(|e| e.to_string())?;
        Ok(cohort)
    }

    fn record_audit(&mut self, study: &Study, operation: &str, proof: &str) -> Result<(), String> {
        let me = self.me.clone();
        self.audit
            .append(&me, &me, "cohort-aggregate", &study.scope, operation, proof);
        let text = serde_json::to_string_pretty(&self.audit).map_err(|e| e.to_string())?;
        write_private_file(&self.data_dir.join("audit.json"), text.as_bytes())
            .map_err(|e| e.to_string())
    }

    /// Does whatever the job's state now allows.
    fn advance(&mut self, job: &str) {
        if let Err(reason) = self.advance_inner(job) {
            if let Some(state) = self.jobs.get_mut(job) {
                state.failed = Some(reason);
            }
        }
    }

    fn advance_inner(&mut self, job: &str) -> Result<(), String> {
        if self.keys.is_none() {
            return Ok(());
        }
        let Some(state) = self.jobs.get(job) else {
            return Ok(());
        };
        if state.finished || state.failed.is_some() {
            return Ok(());
        }
        let Some(study) = state.study.clone() else {
            return Ok(());
        };
        if state.aggregate.is_none()
            && study
                .participants
                .iter()
                .all(|p| state.contributions.contains_key(p))
        {
            self.compute_aggregate(job, &study)?;
        }
        self.release(job, &study, Phase::Counts)?;
        self.release(job, &study, Phase::Sums)
    }

    /// Adds up everybody's cohorts in a fixed order, then announces the hash of the result.
    fn compute_aggregate(&mut self, job: &str, study: &Study) -> Result<(), String> {
        let state = self.jobs.get_mut(job).expect("the job exists");
        let mut merged: Option<CohortFile> = None;
        for participant in &study.participants {
            let cohort = state.contributions[participant].clone();
            let names: Vec<&String> = cohort.columns.iter().map(|c| &c.column.analyte).collect();
            if names != study.analytes.iter().collect::<Vec<_>>() {
                return Err(format!(
                    "{participant} sent other analytes than the study's"
                ));
            }
            merged = Some(match merged {
                None => cohort,
                Some(m) => m.merge(cohort).map_err(|e| e.to_string())?,
            });
        }
        let merged = merged.ok_or("the study has no participants")?;
        let (keys, _) = self.keys.as_ref().ok_or("no keys yet")?;
        let aggregate = merged
            .aggregate(&self.engine, &keys.galois_key)
            .map_err(|e| e.to_string())?;
        let digest = hex::encode(Sha256::digest(
            to_bytes(&aggregate).map_err(|e| e.to_string())?,
        ));
        let state = self.jobs.get_mut(job).expect("the job exists");
        state.aggregate = Some(aggregate);
        state.digest = Some(digest.clone());
        state.ready.insert(self.party, digest.clone());
        self.broadcast(Message::Ready {
            job: job.to_string(),
            digest,
        });
        Ok(())
    }

    /// The ciphertexts for a phase, in the order the partial decryptions are in.
    fn phase_ciphertexts(
        aggregate: &[EncryptedAggregate],
        counts: Option<&[f64]>,
        min_cell_size: u64,
        phase: Phase,
    ) -> Vec<Ciphertext> {
        match phase {
            Phase::Counts => aggregate.iter().map(|a| a.count.clone()).collect(),
            Phase::Sums => aggregate
                .iter()
                .zip(counts.unwrap_or_default())
                .filter(|(_, &count)| count.round() >= min_cell_size as f64)
                .flat_map(|(a, _)| [a.sum.clone(), a.sum_of_squares.clone()])
                .collect(),
        }
    }

    fn release(&mut self, job: &str, study: &Study, phase: Phase) -> Result<(), String> {
        let state = self.jobs.get(job).expect("the job exists");
        let (Some(digest), Some(aggregate)) = (state.digest.clone(), state.aggregate.clone())
        else {
            return Ok(());
        };
        if state.finished || (phase == Phase::Sums && state.counts.is_none()) {
            return Ok(());
        }
        if phase == Phase::Counts && state.counts.is_some() {
            return Ok(());
        }
        let ciphertexts = Self::phase_ciphertexts(
            &aggregate,
            state.counts.as_deref(),
            study.min_cell_size,
            phase,
        );

        // Anyone announcing another hash either saw different data or is misbehaving. Their announcement
        // does not count towards the threshold, and it is worth knowing about.
        let ready: Vec<u32> = state
            .ready
            .iter()
            .filter(|(_, d)| **d == digest)
            .map(|(&p, _)| p)
            .collect();
        let k = self.config.k as usize;
        if ready.len() >= k && !ciphertexts.is_empty() {
            let set: Vec<u32> = ready[..k].to_vec();
            if set.contains(&self.party) && !state.sent.contains(&(phase, set.clone())) {
                self.publish_partial(job, study, phase, &digest, set, &ciphertexts)?;
            }
        }

        // Any set that has reached the threshold finishes the phase.
        let state = self.jobs.get(job).expect("the job exists");
        let complete = state
            .partials
            .iter()
            .find(|((p, d, set), by_party)| {
                *p == phase && *d == digest && by_party.len() == set.len()
            })
            .map(|(_, by_party)| by_party.clone());
        if phase == Phase::Sums && ciphertexts.is_empty() {
            return self.finish(job, study, &digest, &aggregate, &[]);
        }
        let Some(by_party) = complete else {
            return Ok(());
        };
        let mut values = Vec::with_capacity(ciphertexts.len());
        for (index, ct) in ciphertexts.iter().enumerate() {
            let parts = by_party
                .values()
                .map(|items| {
                    items
                        .get(index)
                        .cloned()
                        .ok_or_else(|| "a partial decryption is missing an item".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let decrypted =
                combine(&self.engine, self.config, ct, &parts).map_err(|e| e.to_string())?;
            values.push(decrypted.first().copied().unwrap_or(0.0));
        }
        match phase {
            Phase::Counts => {
                self.jobs.get_mut(job).expect("the job exists").counts = Some(values);
                self.release(job, study, Phase::Sums)
            }
            Phase::Sums => self.finish(job, study, &digest, &aggregate, &values),
        }
    }

    fn publish_partial(
        &mut self,
        job: &str,
        study: &Study,
        phase: Phase,
        digest: &str,
        set: Vec<u32>,
        ciphertexts: &[Ciphertext],
    ) -> Result<(), String> {
        // The last gate: a study withdrawn after contributions were made does not get decrypted.
        if !matches!(self.consent.study_active(&study.id, study.epoch), Ok(true)) {
            return Err("the study is no longer approved".to_string());
        }
        let (_, share) = self.keys.as_ref().ok_or("no keys yet")?;
        let mut rng = os_seeded_rng();
        let items = ciphertexts
            .iter()
            .map(|ct| {
                partial_decrypt(
                    &self.engine,
                    share,
                    ct,
                    &set,
                    self.roster.smudging_bits,
                    &mut rng,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let party = self.party;
        let state = self.jobs.get_mut(job).expect("the job exists");
        state.sent.insert((phase, set.clone()));
        state
            .partials
            .entry((phase, digest.to_string(), set.clone()))
            .or_default()
            .insert(party, items.clone());
        self.broadcast(Message::Partial {
            job: job.to_string(),
            phase,
            digest: digest.to_string(),
            active_set: set,
            items,
        });
        Ok(())
    }

    fn finish(
        &mut self,
        job: &str,
        study: &Study,
        digest: &str,
        aggregate: &[EncryptedAggregate],
        values: &[f64],
    ) -> Result<(), String> {
        let state = self.jobs.get(job).expect("the job exists");
        let counts = state.counts.clone().ok_or("no counts yet")?;
        let mut sums = values.as_chunks::<2>().0.iter();
        let analytes = aggregate
            .iter()
            .zip(&counts)
            .map(|(a, &count)| {
                if count.round() >= study.min_cell_size as f64 {
                    let pair = sums.next().expect("one pair per released analyte");
                    ReleasedAnalyte::Released(AnalyteStatistics::from_totals(
                        &a.column, pair[0], pair[1], count,
                    ))
                } else {
                    ReleasedAnalyte::Suppressed {
                        analyte: a.column.analyte.clone(),
                        min_cell_size: study.min_cell_size,
                    }
                }
            })
            .collect();
        let result = JobResult {
            job: job.to_string(),
            study_id: study.id.clone(),
            epoch: study.epoch,
            participants: study.participants.clone(),
            aggregate_digest: digest.to_string(),
            analytes,
        };
        let path = self.data_dir.join("results").join(format!("{job}.json"));
        let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| e.to_string())?;
        self.record_audit(study, "FHE_THRESHOLD_RELEASE", digest)?;
        let state = self.jobs.get_mut(job).expect("the job exists");
        state.finished = true;
        // The inputs are of no further use, and they are large.
        state.contributions.clear();
        state.aggregate = None;
        state.partials.clear();
        Ok(())
    }
}

/// The path of a job's result under a node's data directory.
pub fn result_path(data_dir: &Path, job: &str) -> PathBuf {
    data_dir.join("results").join(format!("{job}.json"))
}
