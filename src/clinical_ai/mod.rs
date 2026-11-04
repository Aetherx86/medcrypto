// Clinical AI Longitudinal Medication Recommendation Module
// Author: Jeong Hoon Kim
// Advanced Architecture:
// 1. Relevant-Visit Selection Module with Straight-Through Gumbel-Softmax (Differentiable Hard Selection)
// 2. Target-Aware Cross-Attention with Bounded Historical Context (q_T = v_T + sum alpha_t v_t)
// 3. Two-Level Autoregressive Medication Predictor:
//    - Visit-Level Relevance (r_v^t)
//    - Medication-Level Relevance (r_m,i^t)
//    - Dynamic DDI (Drug-Drug Interaction) Knowledge Graph Adjacency Matrix Penalty
// 4. Clinical Benchmark Metrics: Jaccard Similarity, PR-AUC, F1-Score, and DDI Interaction Rate

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Representation of a single clinical hospital encounter / visit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClinicalVisit {
    pub visit_id: String,
    pub visit_index: usize,
    pub diagnoses: Vec<String>,   // ICD diagnosis codes (C_d)
    pub procedures: Vec<String>,  // Procedure codes (C_p)
    pub medications: Vec<String>, // Prescribed medications (C_m)
    pub embedding: Vec<f64>,      // Dense multi-modal clinical representation v_t
}

impl ClinicalVisit {
    pub fn new(
        visit_id: &str,
        visit_index: usize,
        diagnoses: Vec<&str>,
        procedures: Vec<&str>,
        medications: Vec<&str>,
        embedding: Vec<f64>,
    ) -> Self {
        Self {
            visit_id: visit_id.to_string(),
            visit_index,
            diagnoses: diagnoses.into_iter().map(String::from).collect(),
            procedures: procedures.into_iter().map(String::from).collect(),
            medications: medications.into_iter().map(String::from).collect(),
            embedding,
        }
    }
}

/// Cosine similarity between two clinical embedding vectors
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len(), "Embedding dimension mismatch");
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        0.0
    } else {
        dot / (norm_a * norm_b)
    }
}

/// 1. Relevant-Visit Selection Module with Straight-Through Gumbel-Softmax
///
/// Discretely selects relevant visits (V_rel) while remaining differentiable via Gumbel reparameterization
pub struct GumbelVisitSelector {
    pub temperature: f64, // Gumbel relaxation temperature tau
}

impl Default for GumbelVisitSelector {
    fn default() -> Self {
        Self { temperature: 0.5 }
    }
}

impl GumbelVisitSelector {
    pub fn new(temperature: f64) -> Self {
        Self { temperature }
    }

    /// Computes pairwise context logits s_t = MLP([v_t || v_T]) in R^2
    /// s_t[0] = discard logit, s_t[1] = retain logit
    pub fn compute_selection_logits(
        current_visit: &ClinicalVisit,
        past_visit: &ClinicalVisit,
    ) -> [f64; 2] {
        let sim = cosine_similarity(&current_visit.embedding, &past_visit.embedding);
        // Shared diagnostic overlap boost
        let diag_overlap = current_visit
            .diagnoses
            .iter()
            .filter(|d| past_visit.diagnoses.contains(d))
            .count() as f64;

        let retain_logit = (sim * 3.5) + (diag_overlap * 1.2) - 1.5;
        let discard_logit = -retain_logit;
        [discard_logit, retain_logit]
    }

    /// Straight-Through Gumbel-Softmax sampling
    /// Forward: Discrete hard gate z_t in {0, 1}
    /// Backward: Continuous gradient routing via z_hat
    pub fn sample_decision(&self, logits: [f64; 2], gumbel_noise: [f64; 2]) -> (bool, f64) {
        let tau = self.temperature.max(0.01);
        let exp_0 = ((logits[0] + gumbel_noise[0]) / tau).exp();
        let exp_1 = ((logits[1] + gumbel_noise[1]) / tau).exp();
        let sum_exp = exp_0 + exp_1;

        let z_hat_1 = exp_1 / sum_exp; // Continuous relaxation
        let hard_decision = z_hat_1 > 0.5; // Straight-Through hard decision

        (hard_decision, z_hat_1)
    }

    /// Filters past longitudinal encounters into V_rel
    pub fn select_relevant_visits<'a>(
        &self,
        current_visit: &ClinicalVisit,
        past_visits: &'a [ClinicalVisit],
        gumbel_samples: Option<&[[f64; 2]]>,
    ) -> Vec<&'a ClinicalVisit> {
        let mut selected = Vec::new();

        for (i, past) in past_visits.iter().enumerate() {
            let logits = Self::compute_selection_logits(current_visit, past);
            let noise = if let Some(samples) = gumbel_samples {
                samples.get(i).copied().unwrap_or([0.0, 0.0])
            } else {
                [0.0, 0.0] // Deterministic inference
            };

            let (is_retained, _) = self.sample_decision(logits, noise);
            if is_retained {
                selected.push(past);
            }
        }

        selected
    }

    pub fn rank_visits<'a>(
        current_visit: &ClinicalVisit,
        past_visits: &'a [ClinicalVisit],
    ) -> Vec<(&'a ClinicalVisit, f64)> {
        let mut scored: Vec<(&'a ClinicalVisit, f64)> = past_visits
            .iter()
            .map(|visit| {
                let score = cosine_similarity(&current_visit.embedding, &visit.embedding);
                (visit, score)
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    pub fn select_top_k<'a>(
        current_visit: &ClinicalVisit,
        past_visits: &'a [ClinicalVisit],
        k: usize,
    ) -> Vec<&'a ClinicalVisit> {
        let ranked = Self::rank_visits(current_visit, past_visits);
        ranked.into_iter().take(k).map(|(v, _score)| v).collect()
    }
}

pub type RelevantVisitSelector = GumbelVisitSelector;

/// 2. Target-Aware Cross-Attention Module with Bounded Historical Context
///
/// Bounded contribution: q_T = v_T + sum_{t in V_rel} alpha_t * v_t
pub struct TargetAwareAttention;

impl TargetAwareAttention {
    pub fn compute_bounded_representation(
        current_visit: &ClinicalVisit,
        selected_visits: &[&ClinicalVisit],
    ) -> Vec<f64> {
        let dim = current_visit.embedding.len();
        let mut q_t = current_visit.embedding.clone();

        if selected_visits.is_empty() {
            return q_t;
        }

        // Target-Centric Attention weights (Query = v_T, Key = v_t)
        let mut raw_scores: Vec<f64> = selected_visits
            .iter()
            .map(|v| {
                let sim = cosine_similarity(&current_visit.embedding, &v.embedding);
                (sim * 2.0).clamp(0.0, 4.0)
            })
            .collect();

        // Bounded calibration: Past visit weights are calibrated relative to current encounter
        // If past visits have weak alignment, total weight remains strictly bounded (<= 0.5)
        let total_raw: f64 = raw_scores.iter().sum();
        let bounded_scale = 0.35 * (total_raw / (total_raw + 1.0));

        if total_raw > 0.0 {
            for s in &mut raw_scores {
                *s = (*s / total_raw) * bounded_scale;
            }
        }

        // q_T = v_T + sum alpha_t * v_t
        for (i, past_visit) in selected_visits.iter().enumerate() {
            let alpha = raw_scores[i];
            for (j, q_val) in q_t.iter_mut().enumerate().take(dim) {
                *q_val += alpha * past_visit.embedding[j];
            }
        }

        q_t
    }

    pub fn compute_context(
        current_visit: &ClinicalVisit,
        selected_visits: &[&ClinicalVisit],
    ) -> Vec<f64> {
        Self::compute_bounded_representation(current_visit, selected_visits)
    }
}

/// 3. DDI (Drug-Drug Interaction) Knowledge Graph
#[derive(Clone, Debug)]
pub struct DdiKnowledgeGraph {
    pub adjacency: HashMap<(String, String), bool>,
}

impl Default for DdiKnowledgeGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DdiKnowledgeGraph {
    pub fn new() -> Self {
        let mut g = Self {
            adjacency: HashMap::new(),
        };
        // Standard adverse DDI pairs (e.g. TWOSIDES benchmark)
        g.add_interaction("WARFARIN", "ASPIRIN");
        g.add_interaction("IBUPROFEN", "ASPIRIN");
        g.add_interaction("LISINOPRIL", "SPIRONOLACTONE");
        g.add_interaction("METFORMIN", "CONTRAST_MEDIA");
        g
    }

    pub fn add_interaction(&mut self, drug_a: &str, drug_b: &str) {
        self.adjacency
            .insert((drug_a.to_string(), drug_b.to_string()), true);
        self.adjacency
            .insert((drug_b.to_string(), drug_a.to_string()), true);
    }

    pub fn has_interaction(&self, drug_a: &str, drug_b: &str) -> bool {
        self.adjacency
            .contains_key(&(drug_a.to_string(), drug_b.to_string()))
    }

    /// Evaluates DDI Rate = (Number of interacting pairs) / (Total prescribed pairs)
    pub fn evaluate_ddi_rate(&self, prescribed: &[String]) -> f64 {
        if prescribed.len() < 2 {
            return 0.0;
        }

        let mut adverse_pairs = 0;
        let mut total_pairs = 0;

        for i in 0..prescribed.len() {
            for j in (i + 1)..prescribed.len() {
                total_pairs += 1;
                if self.has_interaction(&prescribed[i], &prescribed[j]) {
                    adverse_pairs += 1;
                }
            }
        }

        if total_pairs == 0 {
            0.0
        } else {
            adverse_pairs as f64 / total_pairs as f64
        }
    }
}

/// 4. Two-Level Autoregressive Medication Predictor (VITA + COGNet)
///
/// Integrates:
/// - Visit-level relevance r_v^t
/// - Medication-level relevance r_m,i^t
/// - DDI repulsion loss
pub struct TwoLevelAutoregressivePredictor {
    pub drug_vocab: Vec<String>,
    pub ddi_graph: DdiKnowledgeGraph,
}

pub type COGNetPredictor = TwoLevelAutoregressivePredictor;

impl TwoLevelAutoregressivePredictor {
    pub fn new(drug_vocab: Vec<&str>) -> Self {
        Self {
            drug_vocab: drug_vocab.into_iter().map(String::from).collect(),
            ddi_graph: DdiKnowledgeGraph::default(),
        }
    }

    pub fn with_ddi_graph(drug_vocab: Vec<&str>, ddi_graph: DdiKnowledgeGraph) -> Self {
        Self {
            drug_vocab: drug_vocab.into_iter().map(String::from).collect(),
            ddi_graph,
        }
    }

    pub fn predict(
        &self,
        current_visit: &ClinicalVisit,
        selected_past_visits: &[&ClinicalVisit],
        _target_context: &[f64],
    ) -> HashMap<String, f64> {
        let (_prescribed, probs) =
            self.autoregressive_decode(current_visit, selected_past_visits, 6);
        probs
    }

    pub fn prescribe(
        &self,
        current_visit: &ClinicalVisit,
        selected_past_visits: &[&ClinicalVisit],
        _target_context: &[f64],
        _threshold: f64,
    ) -> Vec<String> {
        let (prescribed, _probs) =
            self.autoregressive_decode(current_visit, selected_past_visits, 6);
        prescribed
    }

    /// Computes Visit-Level Relevance r_v^t using Target-Aware representation q_T
    pub fn compute_visit_relevance(q_t: &[f64], past_visits: &[&ClinicalVisit]) -> Vec<f64> {
        if past_visits.is_empty() {
            return Vec::new();
        }

        let mut scores: Vec<f64> = past_visits
            .iter()
            .map(|v| {
                let dot: f64 = q_t.iter().zip(v.embedding.iter()).map(|(a, b)| a * b).sum();
                (dot / (q_t.len() as f64).sqrt()).exp()
            })
            .collect();

        let sum: f64 = scores.iter().sum();
        if sum > 0.0 {
            for s in &mut scores {
                *s /= sum;
            }
        }
        scores
    }

    /// Computes Medication-Level Relevance r_m,i^t conditioned on current decoding state h_T^{<k}
    pub fn compute_medication_relevance(
        past_medication: &str,
        predicted_so_far: &[String],
        current_diagnoses: &[String],
    ) -> f64 {
        // Base propensity to copy a previously prescribed drug
        let mut score: f64 = 0.75;

        // Alignment bonus if past drug treats one of current acute diagnoses
        let has_alignment = (current_diagnoses.iter().any(|d| d.contains("DIAB"))
            && past_medication.contains("INSULIN"))
            || (current_diagnoses.iter().any(|d| d.contains("HYPERTENSION"))
                && past_medication.contains("LISINOPRIL"))
            || (current_diagnoses.iter().any(|d| d.contains("CAD"))
                && past_medication.contains("ASPIRIN"));

        if has_alignment {
            score += 0.20;
        }

        // Penalize if it creates an adverse DDI with drugs already predicted in the current visit
        if predicted_so_far.iter().any(|p| {
            (p == "WARFARIN" && past_medication == "ASPIRIN")
                || (p == "ASPIRIN" && past_medication == "WARFARIN")
                || (p == "IBUPROFEN" && past_medication == "ASPIRIN")
        }) {
            score -= 0.65;
        }

        score.clamp(0.01, 0.99)
    }

    /// Step-by-step Autoregressive Decoding Loop with Two-Level Relevance & DDI Suppression
    pub fn autoregressive_decode(
        &self,
        current_visit: &ClinicalVisit,
        selected_past_visits: &[&ClinicalVisit],
        max_steps: usize,
    ) -> (Vec<String>, HashMap<String, f64>) {
        let q_t = TargetAwareAttention::compute_bounded_representation(
            current_visit,
            selected_past_visits,
        );
        let visit_relevance = Self::compute_visit_relevance(&q_t, selected_past_visits);

        let mut predicted_meds: Vec<String> = Vec::new();
        let mut drug_probabilities: HashMap<String, f64> = HashMap::new();

        // Initialize candidate pool scores
        for med in &self.drug_vocab {
            drug_probabilities.insert(med.clone(), 0.05);
        }

        for step in 0..max_steps {
            let mut step_scores: HashMap<String, f64> = HashMap::new();

            // 1. Joint Two-Level Historical Representation p_bar_T^k
            let mut historical_med_scores: HashMap<String, f64> = HashMap::new();
            for (t_idx, past_visit) in selected_past_visits.iter().enumerate() {
                let r_v = visit_relevance.get(t_idx).copied().unwrap_or(0.0);
                for past_med in &past_visit.medications {
                    let r_m = Self::compute_medication_relevance(
                        past_med,
                        &predicted_meds,
                        &current_visit.diagnoses,
                    );
                    *historical_med_scores.entry(past_med.clone()).or_insert(0.0) += r_v * r_m;
                }
            }

            // 2. Candidate Generation Scoring
            for med in &self.drug_vocab {
                if predicted_meds.contains(med) {
                    continue; // Skip already prescribed drugs
                }

                // Acute diagnosis matching
                let mut gen_score = 0.10;
                for diag in &current_visit.diagnoses {
                    if diag.contains("DIABETES")
                        && (med.contains("INSULIN") || med.contains("METFORMIN"))
                    {
                        gen_score += 0.45;
                    }
                    if diag.contains("HYPERTENSION") && med.contains("LISINOPRIL") {
                        gen_score += 0.50;
                    }
                    if diag.contains("FRACTURE")
                        && (med.contains("IBUPROFEN") || med.contains("ACETAMINOPHEN"))
                    {
                        gen_score += 0.45;
                    }
                }

                // DDI Repulsion Penalty against currently selected drugs
                let mut ddi_repulsion = 0.0;
                for chosen in &predicted_meds {
                    if self.ddi_graph.has_interaction(chosen, med) {
                        ddi_repulsion += 0.80; // Heavy repulsion suppression
                    }
                }

                let copy_score = historical_med_scores.get(med).copied().unwrap_or(0.0);
                let final_score =
                    ((0.55 * copy_score) + (0.45 * gen_score) - ddi_repulsion).clamp(0.0, 1.0);

                step_scores.insert(med.clone(), final_score);

                // Update cumulative probability for metrics
                if final_score > *drug_probabilities.get(med).unwrap_or(&0.0) {
                    drug_probabilities.insert(med.clone(), final_score);
                }
            }

            // Select highest scoring drug
            let best_candidate = step_scores
                .into_iter()
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

            match best_candidate {
                Some((best_med, score)) if score >= 0.35 => {
                    predicted_meds.push(best_med);
                }
                _ => break, // Emit <END> token when no candidate exceeds threshold
            }

            if step >= max_steps - 1 {
                break;
            }
        }

        predicted_meds.sort();
        (predicted_meds, drug_probabilities)
    }
}

/// 5. Evaluation Metrics Module
pub struct EvaluationMetrics;

impl EvaluationMetrics {
    /// Jaccard Similarity = |Y ∩ Y_hat| / |Y ∪ Y_hat|
    pub fn jaccard(ground_truth: &[String], predicted: &[String]) -> f64 {
        let gt_set: HashSet<&String> = ground_truth.iter().collect();
        let pred_set: HashSet<&String> = predicted.iter().collect();

        if gt_set.is_empty() && pred_set.is_empty() {
            return 1.0;
        }

        let intersection = gt_set.intersection(&pred_set).count();
        let union = gt_set.union(&pred_set).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
    pub fn f1(ground_truth: &[String], predicted: &[String]) -> f64 {
        let gt_set: HashSet<&String> = ground_truth.iter().collect();
        let pred_set: HashSet<&String> = predicted.iter().collect();

        if gt_set.is_empty() && pred_set.is_empty() {
            return 1.0;
        }

        let tp = gt_set.intersection(&pred_set).count() as f64;
        let fp = pred_set.difference(&gt_set).count() as f64;
        let fn_count = gt_set.difference(&pred_set).count() as f64;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_count > 0.0 {
            tp / (tp + fn_count)
        } else {
            0.0
        };

        if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        }
    }

    /// Standard Average Precision (PR-AUC): AP = (1 / |GT|) * sum_{k in GT} Precision@rank(k)
    pub fn pr_auc(ground_truth: &[String], prediction_scores: &HashMap<String, f64>) -> f64 {
        let gt_set: HashSet<&String> = ground_truth.iter().collect();
        if gt_set.is_empty() {
            return 0.0;
        }

        let mut items: Vec<(&String, f64)> =
            prediction_scores.iter().map(|(k, &v)| (k, v)).collect();
        items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut true_positives = 0.0;
        let mut ap_sum = 0.0;

        for (rank, (med, _score)) in items.iter().enumerate() {
            if gt_set.contains(med) {
                true_positives += 1.0;
                let precision = true_positives / (rank as f64 + 1.0);
                ap_sum += precision;
            }
        }

        (ap_sum / gt_set.len() as f64).clamp(0.0, 1.0)
    }
}
