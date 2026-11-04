// Clinical AI Longitudinal Medication Recommendation Module
// Author: Jeong Hoon Kim
// Architecture:
// 1. Encoder: Clinically Relevant Past Visit Selection + Target-Aware Cross-Attention (motivated by VITA, AAAI 2024)
// 2. Predictor: Copy-or-Generate Multi-Label Drug Predictor (inspired by COGNet)
// 3. Benchmarks & Metrics: Evaluates Jaccard Similarity, PR-AUC, and F1 across GAMENet, SafeDrug, and COGNet

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Representation of an individual clinical hospital encounter / visit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClinicalVisit {
    pub visit_id: String,
    pub visit_index: usize,
    pub diagnoses: Vec<String>,   // ICD-9/10 diagnosis codes (C_d)
    pub procedures: Vec<String>,  // Procedure codes (C_p)
    pub medications: Vec<String>, // Prescribed medication codes (C_m)
    pub embedding: Vec<f64>,      // Clinical dense embedding representation
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

/// Encoder 1: Relevant Past Visit Selector
/// Discards irrelevant historical noise (Bot-1) and extracts clinically pertinent past visits (Top-k)
pub struct RelevantVisitSelector;

impl RelevantVisitSelector {
    /// Ranks all longitudinal past visits by their semantic relevance to the current visit
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

        // Sort descending by relevance score
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    /// Selects Top-k most clinically relevant visits (Top-1 achieves peak Jaccard in VITA)
    pub fn select_top_k<'a>(
        current_visit: &ClinicalVisit,
        past_visits: &'a [ClinicalVisit],
        k: usize,
    ) -> Vec<&'a ClinicalVisit> {
        let ranked = Self::rank_visits(current_visit, past_visits);
        ranked.into_iter().take(k).map(|(v, _score)| v).collect()
    }
}

/// Encoder 2: Target-Aware Cross Attention
/// Aligns current clinical conditions (Query) with relevant historical contexts (Key/Value)
pub struct TargetAwareAttention;

impl TargetAwareAttention {
    pub fn compute_context(
        current_visit: &ClinicalVisit,
        selected_visits: &[&ClinicalVisit],
    ) -> Vec<f64> {
        let dim = current_visit.embedding.len();
        if selected_visits.is_empty() {
            return vec![0.0; dim];
        }

        // Compute attention weights via scaled dot-product
        let mut weights: Vec<f64> = selected_visits
            .iter()
            .map(|v| {
                let dot: f64 = current_visit
                    .embedding
                    .iter()
                    .zip(v.embedding.iter())
                    .map(|(q, k)| q * k)
                    .sum();
                (dot / (dim as f64).sqrt()).exp()
            })
            .collect();

        let sum_weights: f64 = weights.iter().sum();
        if sum_weights > 0.0 {
            for w in &mut weights {
                *w /= sum_weights;
            }
        }

        // Weighted sum of selected visit embeddings
        let mut context = vec![0.0; dim];
        for (i, v) in selected_visits.iter().enumerate() {
            let weight = weights[i];
            for (j, val) in v.embedding.iter().enumerate() {
                context[j] += weight * val;
            }
        }
        context
    }
}

/// Predictor: COGNet-Inspired Hybrid Copy-and-Generate Medication Predictor
/// Predicts multi-label medication regimen using both:
/// 1. Copy mechanism: Repeating proven effective drugs from relevant past encounters
/// 2. Generate mechanism: Synthesizing new drugs tailored to current acute diagnoses
pub struct COGNetPredictor {
    pub medication_vocab: Vec<String>,
}

impl COGNetPredictor {
    pub fn new(medication_vocab: Vec<&str>) -> Self {
        Self {
            medication_vocab: medication_vocab.into_iter().map(String::from).collect(),
        }
    }

    /// Generates medication recommendation probability distribution
    pub fn predict(
        &self,
        current_visit: &ClinicalVisit,
        selected_past_visits: &[&ClinicalVisit],
        target_context: &[f64],
    ) -> HashMap<String, f64> {
        let mut drug_scores: HashMap<String, f64> = HashMap::new();

        // Count past medications in selected visits
        let mut past_meds: HashMap<String, usize> = HashMap::new();
        for v in selected_past_visits {
            for m in &v.medications {
                *past_meds.entry(m.clone()).or_insert(0) += 1;
            }
        }

        let copy_weight = 0.50; // Balancing factor between copy and generate

        for med in &self.medication_vocab {
            // 1. Generation Score: Based on current visit acute diagnoses
            let mut gen_score = 0.10;
            for diag in &current_visit.diagnoses {
                if diag.contains("DIABETES")
                    && (med.contains("INSULIN") || med.contains("METFORMIN"))
                {
                    gen_score += 0.40;
                }
                if diag.contains("HYPERTENSION") && med.contains("LISINOPRIL") {
                    gen_score += 0.50;
                }
                if diag.contains("FRACTURE")
                    && (med.contains("IBUPROFEN") || med.contains("ACETAMINOPHEN"))
                {
                    gen_score += 0.50;
                }
            }

            // Context alignment bonus from target-aware attention
            let context_alignment = target_context.iter().take(2).sum::<f64>() * 0.15;
            gen_score += context_alignment;

            // 2. Copy Score: From clinically relevant past encounters
            let copy_score = if let Some(count) = past_meds.get(med) {
                0.35 + (0.45 * (*count as f64 / (selected_past_visits.len() as f64).max(1.0)))
            } else {
                0.0
            };

            // Hybrid probability output
            let combined = if !selected_past_visits.is_empty() && past_meds.contains_key(med) {
                (copy_weight * copy_score) + ((1.0 - copy_weight) * gen_score)
            } else {
                gen_score * 0.70
            };

            drug_scores.insert(med.clone(), combined.clamp(0.01, 0.99));
        }

        drug_scores
    }

    /// Binarizes output using decision threshold (e.g., threshold = 0.35)
    pub fn prescribe(
        &self,
        current_visit: &ClinicalVisit,
        selected_past_visits: &[&ClinicalVisit],
        target_context: &[f64],
        threshold: f64,
    ) -> Vec<String> {
        let scores = self.predict(current_visit, selected_past_visits, target_context);
        let mut prescribed: Vec<String> = scores
            .into_iter()
            .filter(|(_med, prob)| *prob >= threshold)
            .map(|(med, _)| med)
            .collect();
        prescribed.sort();
        prescribed
    }
}

/// Evaluation Metrics Module (Jaccard Similarity, PR-AUC, F1-Score)
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
