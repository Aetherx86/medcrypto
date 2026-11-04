// Clinical AI Longitudinal Medication Recommendation Test Suite
// Author: Jeong Hoon Kim
// Verifies:
// 1. Target-Aware Attention & Relevant Visit Selection
// 2. COGNet Copy-or-Generate Predictor
// 3. Jaccard & PR-AUC Evaluation Metrics
// 4. Empirical validation of VITA (Top-1 relevant vs Bot-1 irrelevant noise)

use medcrypto::clinical_ai::{
    COGNetPredictor, ClinicalVisit, EvaluationMetrics, RelevantVisitSelector, TargetAwareAttention,
};

fn create_mock_ehr_trajectory() -> (ClinicalVisit, Vec<ClinicalVisit>, Vec<String>) {
    // Current encounter (Visit 3): Acute Type 2 Diabetes Complication + Hypertension
    let current_visit = ClinicalVisit::new(
        "visit-03",
        3,
        vec!["DIABETES_T2_ACUTE", "HYPERTENSION_STAGE2"],
        vec!["GLUCOSE_MONITORING", "ECG"],
        vec!["INSULIN_GLARGINE", "LISINOPRIL", "METFORMIN"],
        vec![0.92, 0.88, 0.12, 0.05], // Dense clinical embedding
    );

    // Past Visit 1: Chronic Diabetes management (Highly Relevant / Top-1)
    let past_visit_1 = ClinicalVisit::new(
        "visit-01",
        1,
        vec!["DIABETES_T2", "HYPERLIPIDEMIA"],
        vec!["HBA1C_ASSAY"],
        vec!["INSULIN_GLARGINE", "METFORMIN", "ATORVASTATIN"],
        vec![0.90, 0.85, 0.15, 0.08], // High cosine similarity with visit 3
    );

    // Past Visit 2: Minor Orthopedic Fracture (Irrelevant Noise / Bot-1)
    let past_visit_2 = ClinicalVisit::new(
        "visit-02",
        2,
        vec!["FRACTURE_CLAVICLE"],
        vec!["XRAY_CHEST", "SPLINT_IMMOBILIZATION"],
        vec!["IBUPROFEN", "ACETAMINOPHEN"],
        vec![0.05, 0.02, 0.95, 0.91], // Very low cosine similarity with visit 3
    );

    let ground_truth_meds = vec![
        "INSULIN_GLARGINE".to_string(),
        "LISINOPRIL".to_string(),
        "METFORMIN".to_string(),
    ];

    (
        current_visit,
        vec![past_visit_1, past_visit_2],
        ground_truth_meds,
    )
}

#[test]
fn test_relevant_visit_selection_ranks_correctly() {
    let (current_visit, past_visits, _) = create_mock_ehr_trajectory();

    let ranked = RelevantVisitSelector::rank_visits(&current_visit, &past_visits);

    // Top-1 must be visit-01 (Diabetes related)
    assert_eq!(ranked[0].0.visit_id, "visit-01");
    assert!(ranked[0].1 > 0.95, "Top-1 similarity should be very high");

    // Bot-1 must be visit-02 (Orthopedic noise)
    assert_eq!(ranked[1].0.visit_id, "visit-02");
    assert!(ranked[1].1 < 0.25, "Bot-1 similarity should be low");
}

#[test]
fn test_target_aware_attention_generates_valid_context() {
    let (current_visit, past_visits, _) = create_mock_ehr_trajectory();
    let top_1 = RelevantVisitSelector::select_top_k(&current_visit, &past_visits, 1);

    let context = TargetAwareAttention::compute_context(&current_visit, &top_1);

    assert_eq!(context.len(), current_visit.embedding.len());
    // Context should inherit strong diabetes features (index 0 and 1)
    assert!(context[0] > 0.5);
    assert!(context[1] > 0.5);
}

#[test]
fn test_cognet_predictor_copy_and_generate_accuracy() {
    let (current_visit, past_visits, ground_truth) = create_mock_ehr_trajectory();
    let top_1 = RelevantVisitSelector::select_top_k(&current_visit, &past_visits, 1);
    let context = TargetAwareAttention::compute_context(&current_visit, &top_1);

    let vocab = vec![
        "INSULIN_GLARGINE",
        "LISINOPRIL",
        "METFORMIN",
        "ATORVASTATIN",
        "IBUPROFEN",
        "WARFARIN",
        "ASPIRIN",
    ];
    let predictor = COGNetPredictor::new(vocab);

    let scores = predictor.predict(&current_visit, &top_1, &context);
    let prescribed = predictor.prescribe(&current_visit, &top_1, &context, 0.40);

    // Jaccard similarity must be positive and strong
    let jaccard = EvaluationMetrics::jaccard(&ground_truth, &prescribed);
    assert!(
        jaccard >= 0.40,
        "Jaccard score ({}) should meet or exceed SOTA baseline (~0.40)",
        jaccard
    );

    // PR-AUC calculation
    let pr_auc = EvaluationMetrics::pr_auc(&ground_truth, &scores);
    assert!(pr_auc >= 0.50, "PR-AUC ({}) should be robust", pr_auc);

    // F1 score
    let f1 = EvaluationMetrics::f1(&ground_truth, &prescribed);
    assert!(f1 >= 0.50, "F1 score ({}) should be robust", f1);
}

#[test]
fn test_vita_empirical_hypothesis_top1_beats_bot1() {
    // Validates VITA's core finding:
    // Using Top-1 relevant visit yields strictly superior Jaccard & PR-AUC compared to using Bot-1 irrelevant visit
    let (current_visit, past_visits, ground_truth) = create_mock_ehr_trajectory();

    let vocab = vec![
        "INSULIN_GLARGINE",
        "LISINOPRIL",
        "METFORMIN",
        "ATORVASTATIN",
        "IBUPROFEN",
        "ACETAMINOPHEN",
        "WARFARIN",
    ];
    let predictor = COGNetPredictor::new(vocab);

    // 1. Evaluation with Top-1 Relevant Visit (Diabetes context)
    let top_1 = vec![&past_visits[0]];
    let top_1_context = TargetAwareAttention::compute_context(&current_visit, &top_1);
    let top_1_scores = predictor.predict(&current_visit, &top_1, &top_1_context);
    let top_1_prescribed = predictor.prescribe(&current_visit, &top_1, &top_1_context, 0.40);
    let top_1_jaccard = EvaluationMetrics::jaccard(&ground_truth, &top_1_prescribed);
    let top_1_pr_auc = EvaluationMetrics::pr_auc(&ground_truth, &top_1_scores);

    // 2. Evaluation with Bot-1 Irrelevant Visit (Orthopedic fracture noise)
    let bot_1 = vec![&past_visits[1]];
    let bot_1_context = TargetAwareAttention::compute_context(&current_visit, &bot_1);
    let bot_1_scores = predictor.predict(&current_visit, &bot_1, &bot_1_context);
    let bot_1_prescribed = predictor.prescribe(&current_visit, &bot_1, &bot_1_context, 0.40);
    let bot_1_jaccard = EvaluationMetrics::jaccard(&ground_truth, &bot_1_prescribed);
    let bot_1_pr_auc = EvaluationMetrics::pr_auc(&ground_truth, &bot_1_scores);

    println!("VITA Empirical Validation in MedCrypto:");
    println!(
        "  Top-1 Relevant Visit: Jaccard = {:.4}, PR-AUC = {:.4}",
        top_1_jaccard, top_1_pr_auc
    );
    println!(
        "  Bot-1 Irrelevant Visit: Jaccard = {:.4}, PR-AUC = {:.4}",
        bot_1_jaccard, bot_1_pr_auc
    );

    // Assertion proving VITA theorem: Top-1 > Bot-1
    assert!(
        top_1_jaccard > bot_1_jaccard,
        "VITA hypothesis violated: Top-1 Jaccard ({:.4}) should be higher than Bot-1 ({:.4})",
        top_1_jaccard,
        bot_1_jaccard
    );
    assert!(
        top_1_pr_auc > bot_1_pr_auc,
        "VITA hypothesis violated: Top-1 PR-AUC ({:.4}) should be higher than Bot-1 ({:.4})",
        top_1_pr_auc,
        bot_1_pr_auc
    );
}
