// Descriptions of the detectors and the fusion step, matched to src/models/*.py and
// src/engine/engine.py. Actual hyperparameters, cut-offs and metrics are read at run time from
// the exported snapshot (engine().params, engine().cutoffs, evaluation()); the text here only
// explains what each part does.

export const MODELS = [
  {
    id: 'if',
    short: 'IF',
    name: 'Isolation Forest',
    className: 'MavisIsolationForest',
    file: 'src/models/isolation_forest.py',
    library: 'scikit-learn IsolationForest',
    idea: 'Builds random trees that split the feature space. A flow that is cut off from the rest in only a few splits is unusual. Each tree sees 75% of the benign rows and half of the features.',
    scoreName: 'Negated decision function',
    scoreFormula: 'score = −decision_function(x)',
    scoreDirection: 'Higher is more anomalous. The engine does not use sklearn’s own boundary: it ranks the score against benign flows (percentile).',
    trainingNote: 'Fitted on benign traffic only (Monday capture).',
    persistence: 'joblib',
  },
  {
    id: 'lof',
    short: 'LOF',
    name: 'Local Outlier Factor',
    className: 'MavisLOF',
    file: 'src/models/lof.py',
    library: 'scikit-learn LocalOutlierFactor (novelty=True)',
    idea: 'Compares how dense a flow’s neighbourhood is with the density around its nearest benign neighbours. A flow in a sparse pocket stands out.',
    scoreName: 'Negated decision function',
    scoreFormula: 'score = −decision_function(x)',
    scoreDirection: 'Higher is more anomalous; ranked against benign flows like the others.',
    trainingNote: 'LOF cost grows with the stored training set, so training rows above 30,000 are randomly subsampled (seed 42).',
    persistence: 'joblib (keeps the subsampled training set)',
  },
  {
    id: 'ae',
    short: 'AE',
    name: 'Deep Autoencoder',
    className: 'MavisAutoencoder',
    file: 'src/models/autoencoder.py',
    library: 'PyTorch',
    idea: 'Learns to compress and rebuild benign flows through a narrow bottleneck. Traffic it cannot rebuild well has a high reconstruction error. The per-feature error also tells the analyst which features were off.',
    scoreName: 'Reconstruction error',
    scoreFormula: 'score = mean((x − x̂)²) per flow',
    scoreDirection: 'Higher is more anomalous. MSE loss, Adam with cosine learning-rate decay.',
    trainingNote: 'Trained on benign traffic only, with a validation split.',
    persistence: 'torch state_dict',
  },
  {
    id: 'ecod',
    short: 'EC',
    name: 'ECOD',
    className: 'MavisECOD',
    file: 'src/models/ecod.py',
    library: 'NumPy (own implementation of Li et al., 2022)',
    idea: 'Estimates, for every feature, how rare a value is in benign traffic from its empirical distribution, looking at the tail the feature is skewed towards. Rare values in many features add up. No parameters to tune, and the per-feature tail scores show which features are off.',
    scoreName: 'Summed tail surprise',
    scoreFormula: 'score = max(Σ −log F_left(x_j), Σ −log F_right(x_j), Σ −log F_skew(x_j))',
    scoreDirection: 'Higher is more anomalous. Each feature’s distribution is stored as a compact quantile grid, dense in the tails.',
    trainingNote: 'Fitted on benign traffic only (Monday capture). Seconds to fit, millions of flows per minute to score.',
    persistence: 'joblib (quantile grids)',
  },
];

export const modelById = Object.fromEntries(MODELS.map((m) => [m.id, m]));

// The part of the engine that is not an anomaly detector.
export const CLASSIFIER = {
  id: 'clf',
  short: 'CLF',
  name: 'Attack classifier',
  file: 'src/engine/engine.py',
  library: 'scikit-learn HistGradientBoostingClassifier',
  idea: 'A gradient-boosted classifier recognises the attack families it was shown in labelled data. Its inputs are the scaled flow features plus the detector percentiles, so it also learns when the detectors can be trusted.',
  training: 'Benign rows are capped at 300,000. Rare families are padded with synthetic rows (SMOTE-style interpolation between same-class neighbours) up to 2,000 per class; class weights are the square root of inverse frequency.',
  settings: [['max_iter', '300'], ['learning_rate', '0.1'], ['max_leaf_nodes', '63'], ['early_stopping', 'True (10% validation)']],
};

// How the pieces fit together, in order. Used by the ML Models and Settings views.
export const FUSION_STEPS = [
  ['Score', 'Each detector scores the flow in its own units.'],
  ['Rank', 'Each score becomes a percentile of benign calibration flows, so the four share one 0 to 1 scale. A detector “votes” above its 99th benign percentile.'],
  ['Combine', 'The anomaly score is the mean of the four percentiles, ranked again against benign flows. On calibration flows the mean beat Fisher’s method, max, a mean of three without ECOD, and a mean plus a “strong single vote” rule.'],
  ['Classify', 'The classifier returns a probability for every attack family and for benign.'],
  ['Decide', 'Two paths share the alert budget. Known: attack probability above the calibrated threshold, named by the most likely family. Novel: combined anomaly percentile above its threshold, reported as “Novel”.'],
  ['Rate', 'Risk = 100 × likelihood × (0.7 + 0.3 × impact of the family). Likelihood grows with attack probability and with how deep in the benign tail the flow sits.'],
];
