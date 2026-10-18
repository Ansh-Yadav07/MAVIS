// The stages of the MAVIS pipeline and where each one lives in the repository.
// Every stage is built; `evidence` names the file that implements it or the report it writes.

export const PIPELINE = [
  { id: 'data', label: 'Dataset', detail: 'CIC-IDS2017 MachineLearningCSV profiled', state: 'done', evidence: 'reports/raw_data_profile.json' },
  { id: 'prep', label: 'Preprocessing', detail: 'Clean, drop constant columns, split, signed-log scale', state: 'done', evidence: 'scripts/preprocess.py' },
  { id: 'models', label: 'Detectors', detail: 'Isolation Forest, LOF and autoencoder trained on benign Monday traffic', state: 'done', evidence: 'src/models/, scripts/train_evaluate.py' },
  { id: 'fusion', label: 'Fusion and risk engine', detail: 'Percentile fusion, attack classifier, calibrated alert budget', state: 'done', evidence: 'src/engine/engine.py, scripts/build_engine.py' },
  { id: 'export', label: 'Console snapshot', detail: 'Engine output for every capture day', state: 'done', evidence: 'scripts/export_frontend.py -> frontend/data/mavis.json' },
  { id: 'ui', label: 'Dashboard', detail: 'This interface', state: 'ui', evidence: 'frontend/' },
];

export const STATE_LABEL = {
  done: 'Built',
  code: 'Code only',
  planned: 'Not built',
  ui: 'Frontend',
};
