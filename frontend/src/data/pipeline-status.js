// What the repository actually contains today, stage by stage.
// state: 'done' (exists and has output), 'code' (code exists, not run), 'planned' (described in Readme only), 'ui' (this frontend)

export const PIPELINE = [
  { id: 'data', label: 'Dataset', detail: 'CIC-IDS2017 CSVs profiled', state: 'done', evidence: 'reports/raw_data_profile.json' },
  { id: 'prep', label: 'Preprocessing', detail: 'Cleaning, splitting, scaling', state: 'code', evidence: 'src/data/, scripts/preprocess.py' },
  { id: 'models', label: 'Detectors', detail: 'IF · LOF · Autoencoder classes', state: 'code', evidence: 'src/models/' },
  { id: 'train', label: 'Training run', detail: 'No trained model or scores yet', state: 'planned', evidence: 'profile scope: "no models were trained"' },
  { id: 'fusion', label: 'Fusion / risk engine', detail: 'Score normalisation and fusion', state: 'planned', evidence: 'Readme: MAVIS Risk Engine' },
  { id: 'ui', label: 'Dashboard', detail: 'This interface', state: 'ui', evidence: 'frontend/' },
];

export const STATE_LABEL = {
  done: 'Has output',
  code: 'Code only',
  planned: 'Not built',
  ui: 'Frontend',
};
