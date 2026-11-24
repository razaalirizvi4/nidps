// Demo/offline fallback data, ported from the original v0 mockup. api.js serves this only when
// the real services/dashboard API is unreachable (connection refused / network error), so the UI
// is still browsable before that backend exists or while it's offline -- never on a 401 or on a
// real server error, both of which should surface normally. Delete this module once the backend
// is always expected to be present.

export const demoOverview = {
  flows_analyzed: 155322,
  intrusions_detected: 1245,
  active_blocks: 42,
};

export const demoAlerts = [
  { verdict_id: 1, time: '14:32:05', host_ip: '192.168.1.105', dst: '192.168.1.1', attack_class: 'PORT_SCAN', layers: ['L1'], confidence: '0.98', decision: 'ALERT', risk: '68' },
  { verdict_id: 2, time: '14:30:22', host_ip: '192.168.1.112', dst: '192.168.1.1', attack_class: 'BRUTE_FORCE', layers: ['L3'], confidence: '0.94', decision: 'BLOCK', risk: '91' },
  { verdict_id: 3, time: '14:28:14', host_ip: '192.168.1.120', dst: '192.168.1.1', attack_class: 'DOS_ATTACK', layers: ['L1', 'L2', 'L3'], confidence: '0.99', decision: 'BLOCK', risk: '97' },
  { verdict_id: 4, time: '14:25:48', host_ip: '45.142.212.19', dst: '10.0.0.21', attack_class: 'SSH_PROBE', layers: ['L1'], confidence: '0.89', decision: 'BLOCK', risk: '84' },
  { verdict_id: 5, time: '14:21:03', host_ip: '192.168.1.44', dst: '10.0.0.14', attack_class: 'ANOMALOUS_FLOW', layers: ['L2'], confidence: '0.76', decision: 'PASS', risk: '42' },
];

export const demoEvidence = {
  1: [{ layer: 'L1', evidence_type: 'SIGNATURE', signature_id: 2032754, score: 0.98, predicted_class: null, confidence: null }],
  2: [
    { layer: 'L1', evidence_type: 'SIGNATURE', signature_id: null, score: null, predicted_class: null, confidence: null },
    { layer: 'L3', evidence_type: 'CLASS', signature_id: null, score: null, predicted_class: 'BRUTE_FORCE', confidence: 0.94 },
  ],
  3: [{ layer: 'L1', evidence_type: 'SIGNATURE', signature_id: 2041188, score: 0.99, predicted_class: null, confidence: null }],
  4: [{ layer: 'L1', evidence_type: 'SIGNATURE', signature_id: 2019232, score: 0.89, predicted_class: null, confidence: null }],
  5: [{ layer: 'L2', evidence_type: 'ANOMALY', signature_id: null, score: 0.81, predicted_class: null, confidence: null }],
};

export const demoHosts = [
  { ip_address: '192.168.1.105', hostname: 'workstation-05', risk_score: 68, last_seen: '14:32:05' },
  { ip_address: '192.168.1.112', hostname: 'office-laptop', risk_score: 91, last_seen: '14:30:22' },
  { ip_address: '192.168.1.44', hostname: 'admin-console', risk_score: 12, last_seen: '14:21:03' },
  { ip_address: '10.0.0.21', hostname: 'gateway-node', risk_score: 31, last_seen: '14:18:44' },
];

export const demoTrafficHistory = [38, 44, 42, 51, 48, 59, 55, 64, 60, 72, 67, 78, 74, 82, 79, 91, 85, 96, 89, 100, 94, 92, 104, 99, 112, 106, 118, 111, 124, 117, 131, 123];
export const demoTrafficLabels = ['14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00', '23:00', '00:00', '01:00', '02:00', '03:00', '04:00', '05:00', '06:00', '07:00', '08:00', '09:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00'];

export const demoBlockedHosts = [
  { block_id: 1, ip_address: '192.168.1.112', hostname: 'office-laptop', attack_class: 'BRUTE_FORCE', layers: ['L3'], start_time: '14:30:22', remaining: '23m' },
  { block_id: 2, ip_address: '192.168.1.120', hostname: 'unknown-host', attack_class: 'DOS_ATTACK', layers: ['L1', 'L2', 'L3'], start_time: '14:28:14', remaining: '21m' },
  { block_id: 3, ip_address: '45.142.212.19', hostname: 'external-source', attack_class: 'SSH_PROBE', layers: ['L1'], start_time: '14:25:48', remaining: '18m' },
];

export const demoAllowlist = [
  { entry_id: 1, address: '192.168.1.1', description: 'ISP gateway', is_permanent: true, added_by: 'system' },
  { entry_id: 2, address: '192.168.1.10', description: 'NIDPS access point', is_permanent: true, added_by: 'system' },
  { entry_id: 3, address: '192.168.1.44', description: 'Administrator device', is_permanent: false, added_by: 'admin' },
];

export const demoSettingsTabs = {
  detection_layers: [
    { key: 'detection.layer1_enabled', label: 'Signature Detection (Suricata)', value: true, default: true },
    { key: 'detection.layer2_enabled', label: 'Anomaly Detection (Isolation Forest)', value: true, default: true },
    { key: 'detection.layer3_enabled', label: 'Attack Classification (RF / XGBoost)', value: true, default: true },
  ],
  thresholds: [
    { key: 'anomaly_threshold', label: 'ANOMALY DETECTION THRESHOLD', value: 0.75, default: 0.75, min_value: 0, max_value: 1 },
    { key: 'classification_confidence', label: 'CLASSIFICATION CONFIDENCE', value: 0.8, default: 0.8, min_value: 0, max_value: 1 },
    { key: 'risk.block_threshold', label: 'HOST RISK / BLOCK THRESHOLD', value: 70, default: 70, min_value: 0, max_value: 100 },
    { key: 'network.flow_timeout_s', label: 'FLOW TIMEOUT (s)', value: 60, default: 60, min_value: 10, max_value: 300 },
  ],
  prevention_and_failure: [
    { key: 'failure_mode', label: 'FAILURE MODE', value: 'FAIL-OPEN', default: 'FAIL-OPEN' },
  ],
  rules_calibration_models: [],
};

export const demoHealth = [
  { component: 'Suricata', state: 'RUNNING', detected_at: '14:32:05' },
  { component: 'Flow Extractor', state: 'RUNNING', detected_at: '14:32:05' },
  { component: 'Isolation Forest', state: 'RUNNING', detected_at: '14:32:04' },
  { component: 'RF/XGBoost Classifier', state: 'RUNNING', detected_at: '14:32:04' },
  { component: 'Decision Fusion', state: 'RUNNING', detected_at: '14:32:05' },
  { component: 'Prevention Engine', state: 'RUNNING', detected_at: '14:32:05' },
  { component: 'Watchdog', state: 'RUNNING', detected_at: '14:32:05' },
];

export const demoModels = [
  { model_type: 'RF', version: '2.4', is_active: true, deployed_at: '2026-09-28' },
  { model_type: 'XGBoost', version: '2.4', is_active: true, deployed_at: '2026-09-28' },
];
