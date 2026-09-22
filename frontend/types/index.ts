export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type AlertStatus = "NEW" | "ACKNOWLEDGED" | "RESOLVED";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED";
export type ClientStatus = "ONLINE" | "OFFLINE" | "TRAINING" | "ERROR";
export type OperationalMode = "LIVE" | "TEST" | "OFFLINE";
export type WSStatus = "CONNECTED" | "RECONNECTING" | "DISCONNECTED";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  client_id: string;
  event_type: string;
  source: string;
  destination: string;
  protocol: string;
  features: Record<string, any>;
  metadata_payload: Record<string, any>;
  is_test: boolean;
  processing_status: string;
  processing_latency_ms: number;
}

export interface ExplainabilityFeature {
  feature: string;
  contribution: number;
  percentage: string;
  impact: string;
  value: number;
}

export interface DetectionExplainability {
  top_features: ExplainabilityFeature[];
  summary: string;
}

export interface Detection {
  id: number;
  event_id: string;
  prediction: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  attack_type: string;
  confidence: number;
  severity: Severity;
  model_version: string;
  processing_latency_ms: number;
  rule_matches: string[];
  explainability?: DetectionExplainability;
  created_at: string;
}

export interface Alert {
  alert_id: string;
  event_id: string;
  timestamp: string;
  client_id: string;
  attack_type: string;
  severity: Severity;
  confidence: number;
  risk_score: number;
  explanation?: string;
  explainability?: DetectionExplainability;
  model_version: string;
  status: AlertStatus;
  acknowledged_by?: string;
  acknowledged_at?: string;
  resolved_by?: string;
  resolved_at?: string;
  is_test: boolean;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  created_at: string;
  updated_at: string;
  related_alerts: string[];
  related_events: string[];
  summary?: string;
}

export interface ClientDevice {
  client_id: string;
  name: string;
  status: ClientStatus;
  last_seen: string;
  model_version: string;
  training_status: string;
  local_metrics: Record<string, any>;
  ip_address?: string;
  created_at: string;
}

export interface TrainingRound {
  round_num: number;
  clients_selected: number;
  clients_completed: number;
  local_loss?: number;
  global_loss?: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  training_time: number;
  model_version: string;
  created_at: string;
}

export interface DifferentialPrivacyMetrics {
  is_private: boolean;
  epsilon: number | null;
  delta: number;
  noise_multiplier: number;
  privacy_tier: string;
  clip_threshold?: number;
  num_rounds?: number;
  description: string;
}

export interface FederatedStatus {
  status: "ACTIVE" | "IDLE" | "TRAINING" | "ERROR";
  current_round: number;
  max_rounds: number;
  active_clients: number;
  global_model_version: string;
  differential_privacy?: DifferentialPrivacyMetrics;
  latest_metrics: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1?: number;
    algorithm?: string;
    differential_privacy?: DifferentialPrivacyMetrics;
  };
  last_aggregation?: string;
}

export interface PrivacyStatus {
  status: string;
  raw_training_data_shared: string;
  data_minimization: string;
  pii_detection: string;
  pseudonymization: string;
  audit_logging: string;
  total_privacy_transformations: number;
  redacted_fields_count: number;
  pseudonymized_fields_count: number;
  active_policy: Record<string, string>;
}

export interface PrivacyEvent {
  id: number;
  event_id: string;
  action: string;
  fields_transformed: string[];
  technique: string;
  timestamp: string;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  resource_id?: string;
  result: string;
  metadata_payload: Record<string, any>;
}

export interface SystemMetrics {
  timestamp: number;
  cpu_usage_percent: number;
  memory_usage_percent: number;
  total_events: number;
  total_alerts: number;
  active_clients: number;
  total_registered_clients: number;
  avg_processing_latency_ms: number;
  websocket_active_connections: number;
  network_health: string;
}

export interface HealthCheck {
  api: boolean;
  database: boolean;
  ml_model: boolean;
  websocket: boolean;
  federated_learning: boolean;
  subsystems: {
    api: string;
    database: string;
    threat_detection_ml: string;
    federated_learning: string;
    websocket_broadcaster: string;
    threat_intelligence_feed: string;
  };
  overall_status: string;
  mode: string;
}
