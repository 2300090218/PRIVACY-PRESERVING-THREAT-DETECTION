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

export interface Organization {
  id: number;
  org_id: string;
  name: string;
  status: string;
  contact_email?: string;
  created_at: string;
  active_agents: number;
  total_events: number;
  total_detections: number;
  location?: string;
  is_demo?: boolean;
  demo_status?: string;
  security_status?: string;
  record_counts?: {
    students?: number;
    faculty?: number;
    it_staff?: number;
    security_staff?: number;
    administrators?: number;
    security_agents?: number;
    total_records?: number;
  };
}

export interface SyntheticPersonRecord {
  record_id: string;
  organization_id: string;
  role: string;
  pseudonym: string;
  department?: string;
  campus?: string;
  status: string;
  is_synthetic: boolean;
}

export interface AgentDevice {
  id: number;
  agent_id: string;
  organization_id: string;
  name: string;
  status: string;
  version: string;
  last_seen: string;
  created_at: string;
}

export interface PrivacyPolicyItem {
  policy_id: string;
  organization_id: string;
  field_name: string;
  action: "ALLOW" | "REMOVE" | "MASK" | "PSEUDONYMIZE" | "AGGREGATE";
  parameters: Record<string, any>;
  is_active: boolean;
  version: string;
}

export interface RealPrivacyMetrics {
  processed_events: number;
  protected_events: number;
  removed_fields: number;
  masked_fields: number;
  pseudonymized_fields: number;
  privacy_violations: number;
  transmission_failures: number;
  active_policies_count: number;
  privacy_guarantee: string;
  zero_raw_retention: boolean;
}

export interface SystemHealthV1 {
  status: string;
  timestamp: string;
  api: Record<string, any>;
  database: Record<string, any>;
  websocket: Record<string, any>;
  agents: Record<string, any>;
  ml_model: Record<string, any>;
  queue: Record<string, any>;
}

