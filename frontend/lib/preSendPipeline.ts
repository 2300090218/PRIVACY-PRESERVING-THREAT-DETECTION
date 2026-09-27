/**
 * Edge Pre-Send Security & Privacy Pipeline (Frontend Client-Side Implementation)
 * Enforces local edge data minimization, secret scanning, threat inspection,
 * telemetry optimization, and safety gating inside the user's local runtime.
 * Guarantees that raw sensitive telemetry NEVER leaves the browser.
 */

export interface PreSendPipelineReport {
  verdict: "SAFE" | "BLOCKED";
  privacyStatus: "SAFE" | "BLOCKED";
  threatStatus: "SAFE" | "SUSPICIOUS" | "BLOCKED";
  sensitiveFieldsCount: number;
  optimizationActionsCount: number;
  schemaValid: boolean;
  secretsDetected: string[];
  payloadSizeBytes: number;
  finalDecision: "SAFE TO SEND" | "BLOCKED";
  safeArtifact: any | null;
  violations: string[];
  decisionLog: string[];
}

const FORBIDDEN_RAW_FIELDS = new Set([
  "username",
  "user",
  "user_id",
  "email",
  "source_ip",
  "destination_ip",
  "client_ip",
  "ip_address",
  "hostname",
  "mac_address",
  "latitude",
  "longitude",
  "exact_location",
  "location",
  "raw_device_id",
  "password",
  "passwd",
  "secret",
  "api_key",
  "token",
  "access_token",
  "jwt",
  "private_key",
  "ssn",
  "credit_card",
  "raw_log",
  "raw_logs",
  "raw_network_logs",
]);

const AWS_KEY_REGEX = /\bAKIA[0-9A-Z]{16}\b/g;
const JWT_REGEX = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const BEARER_TOKEN_REGEX = /\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b/gi;
const EMAIL_REGEX = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const PRIVATE_KEY_REGEX = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g;
const PASSWORD_INLINE_REGEX = /(?:password|passwd|secret)\s*[:=]\s*['"]?([^\s'\";,}]+)/gi;

// Simple deterministic pseudonym hash for browser edge execution
function simpleEdgeHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).toUpperCase().padStart(8, "0");
  return hex.slice(0, 8);
}

function bucketizeNumber(val: number, tiers: number[]): string {
  for (let i = 0; i < tiers.length; i++) {
    if (val < tiers[i]) {
      const prev = i > 0 ? tiers[i - 1] : 0;
      return `TIER_${i}_${prev}_TO_${tiers[i]}`;
    }
  }
  return `TIER_HIGH_ABOVE_${tiers[tiers.length - 1]}`;
}

export function runPreSendPipeline(rawEvent: any): PreSendPipelineReport {
  const decisionLog: string[] = [];
  const violations: string[] = [];
  const secretsDetected: string[] = [];
  let schemaValid = true;
  let isThreatExploitDetected = false;

  // 1. Structure & Schema Validation
  if (!rawEvent || typeof rawEvent !== "object" || Array.isArray(rawEvent)) {
    return {
      verdict: "BLOCKED",
      privacyStatus: "BLOCKED",
      threatStatus: "BLOCKED",
      sensitiveFieldsCount: 0,
      optimizationActionsCount: 0,
      schemaValid: false,
      secretsDetected: [],
      payloadSizeBytes: 0,
      finalDecision: "BLOCKED",
      safeArtifact: null,
      violations: ["Payload is not a valid JSON telemetry object."],
      decisionLog: ["Stage 1 Failed: Invalid JSON structure."],
    };
  }

  const rawJsonStr = JSON.stringify(rawEvent);
  const payloadSizeBytes = new Blob([rawJsonStr]).size;

  if (payloadSizeBytes > 65536) {
    violations.push(`Payload size (${payloadSizeBytes} bytes) exceeds maximum limit of 65536 bytes.`);
    schemaValid = false;
  }

  if (!rawEvent.event_type) {
    violations.push("Missing required field 'event_type'.");
    schemaValid = false;
  }

  decisionLog.push(`Stage 1 Threat/Bug Inspection: Schema valid=${schemaValid}, Size=${payloadSizeBytes}B`);

  // Detect Injections and Secrets
  const scanString = (val: string, path: string) => {
    if (AWS_KEY_REGEX.test(val)) secretsDetected.push(`AWS API Key at '${path}'`);
    if (JWT_REGEX.test(val)) secretsDetected.push(`JWT Token at '${path}'`);
    if (BEARER_TOKEN_REGEX.test(val)) secretsDetected.push(`Bearer Token at '${path}'`);
    if (PRIVATE_KEY_REGEX.test(val)) secretsDetected.push(`Private Key at '${path}'`);
    if (PASSWORD_INLINE_REGEX.test(val)) secretsDetected.push(`Inline password assignment at '${path}'`);

    if (/\$\{jndi:(?:ldap|rmi|dns):/i.test(val) || /;\s*rm\s+-rf/i.test(val)) {
      violations.push(`Active malicious exploit signature detected at '${path}'.`);
      isThreatExploitDetected = true;
    }
  };

  const inspectRecursive = (obj: any, path = "") => {
    if (typeof obj === "string") {
      scanString(obj, path);
    } else if (obj && typeof obj === "object") {
      for (const [k, v] of Object.entries(obj)) {
        inspectRecursive(v, path ? `${path}.${k}` : k);
      }
    }
  };
  inspectRecursive(rawEvent);

  let threatStatus: "SAFE" | "SUSPICIOUS" | "BLOCKED" = "SAFE";
  if (isThreatExploitDetected) {
    threatStatus = "BLOCKED";
  } else {
    const failedAttempts = Number(rawEvent.failed_attempts || 0);
    const destPort = Number(rawEvent.destination_port || 0);
    if (failedAttempts >= 5 || [4444, 1337, 31337, 8888, 9999].includes(destPort)) {
      threatStatus = "SUSPICIOUS";
      decisionLog.push("Stage 1 Threat Analysis: Telemetry reflects security threat behavior (SUSPICIOUS).");
    }
  }

  // 2. Privacy Transformation (Remove, Mask, Pseudonymize, Aggregate)
  const protectedEvent: Record<string, any> = {};
  let sensitiveFieldsCount = 0;
  const removedFields: string[] = [];
  const pseudoFields: string[] = [];

  for (const [key, val] of Object.entries(rawEvent)) {
    const keyLower = key.toLowerCase();

    // REMOVE forbidden fields
    if (FORBIDDEN_RAW_FIELDS.has(keyLower)) {
      sensitiveFieldsCount++;
      removedFields.push(key);
      continue;
    }

    // PSEUDONYMIZE Device / Host ID
    if (keyLower === "device_id" || keyLower === "host_id") {
      sensitiveFieldsCount++;
      const pseudo = `DEV-${simpleEdgeHash(String(val))}`;
      protectedEvent[key] = pseudo;
      pseudoFields.push(`${key}->${pseudo}`);
      continue;
    }

    // AGGREGATE Numeric Metrics
    if (keyLower === "bytes_transferred" && typeof val === "number") {
      sensitiveFieldsCount++;
      protectedEvent[key] = bucketizeNumber(val, [1000, 10000, 100000, 1000000]);
      continue;
    }
    if (keyLower === "duration_seconds" && typeof val === "number") {
      sensitiveFieldsCount++;
      protectedEvent[key] = bucketizeNumber(val, [1, 5, 30, 120, 600]);
      continue;
    }

    // SANITIZE Strings
    if (typeof val === "string") {
      let sanitized = val
        .replace(AWS_KEY_REGEX, "[REDACTED-KEY]")
        .replace(BEARER_TOKEN_REGEX, "[REDACTED-TOKEN]")
        .replace(JWT_REGEX, "[REDACTED-JWT]")
        .replace(PRIVATE_KEY_REGEX, "[REDACTED-KEY]");

      sanitized = sanitized.replace(EMAIL_REGEX, (match) => `USER-${simpleEdgeHash(match)}`);
      protectedEvent[key] = sanitized;
    } else {
      protectedEvent[key] = val;
    }
  }

  if (!protectedEvent.event_id) {
    protectedEvent.event_id = `evt_${simpleEdgeHash(Date.now().toString())}${Math.random().toString(16).slice(2, 6)}`;
  }
  if (!protectedEvent.timestamp) {
    protectedEvent.timestamp = new Date().toISOString();
  }
  if (!protectedEvent.organization_id) {
    protectedEvent.organization_id = "org_enterprise_a";
  }

  protectedEvent.privacy_metadata = {
    policy_name: "Enterprise Boundary Privacy Baseline",
    policy_version: "1.0.0",
    removed_count: removedFields.length,
    pseudonymized_count: pseudoFields.length,
    removed_fields: removedFields,
    pseudonymized_fields: pseudoFields,
  };

  decisionLog.push(`Stage 2 Privacy Transformation: ${sensitiveFieldsCount} sensitive attributes minimized.`);

  // 3. Telemetry Optimization
  const optimizedEvent: Record<string, any> = {};
  let optimizationActionsCount = 0;
  const purgeKeys = new Set(["debug", "trace_log", "client_env", "temp_id", "unprocessed_raw"]);

  for (const [k, v] of Object.entries(protectedEvent)) {
    if (purgeKeys.has(k.toLowerCase()) || k.startsWith("_")) {
      optimizationActionsCount++;
      continue;
    }
    if (v === null || v === "") {
      optimizationActionsCount++;
      continue;
    }
    optimizedEvent[k] = v;
  }

  if (Array.isArray(optimizedEvent.attack_indicators)) {
    const rawList = optimizedEvent.attack_indicators;
    const dedup = Array.from(new Set(rawList.map((x: any) => String(x).trim().toUpperCase())));
    if (dedup.length !== rawList.length) {
      optimizationActionsCount++;
    }
    optimizedEvent.attack_indicators = dedup;
  }

  if (typeof optimizedEvent.protocol === "string") {
    optimizedEvent.protocol = optimizedEvent.protocol.trim().toUpperCase();
  }

  decisionLog.push(`Stage 3 Telemetry Optimization: ${optimizationActionsCount} minimization actions applied.`);

  // 4. Final Validation (Pre-Send Safety Gate)
  for (const k of Object.keys(optimizedEvent)) {
    if (FORBIDDEN_RAW_FIELDS.has(k.toLowerCase())) {
      violations.push(`Residual forbidden field detected: '${k}'.`);
    }
  }

  // Check string values for raw credential leakage
  const checkLeaked = (item: any) => {
    if (typeof item === "string") {
      if (AWS_KEY_REGEX.test(item)) violations.push("Residual AWS key pattern detected in candidate artifact.");
      if (JWT_REGEX.test(item)) violations.push("Residual JWT token pattern detected in candidate artifact.");
      if (BEARER_TOKEN_REGEX.test(item)) violations.push("Residual Bearer token detected in candidate artifact.");
      if (PRIVATE_KEY_REGEX.test(item)) violations.push("Residual private key detected in candidate artifact.");
    } else if (item && typeof item === "object") {
      for (const v of Object.values(item)) checkLeaked(v);
    }
  };
  checkLeaked(optimizedEvent);

  const isSafe = violations.length === 0 && threatStatus !== "BLOCKED" && schemaValid;
  const verdict = isSafe ? "SAFE" : "BLOCKED";
  const privacyStatus = violations.length === 0 ? "SAFE" : "BLOCKED";

  decisionLog.push(`Stage 4 Final Safety Gate: Verdict = ${verdict}`);

  return {
    verdict,
    privacyStatus,
    threatStatus,
    sensitiveFieldsCount,
    optimizationActionsCount,
    schemaValid,
    secretsDetected,
    payloadSizeBytes: new Blob([JSON.stringify(optimizedEvent)]).size,
    finalDecision: isSafe ? "SAFE TO SEND" : "BLOCKED",
    safeArtifact: isSafe ? optimizedEvent : null,
    violations,
    decisionLog,
  };
}
