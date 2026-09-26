"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { WSStatus } from "@/types";
import { api } from "@/lib/api";

export interface WSEventMessage {
  type: string;
  timestamp: string;
  data: any;
}

export function getWebSocketUrl(): string {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL;
  }
  if (process.env.NEXT_PUBLIC_API_URL) {
    const apiBase = process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, "");
    if (apiBase.startsWith("https://")) {
      return apiBase.replace(/^https:\/\//, "wss://") + "/ws";
    }
    if (apiBase.startsWith("http://")) {
      return apiBase.replace(/^http:\/\//, "ws://") + "/ws";
    }
  }
  if (typeof window !== "undefined") {
    // If running in browser and on standard localhost development
    if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
      return "ws://127.0.0.1:8000/ws";
    }
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${window.location.host}/ws`;
  }
  return "ws://127.0.0.1:8000/ws";
}

export function getSseUrl(): string {
  if (process.env.NEXT_PUBLIC_SSE_URL) {
    return process.env.NEXT_PUBLIC_SSE_URL;
  }
  const apiBase = (process.env.NEXT_PUBLIC_API_URL || "").replace(/\/+$/, "");
  return `${apiBase}/api/v1/ws/sse`;
}

export const WS_URL = getWebSocketUrl();

export function useWebSocketTelemetry(onMessageReceived?: (msg: WSEventMessage) => void) {
  const [status, setStatus] = useState<WSStatus>("DISCONNECTED");
  const [lastMessage, setLastMessage] = useState<WSEventMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const httpPollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const wsFailures = useRef<number>(0);
  const isUnmounted = useRef(false);

  // Cache to track already dispatched events during HTTP polling fallback
  const seenAlerts = useRef<Set<string>>(new Set());
  const seenDetections = useRef<Set<string>>(new Set());
  const seenEvents = useRef<Set<string>>(new Set());
  const initialLoadDone = useRef(false);

  // HTTP Polling Fallback when WebSocket / SSE are unavailable (e.g. Vercel Serverless)
  const pollHttpTelemetry = useCallback(async () => {
    if (isUnmounted.current) return;
    try {
      const [alertsRes, detectionsRes, eventsRes] = await Promise.all([
        api.getAlerts().catch(() => []),
        api.getDetections({ limit: 10 }).catch(() => []),
        api.getRecentEvents(10).catch(() => []),
      ]);

      if (!initialLoadDone.current) {
        // Seed seen sets so initial batch doesn't trigger mass duplicate notifications
        alertsRes.forEach((a: any) => seenAlerts.current.add(a.alert_id));
        detectionsRes.forEach((d: any) => seenDetections.current.add(d.detection_id || d.event_id));
        eventsRes.forEach((e: any) => seenEvents.current.add(e.event_id));
        initialLoadDone.current = true;
        return;
      }

      // Check for newly created alerts
      for (const alert of alertsRes) {
        if (!seenAlerts.current.has(alert.alert_id)) {
          seenAlerts.current.add(alert.alert_id);
          const msg: WSEventMessage = {
            type: "alert.created",
            timestamp: alert.timestamp || (alert as any).created_at || new Date().toISOString(),
            data: alert,
          };
          setLastMessage(msg);
          onMessageReceived?.(msg);
        }
      }

      // Check for newly created detections
      for (const det of detectionsRes) {
        const id = (det as any).detection_id || det.event_id;
        if (id && !seenDetections.current.has(id)) {
          seenDetections.current.add(id);
          const msg: WSEventMessage = {
            type: "detection.created",
            timestamp: det.created_at || (det as any).timestamp || new Date().toISOString(),
            data: det,
          };
          setLastMessage(msg);
          onMessageReceived?.(msg);
        }
      }

      // Check for newly ingested events
      for (const ev of eventsRes) {
        if (ev.event_id && !seenEvents.current.has(ev.event_id)) {
          seenEvents.current.add(ev.event_id);
          const msg: WSEventMessage = {
            type: "event.received",
            timestamp: ev.timestamp || new Date().toISOString(),
            data: ev,
          };
          setLastMessage(msg);
          onMessageReceived?.(msg);
        }
      }
    } catch (_) {
      // Backend request will retry next interval
    }
  }, [onMessageReceived]);

  const startHttpFallback = useCallback(() => {
    if (httpPollIntervalRef.current) return;
    console.log("[Telemetry] Active HTTP Polling Fallback initiated for live metrics & alerts");
    pollHttpTelemetry();
    httpPollIntervalRef.current = setInterval(pollHttpTelemetry, 3000);
  }, [pollHttpTelemetry]);

  const connectSSE = useCallback(() => {
    if (isUnmounted.current) return;
    try {
      setStatus("RECONNECTING");
      const sse = new EventSource(getSseUrl());
      sseRef.current = sse;

      sse.onopen = () => {
        if (!isUnmounted.current) {
          setStatus("CONNECTED");
          console.log("[SSE] Connected to threat detection live stream");
          if (httpPollIntervalRef.current) {
            clearInterval(httpPollIntervalRef.current);
            httpPollIntervalRef.current = null;
          }
        }
      };

      sse.onmessage = (event) => {
        try {
          const msg: WSEventMessage = JSON.parse(event.data);
          setLastMessage(msg);
          if (onMessageReceived) {
            onMessageReceived(msg);
          }
        } catch (_) {}
      };

      sse.onerror = () => {
        if (!isUnmounted.current) {
          setStatus("DISCONNECTED");
          if (sseRef.current) {
            sseRef.current.close();
            sseRef.current = null;
          }
          // On Vercel / serverless where SSE is unsupported, switch to HTTP Polling
          startHttpFallback();
        }
      };
    } catch (_) {
      setStatus("DISCONNECTED");
      startHttpFallback();
    }
  }, [onMessageReceived, startHttpFallback]);

  const connect = useCallback(() => {
    if (isUnmounted.current) return;

    // After 2 failed attempts on serverless / Vercel, immediately activate HTTP polling stream
    if (wsFailures.current >= 2) {
      startHttpFallback();
      return;
    }

    try {
      setStatus((prev) => (prev === "CONNECTED" ? "CONNECTED" : "RECONNECTING"));
      const ws = new WebSocket(getWebSocketUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isUnmounted.current) {
          wsFailures.current = 0;
          setStatus("CONNECTED");
          console.log("[WebSocket] Connected to threat detection live stream");
          if (httpPollIntervalRef.current) {
            clearInterval(httpPollIntervalRef.current);
            httpPollIntervalRef.current = null;
          }
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg: WSEventMessage = JSON.parse(event.data);
          setLastMessage(msg);
          if (onMessageReceived) {
            onMessageReceived(msg);
          }
        } catch (_) {}
      };

      ws.onclose = () => {
        if (!isUnmounted.current) {
          setStatus("DISCONNECTED");
          wsFailures.current += 1;
          if (wsFailures.current >= 2) {
            startHttpFallback();
          } else {
            reconnectTimeoutRef.current = setTimeout(connect, 2500);
          }
        }
      };

      ws.onerror = () => {
        wsFailures.current += 1;
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        } else if (wsFailures.current >= 2) {
          startHttpFallback();
        }
      };
    } catch (_) {
      setStatus("DISCONNECTED");
      wsFailures.current += 1;
      startHttpFallback();
    }
  }, [onMessageReceived, startHttpFallback]);

  useEffect(() => {
    isUnmounted.current = false;
    connect();

    // Periodic ping to keep WebSocket connection alive if active
    const pingInterval = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send("ping");
      }
    }, 15000);

    // Instant local event bridge for security tests executed in the UI
    const handleTestExecuted = (e: any) => {
      const scan = e.detail;
      if (scan && onMessageReceived) {
        const detMsg: WSEventMessage = {
          type: "detection.created",
          timestamp: scan.timestamp || new Date().toISOString(),
          data: {
            detection_id: `DET-TEST-${Date.now().toString(36)}`,
            attack_type: scan.attack_type,
            confidence: scan.confidence || 0.95,
            severity: scan.severity || "HIGH",
            timestamp: scan.timestamp || new Date().toISOString(),
            risk_score: scan.risk_score || 85,
            rule_matches: scan.rule_matches || [],
            source: scan.scenario_name || "Synthetic Injection",
            is_test: true,
          },
        };
        setLastMessage(detMsg);
        onMessageReceived(detMsg);

        if (scan.alert_created) {
          const alertMsg: WSEventMessage = {
            type: "alert.created",
            timestamp: new Date().toISOString(),
            data: {
              alert_id: `ALT-TEST-${Date.now().toString(36)}`,
              title: `Security Alert: ${scan.attack_type}`,
              severity: scan.severity || "HIGH",
              status: "NEW",
              risk_score: scan.risk_score || 85,
              created_at: new Date().toISOString(),
              is_test: true,
            },
          };
          onMessageReceived(alertMsg);
        }
      }
    };

    if (typeof window !== "undefined") {
      window.addEventListener("threat-detection:test-executed", handleTestExecuted);
    }

    return () => {
      isUnmounted.current = true;
      clearInterval(pingInterval);
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (httpPollIntervalRef.current) clearInterval(httpPollIntervalRef.current);
      if (wsRef.current) wsRef.current.close();
      if (sseRef.current) sseRef.current.close();
      if (typeof window !== "undefined") {
        window.removeEventListener("threat-detection:test-executed", handleTestExecuted);
      }
    };
  }, [connect, onMessageReceived]);

  return { status, lastMessage };
}
