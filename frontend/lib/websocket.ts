"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { WSStatus } from "@/types";

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
  return "ws://127.0.0.1:8000/ws";
}

export function getSseUrl(): string {
  if (process.env.NEXT_PUBLIC_SSE_URL) {
    return process.env.NEXT_PUBLIC_SSE_URL;
  }
  const apiBase = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");
  return `${apiBase}/api/v1/ws/sse`;
}

export const WS_URL = getWebSocketUrl();

export function useWebSocketTelemetry(onMessageReceived?: (msg: WSEventMessage) => void) {
  const [status, setStatus] = useState<WSStatus>("DISCONNECTED");
  const [lastMessage, setLastMessage] = useState<WSEventMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const wsFailures = useRef<number>(0);
  const isUnmounted = useRef(false);

  const connectSSE = useCallback(() => {
    if (isUnmounted.current) return;
    try {
      setStatus("RECONNECTING");
      const sse = new EventSource(getSseUrl());
      sseRef.current = sse;

      sse.onopen = () => {
        if (!isUnmounted.current) {
          setStatus("CONNECTED");
          console.log("[SSE] Connected to threat detection live stream (HTTP stream fallback)");
        }
      };

      sse.onmessage = (event) => {
        try {
          const msg: WSEventMessage = JSON.parse(event.data);
          setLastMessage(msg);
          if (onMessageReceived) {
            onMessageReceived(msg);
          }
        } catch (e) {
          // Non-JSON ping
        }
      };

      sse.onerror = () => {
        if (!isUnmounted.current) {
          setStatus("DISCONNECTED");
          if (sseRef.current) {
            sseRef.current.close();
            sseRef.current = null;
          }
          reconnectTimeoutRef.current = setTimeout(() => {
            connectSSE();
          }, 3000);
        }
      };
    } catch (err) {
      setStatus("DISCONNECTED");
    }
  }, [onMessageReceived]);

  const connect = useCallback(() => {
    if (isUnmounted.current) return;

    // If WebSockets have failed 3 times, switch to Server-Sent Events (SSE)
    if (wsFailures.current >= 3 && typeof window !== "undefined" && "EventSource" in window) {
      console.warn("[Telemetry] WebSocket connection unavailable; falling back to Server-Sent Events (SSE)");
      connectSSE();
      return;
    }

    try {
      setStatus((prev) => (prev === "CONNECTED" ? "CONNECTED" : "RECONNECTING"));
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isUnmounted.current) {
          wsFailures.current = 0;
          setStatus("CONNECTED");
          console.log("[WebSocket] Connected to threat detection live stream");
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg: WSEventMessage = JSON.parse(event.data);
          setLastMessage(msg);
          if (onMessageReceived) {
            onMessageReceived(msg);
          }
        } catch (e) {
          // Heartbeat pong or plain string
        }
      };

      ws.onclose = () => {
        if (!isUnmounted.current) {
          setStatus("DISCONNECTED");
          wsFailures.current += 1;
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, 2500);
        }
      };

      ws.onerror = () => {
        wsFailures.current += 1;
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      };
    } catch (err) {
      setStatus("DISCONNECTED");
      wsFailures.current += 1;
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    }
  }, [connectSSE, onMessageReceived]);

  useEffect(() => {
    isUnmounted.current = false;
    connect();

    // Periodic ping to keep WebSocket connection alive
    const pingInterval = setInterval(() => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send("ping");
      }
    }, 15000);

    return () => {
      isUnmounted.current = true;
      clearInterval(pingInterval);
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
      if (sseRef.current) sseRef.current.close();
    };
  }, [connect]);

  return { status, lastMessage };
}
