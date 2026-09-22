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

export const WS_URL = getWebSocketUrl();


export function useWebSocketTelemetry(onMessageReceived?: (msg: WSEventMessage) => void) {
  const [status, setStatus] = useState<WSStatus>("DISCONNECTED");
  const [lastMessage, setLastMessage] = useState<WSEventMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const isUnmounted = useRef(false);

  const connect = useCallback(() => {
    if (isUnmounted.current) return;
    try {
      setStatus((prev) => (prev === "CONNECTED" ? "CONNECTED" : "RECONNECTING"));
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!isUnmounted.current) {
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
          // Schedule reconnect in 2.5 seconds
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, 2500);
        }
      };

      ws.onerror = () => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      };
    } catch (err) {
      setStatus("DISCONNECTED");
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    }
  }, [onMessageReceived]);

  useEffect(() => {
    isUnmounted.current = false;
    connect();

    // Periodic ping to keep alive
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
    };
  }, [connect]);

  return { status, lastMessage };
}
