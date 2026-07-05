import { useEffect, useRef, useCallback, useState } from "react";
import type { WebSocketStatus } from "@/lib/websocket";

type MessageHandler = (data: unknown) => void;

interface UseWebSocketOptions {
  url: string;
  onMessage: MessageHandler;
  onStatusChange?: (status: WebSocketStatus) => void;
  reconnect?: boolean;
  maxRetries?: number;
}

export function useWebSocket({
  url,
  onMessage,
  onStatusChange,
  reconnect = true,
  maxRetries = 10,
}: UseWebSocketOptions) {
  const [status, setStatus] = useState<WebSocketStatus>("disconnected");
  const wsRef = useRef<WebSocket | null>(null);
  const retryCount = useRef(0);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setStatus("connecting");
    onStatusChange?.("connecting");

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      onStatusChange?.("connected");
      retryCount.current = 0;
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch {
        console.warn("Unparseable WS message:", event.data);
      }
    };

    ws.onerror = () => {
      setStatus("error");
      onStatusChange?.("error");
    };

    ws.onclose = () => {
      setStatus("disconnected");
      onStatusChange?.("disconnected");

      if (reconnect && retryCount.current < maxRetries) {
        const delay = Math.min(
          1000 * Math.pow(2, retryCount.current),
          30_000,
        );
        retryCount.current += 1;
        retryTimeoutRef.current = setTimeout(connect, delay);
      }
    };
  }, [url, onMessage, onStatusChange, reconnect, maxRetries]);

  const disconnect = useCallback(() => {
    if (retryTimeoutRef.current) clearTimeout(retryTimeoutRef.current);
    wsRef.current?.close();
    wsRef.current = null;
    setStatus("disconnected");
  }, []);

  const send = useCallback((data: Record<string, unknown>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return { status, send, disconnect, connect };
}
