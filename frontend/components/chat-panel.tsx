"use client";

import { useRef, useEffect } from "react";
import { ChatMessageItem, StreamingMessage } from "./chat-message";
import { ChatInput } from "./chat-input";
import type { ChatMessage } from "@/lib/types";

export function ChatPanel({
  messages,
  streamingContent,
  isLoading,
  onSend,
}: {
  messages: ChatMessage[];
  streamingContent: string;
  isLoading: boolean;
  onSend: (message: string) => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, streamingContent]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-4 py-3 border-b border-sp-border flex items-center justify-between">
        <h2 className="text-sm font-bold text-sp-cyan uppercase tracking-wider">
          Agent
        </h2>
        {isLoading && (
          <span className="text-[10px] text-sp-green animate-pulse-cyan uppercase tracking-wider">
            Processing
          </span>
        )}
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto">
        {messages.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center text-sp-muted">
              <div className="text-4xl mb-4 glow-cyan">&#9678;</div>
              <p className="text-sm">SHADOWPULSE Ready</p>
              <p className="text-xs mt-1">Create a session to begin</p>
            </div>
          </div>
        )}
        {messages.map((msg) => (
          <ChatMessageItem key={msg.id} message={msg} />
        ))}
        <StreamingMessage content={streamingContent} />
      </div>

      {/* Input */}
      <ChatInput onSend={onSend} disabled={isLoading} />
    </div>
  );
}
