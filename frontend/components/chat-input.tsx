"use client";

import { useState, useRef, useCallback, type KeyboardEvent } from "react";

export function ChatInput({
  onSend,
  disabled,
}: {
  onSend: (message: string) => void;
  disabled: boolean;
}) {
  const [value, setValue] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSend = useCallback(() => {
    const trimmed = value.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setValue("");
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
  }, [value, disabled, onSend]);

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = () => {
    const ta = textareaRef.current;
    if (ta) {
      ta.style.height = "auto";
      ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
    }
  };

  return (
    <div className="px-4 py-3 border-t border-sp-border">
      <div className="flex items-end gap-2 bg-sp-bg rounded-lg border border-sp-border focus-within:border-sp-cyan/50 transition-colors">
        <span className="text-sp-cyan pl-3 pb-2.5 text-sm select-none">{">"}</span>
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            handleInput();
          }}
          onKeyDown={handleKeyDown}
          placeholder={
            disabled
              ? "Agent is working..."
              : "Enter command or message..."
          }
          disabled={disabled}
          rows={1}
          className="flex-1 bg-transparent text-sm text-sp-text placeholder-sp-muted py-2.5 resize-none outline-none font-mono"
        />
        <button
          onClick={handleSend}
          disabled={disabled || !value.trim()}
          className="px-3 py-2 mb-1 mr-1 text-xs font-bold uppercase tracking-wider rounded
            bg-sp-cyan/20 text-sp-cyan hover:bg-sp-cyan/30
            disabled:opacity-30 disabled:cursor-not-allowed
            transition-colors"
        >
          Send
        </button>
      </div>
    </div>
  );
}
