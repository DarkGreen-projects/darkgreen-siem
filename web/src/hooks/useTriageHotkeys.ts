import { useEffect, useRef } from "react";

export type TriageHotkeyHandlers = {
  onNext?: () => void;
  onPrev?: () => void;
  onAck?: () => void;
  onInProgress?: () => void;
  onClose?: () => void;
  onPivot?: () => void;
  onHelp?: () => void;
  enabled?: boolean;
};

function isTypingTarget(el: EventTarget | null): boolean {
  if (!(el instanceof HTMLElement)) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  return el.isContentEditable;
}

export function useTriageHotkeys(handlers: TriageHotkeyHandlers) {
  const ref = useRef(handlers);
  ref.current = handlers;
  const enabled = handlers.enabled !== false;

  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;
      const h = ref.current;
      const key = e.key;
      if (key === "j" || key === "J") {
        e.preventDefault();
        h.onNext?.();
      } else if (key === "k" || key === "K") {
        e.preventDefault();
        h.onPrev?.();
      } else if (key === "a" || key === "A") {
        e.preventDefault();
        h.onAck?.();
      } else if (key === "i" || key === "I") {
        e.preventDefault();
        h.onInProgress?.();
      } else if (key === "c" || key === "C") {
        e.preventDefault();
        h.onClose?.();
      } else if (key === "/") {
        e.preventDefault();
        h.onPivot?.();
      } else if (key === "?") {
        e.preventDefault();
        h.onHelp?.();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [enabled]);
}

export const TRIAGE_HOTKEY_HELP = [
  { key: "j / k", desc: "prossimo / precedente in coda" },
  { key: "a", desc: "ack" },
  { key: "i", desc: "in corso" },
  { key: "c", desc: "chiudi (dialog disposition)" },
  { key: "/", desc: "pivot ricerca su entity" },
  { key: "?", desc: "mostra/nascondi aiuto" },
];
