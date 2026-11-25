import { useEffect, useRef } from "react";

type Options = {
  enabled?: boolean;
  deps?: unknown[];
};

/**
 * setInterval that pauses while the document tab is hidden.
 */
export function useVisibleInterval(
  callback: () => void,
  ms: number,
  options: Options = {}
) {
  const { enabled = true, deps = [] } = options;
  const cbRef = useRef(callback);
  cbRef.current = callback;

  useEffect(() => {
    if (!enabled || ms <= 0) return;
    let id: ReturnType<typeof setInterval> | null = null;

    const tick = () => {
      if (document.visibilityState === "hidden") return;
      cbRef.current();
    };

    const start = () => {
      if (id != null) return;
      id = setInterval(tick, ms);
    };

    const stop = () => {
      if (id == null) return;
      clearInterval(id);
      id = null;
    };

    const onVis = () => {
      if (document.visibilityState === "hidden") {
        stop();
      } else {
        tick();
        start();
      }
    };

    if (document.visibilityState !== "hidden") {
      start();
    }
    document.addEventListener("visibilitychange", onVis);
    return () => {
      document.removeEventListener("visibilitychange", onVis);
      stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, enabled, ...deps]);
}
