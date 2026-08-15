"use client";

import { useEffect, useRef, useState } from "react";

const ANIMATION_MS = 600;

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined") return true;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Counts a number upward from its previous value to `value`. This is
 * docs/10-FRONTEND.md's one orchestrated motion moment — the pipeline
 * funnel's counters are the only thing on the page that animate; everything
 * else is instant. Skips straight to the final value under
 * `prefers-reduced-motion`, and never animates a decrease (counters are
 * monotonic in practice; if one ever drops, that's a fresh value, not a
 * motion cue).
 */
export function AnimatedCounter({ value }: { value: number }) {
  const [displayed, setDisplayed] = useState(0);
  const frameRef = useRef<number | null>(null);
  const fromRef = useRef(0);

  useEffect(() => {
    const from = fromRef.current;
    fromRef.current = value;

    if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);

    if (value <= from || prefersReducedMotion()) {
      setDisplayed(value);
      return;
    }

    const start = performance.now();
    const delta = value - from;

    const tick = (now: number) => {
      const elapsed = now - start;
      const t = Math.min(elapsed / ANIMATION_MS, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplayed(Math.round(from + delta * eased));
      if (t < 1) {
        frameRef.current = requestAnimationFrame(tick);
      } else {
        frameRef.current = null;
      }
    };

    frameRef.current = requestAnimationFrame(tick);

    return () => {
      if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
    };
  }, [value]);

  return <span>{displayed.toLocaleString("en-US")}</span>;
}
