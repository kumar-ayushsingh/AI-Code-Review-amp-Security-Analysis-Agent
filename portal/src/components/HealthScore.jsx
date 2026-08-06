import React, { useState, useEffect, useRef } from "react";
import styles from "./HealthScore.module.css";

const SEVERITY_WEIGHTS = { critical: 15, high: 8, medium: 3, low: 1 };

function getScoreColor(score) {
  if (score >= 80) return "#4ade80";
  if (score >= 60) return "#fbbf24";
  if (score >= 40) return "#fb923c";
  return "#f87171";
}

function getScoreLabel(score) {
  if (score >= 80) return "Excellent";
  if (score >= 60) return "Fair";
  if (score >= 40) return "Needs Work";
  return "Critical";
}

export default function HealthScore({ breakdown }) {
  const penalties =
    (breakdown.critical || 0) * SEVERITY_WEIGHTS.critical +
    (breakdown.high || 0) * SEVERITY_WEIGHTS.high +
    (breakdown.medium || 0) * SEVERITY_WEIGHTS.medium +
    (breakdown.low || 0) * SEVERITY_WEIGHTS.low;
  const score = Math.max(0, 100 - penalties);
  const color = getScoreColor(score);
  const label = getScoreLabel(score);

  // SVG ring params
  const R = 54;
  const CIRC = 2 * Math.PI * R;
  const [animated, setAnimated] = useState(0);
  const raf = useRef(null);

  useEffect(() => {
    let start = null;
    const duration = 1200;
    function step(ts) {
      if (!start) start = ts;
      const p = Math.min((ts - start) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setAnimated(Math.round(ease * score));
      if (p < 1) raf.current = requestAnimationFrame(step);
    }
    raf.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf.current);
  }, [score]);

  const dash = (animated / 100) * CIRC;

  return (
    <div className={styles.wrapper}>
      <div className={styles.ring} style={{ "--score-color": color }}>
        <svg width="140" height="140" viewBox="0 0 130 130" aria-hidden="true">
          <circle
            cx="65" cy="65" r={R}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"
          />
          <circle
            cx="65" cy="65" r={R}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${CIRC}`}
            strokeDashoffset={0}
            transform="rotate(-90 65 65)"
            style={{ filter: `drop-shadow(0 0 8px ${color}88)`, transition: "none" }}
          />
        </svg>
        <div className={styles.center}>
          <span className={styles.number} style={{ color }}>{animated}</span>
          <span className={styles.outOf}>/100</span>
        </div>
      </div>
      <div className={styles.meta}>
        <h2 className={styles.title}>Code Health Score</h2>
        <span className={styles.label} style={{ color, border: `1px solid ${color}44`, background: `${color}12` }}>
          {label}
        </span>
        <p className={styles.hint}>
          Weighted penalty: {SEVERITY_WEIGHTS.critical}×CRIT · {SEVERITY_WEIGHTS.high}×HIGH · {SEVERITY_WEIGHTS.medium}×MED · {SEVERITY_WEIGHTS.low}×LOW
        </p>
      </div>
    </div>
  );
}
