import React from "react";
import styles from "./SeverityBadges.module.css";

const SEV_META = {
  critical: { label: "Critical", color: "#f87171", glow: "rgba(248,113,113,0.2)", icon: "🔴" },
  high:     { label: "High",     color: "#fb923c", glow: "rgba(251,146,60,0.2)",  icon: "🟠" },
  medium:   { label: "Medium",   color: "#fbbf24", glow: "rgba(251,191,36,0.18)", icon: "🟡" },
  low:      { label: "Low",      color: "#8b949e", glow: "rgba(139,148,158,0.18)", icon: "⚪" },
};

export default function SeverityBadges({ breakdown }) {
  return (
    <div className={styles.grid}>
      {Object.entries(SEV_META).map(([key, meta]) => {
        const count = breakdown[key] || 0;
        return (
          <div
            key={key}
            className={styles.badge}
            style={{
              "--badge-color": meta.color,
              "--badge-glow": meta.glow,
              opacity: count === 0 ? 0.4 : 1,
            }}
          >
            <div className={styles.count}>{count}</div>
            <div className={styles.row}>
              <span className={styles.dot} />
              <span className={styles.label}>{meta.label}</span>
            </div>
            <div className={styles.bar}>
              <div
                className={styles.barFill}
                style={{ width: `${Math.min(100, count * 20)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
