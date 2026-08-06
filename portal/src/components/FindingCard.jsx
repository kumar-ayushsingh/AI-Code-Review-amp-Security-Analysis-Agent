import React, { useState } from "react";
import styles from "./FindingCard.module.css";

const SEV_CONFIG = {
  critical: { color: "#f87171", bg: "rgba(248,113,113,0.08)", label: "CRITICAL" },
  high:     { color: "#fb923c", bg: "rgba(251,146,60,0.08)",  label: "HIGH" },
  medium:   { color: "#fbbf24", bg: "rgba(251,191,36,0.07)", label: "MEDIUM" },
  low:      { color: "#60a5fa", bg: "rgba(96,165,250,0.07)",  label: "LOW" },
};

const AGENT_LABEL = {
  security_vulnerability: "Security Agent",
  code_analysis: "Code Analysis",
};

function ChevronIcon({ open }) {
  return (
    <svg
      width="16" height="16" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
      style={{ transform: open ? "rotate(180deg)" : "rotate(0)", transition: "transform 0.25s" }}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

function Explanation({ text }) {
  if (!text) return null;
  const parts = text.split("\n\n");
  const rag = parts[0]?.startsWith("[RAG Guideline]")
    ? parts[0].replace("[RAG Guideline] ", "")
    : null;
  const base = rag ? parts.slice(1).join("\n\n") : text;

  return (
    <div className={styles.explanation}>
      {rag && (
        <div className={styles.ragBox}>
          <span className={styles.ragTag}>RAG Guideline</span>
          <p className={styles.ragText}>{rag}</p>
        </div>
      )}
      {base && <p className={styles.baseText}>{base}</p>}
    </div>
  );
}

export default function FindingCard({ finding, index }) {
  const [open, setOpen] = useState(false);
  const sev = SEV_CONFIG[finding.severity] || SEV_CONFIG.low;
  const rem = finding.remediation;

  return (
    <div
      className={`${styles.card} ${open ? styles.expanded : ""}`}
      style={{ "--sev-color": sev.color, "--sev-bg": sev.bg }}
    >
      {/* Header row — always visible */}
      <button
        className={styles.header}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        id={`finding-${finding.rank}`}
      >
        <div className={styles.rank}>#{finding.rank}</div>

        <div className={styles.sevBadge} style={{ background: sev.bg, color: sev.color }}>
          {sev.label}
        </div>

        <div className={styles.meta}>
          <span className={styles.type}>{finding.finding_type.replace(/_/g, " ")}</span>
          <div className={styles.tags}>
            <span className={styles.tag}>Line {finding.line_number}</span>
            <span className={styles.tag}>{AGENT_LABEL[finding.source_agent] || finding.source_agent}</span>
          </div>
        </div>

        <div className={styles.oneliner}>{finding.one_liner}</div>

        <div className={styles.chevron}>
          <ChevronIcon open={open} />
        </div>
      </button>

      {/* Expanded body */}
      {open && (
        <div className={styles.body} role="region" aria-labelledby={`finding-${finding.rank}`}>
          {/* Fix action */}
          <div className={styles.section}>
            <h4 className={styles.sectionTitle}>
              <span className={styles.sectionIcon}>⚡</span> Fix Action
            </h4>
            <p className={styles.fixAction}>{finding.fix_action}</p>
          </div>

          {/* Principle */}
          {finding.principle && (
            <div className={styles.principleRow}>
              <span className={styles.principleIcon}>📖</span>
              <span className={styles.principleText}>{finding.principle}</span>
            </div>
          )}

          {/* Remediation */}
          {rem && (
            <>
              {/* Corrected code */}
              <div className={styles.section}>
                <h4 className={styles.sectionTitle}>
                  <span className={styles.sectionIcon}>✅</span> Corrected Code
                </h4>
                <div className={styles.codeWrapper}>
                  <div className={styles.codeDots}>
                    <span /><span /><span />
                  </div>
                  <pre className={styles.code}><code>{rem.corrected_code}</code></pre>
                </div>
              </div>

              {/* Explanation */}
              <div className={styles.section}>
                <h4 className={styles.sectionTitle}>
                  <span className={styles.sectionIcon}>💡</span> Why This Fix Works
                </h4>
                <Explanation text={rem.explanation} />
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
