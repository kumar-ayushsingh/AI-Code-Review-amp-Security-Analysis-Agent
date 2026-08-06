import React, { useState } from "react";
import "./index.css";
import styles from "./App.module.css";
import HealthScore from "./components/HealthScore";
import SeverityBadges from "./components/SeverityBadges";
import FindingCard from "./components/FindingCard";
import { PR_SUMMARY } from "./data/prSummary";

const FILTER_OPTIONS = ["all", "critical", "high", "medium", "low"];

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
      stroke="url(#grad)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <defs>
        <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#a78bfa" />
          <stop offset="100%" stopColor="#60a5fa" />
        </linearGradient>
      </defs>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function WarningIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
      stroke="#fb923c" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
      stroke="#4ade80" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
      <polyline points="22 4 12 14.01 9 11.01"/>
    </svg>
  );
}

function AgentPill({ name, count }) {
  return (
    <span className={styles.agentPill}>
      <span className={styles.agentDot} />
      {name.replace("_", " ")}: <strong>{count}</strong>
    </span>
  );
}

export default function App() {
  const [filter, setFilter] = useState("all");
  const summary = PR_SUMMARY;
  const bd = summary.severity_breakdown;

  const filtered = summary.prioritized_fixes.filter(
    (f) => filter === "all" || f.severity === filter
  );

  const isHealthy = !summary.has_blocking;

  return (
    <div className={styles.app}>
      {/* ── Navbar ─────────────────────────────────────────── */}
      <nav className={styles.nav}>
        <div className={styles.navInner}>
          <div className={styles.logo}>
            <ShieldIcon />
            <span>CodeGuard</span>
          </div>
          <div className={styles.navRight}>
            <span className={styles.navTag}>Developer Portal</span>
          </div>
        </div>
      </nav>

      <main className={styles.main}>
        {/* ── Hero card: health score + overview banner ───── */}
        <div className={styles.heroCard}>
          <div className={styles.heroLeft}>
            <HealthScore breakdown={bd} />
          </div>
          <div className={styles.heroRight}>
            {/* Overview banner */}
            <div
              className={styles.banner}
              style={
                isHealthy
                  ? { borderColor: "rgba(74,222,128,0.3)", background: "rgba(74,222,128,0.05)" }
                  : summary.has_critical
                  ? { borderColor: "rgba(248,113,113,0.3)", background: "rgba(248,113,113,0.05)" }
                  : { borderColor: "rgba(251,146,60,0.3)",  background: "rgba(251,146,60,0.05)" }
              }
            >
              <div className={styles.bannerIcon}>
                {isHealthy ? <CheckIcon /> : <WarningIcon />}
              </div>
              <div>
                <div className={styles.bannerFile}>{summary.filename}</div>
                <p className={styles.bannerText}>{summary.executive_overview.replace(/`[^`]+`\s*/,"")}</p>
              </div>
            </div>

            {/* CI flags */}
            <div className={styles.flagRow}>
              <span className={`${styles.flag} ${summary.has_critical ? styles.flagRed : styles.flagGreen}`}>
                {summary.has_critical ? "⛔ has_critical" : "✅ no_critical"}
              </span>
              <span className={`${styles.flag} ${summary.has_blocking ? styles.flagOrange : styles.flagGreen}`}>
                {summary.has_blocking ? "⚠️ has_blocking" : "✅ no_blocking"}
              </span>
              {Object.entries(summary.agent_contributions).map(([agent, count]) => (
                <AgentPill key={agent} name={agent} count={count} />
              ))}
            </div>
          </div>
        </div>

        {/* ── Severity breakdown badges ───────────────────── */}
        <section className={styles.section}>
          <h2 className={styles.sectionHeading}>Severity Breakdown</h2>
          <SeverityBadges breakdown={bd} />
        </section>

        {/* ── Findings list ───────────────────────────────── */}
        <section className={styles.section}>
          <div className={styles.listHeader}>
            <h2 className={styles.sectionHeading}>
              Prioritized Findings
              <span className={styles.count}>{filtered.length} of {bd.total}</span>
            </h2>
            <div className={styles.filters} role="group" aria-label="Filter by severity">
              {FILTER_OPTIONS.map((opt) => (
                <button
                  key={opt}
                  className={`${styles.filterBtn} ${filter === opt ? styles.filterActive : ""}`}
                  onClick={() => setFilter(opt)}
                >
                  {opt === "all" ? "All" : opt.charAt(0).toUpperCase() + opt.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className={styles.empty}>No findings at this severity level.</div>
          ) : (
            <div className={styles.findingsList}>
              {filtered.map((f) => (
                <FindingCard key={`${f.rank}-${f.finding_type}-${f.line_number}`} finding={f} />
              ))}
            </div>
          )}
        </section>
      </main>

      <footer className={styles.footer}>
        <p>CodeGuard Portal · Powered by Code Analysis + Security Vulnerability + Remediation agents</p>
      </footer>
    </div>
  );
}
