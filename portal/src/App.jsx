import React, { useState } from "react";
import "./index.css";
import styles from "./App.module.css";
import HealthScore from "./components/HealthScore";
import SeverityBadges from "./components/SeverityBadges";
import FindingCard from "./components/FindingCard";
import CodeInput from "./components/CodeInput";

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
  const [summary, setSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [error, setError] = useState(null);

  const handleAnalyze = async (code, language, filename) => {
    setIsLoading(true);
    setError(null);
    try {
      const apiBase = import.meta.env.VITE_CHAT_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language, filename }),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Analysis failed: ${res.status} ${text}`);
      }
      const data = await res.json();
      setSummary(data);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const resetAnalysis = () => {
    setSummary(null);
    setError(null);
    setFilter("all");
  };

  const handleExportPDF = async () => {
    if (!summary) return;
    setIsExporting(true);
    try {
      const apiBase = import.meta.env.VITE_CHAT_API_URL || "http://localhost:8000";
      const res = await fetch(`${apiBase}/export-report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(summary),
      });
      if (!res.ok) {
        throw new Error("Failed to generate PDF");
      }
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "CodeGuard_Report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(err);
      alert("Could not export PDF: " + err.message);
    } finally {
      setIsExporting(false);
    }
  };

  // If no summary yet, show the input view (or loading/error states)
  if (!summary) {
    return (
      <div className={styles.app}>
        <nav className={styles.nav}>
          <div className={styles.navInner}>
            <div className={styles.logo}>
              <ShieldIcon />
              <span>CodeGuard</span>
            </div>
            <div className={styles.navRight}>
              {/* Developer Portal tag removed */}
            </div>
          </div>
        </nav>
        <main className={styles.main}>
          {isLoading ? (
            <div className="animate-fade-in-up" style={{ textAlign: "center", marginTop: "100px", color: "var(--text-muted)" }}>
              <div className="spinner" style={{ marginBottom: "20px" }}></div>
              <h2 style={{ fontFamily: "var(--font-heading)", color: "var(--text-primary)" }}>Analyzing Code...</h2>
              <p>Our AI agents are reviewing your code for quality smells and security vulnerabilities.</p>
            </div>
          ) : (
            <div className="animate-fade-in-up">
              {error && (
                <div style={{ maxWidth: "900px", margin: "0 auto 24px", padding: "16px", backgroundColor: "rgba(224,49,49,0.1)", border: "1px solid #e03131", borderRadius: "8px", color: "#e03131" }}>
                  <strong>Error:</strong> {error}
                </div>
              )}
              <CodeInput onAnalyze={handleAnalyze} />
            </div>
          )}
        </main>
      </div>
    );
  }

  // Dashboard View
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
            <button onClick={handleExportPDF} disabled={isExporting} style={{ background: "var(--accent-dark)", border: "none", color: "white", padding: "6px 16px", borderRadius: "20px", cursor: isExporting ? "not-allowed" : "pointer", fontWeight: "600", opacity: isExporting ? 0.7 : 1, transition: "opacity 0.2s" }}>
              {isExporting ? "Generating..." : "Download Report"}
            </button>
            <button onClick={resetAnalysis} style={{ background: "transparent", border: "1px solid var(--border)", color: "var(--text-primary)", padding: "6px 16px", borderRadius: "20px", cursor: "pointer" }}>New Analysis</button>
          </div>
        </div>
      </nav>

      <main className={styles.main}>
        {/* ── Hero card: health score + overview banner ───── */}
        <div className={`${styles.heroCard} animate-fade-in-up delay-100`}>
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
        <section className={`${styles.section} animate-fade-in-up delay-200`}>
          <h2 className={styles.sectionHeading}>Severity Breakdown</h2>
          <SeverityBadges breakdown={bd} />
        </section>

        {/* ── Findings list ───────────────────────────────── */}
        <section className={`${styles.section} animate-fade-in-up delay-300`}>
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
              {filtered.map((f, i) => (
                <div key={`${f.rank}-${f.finding_type}-${f.line_number}`} className={`animate-fade-in-up delay-${Math.min(100 + (i * 100), 500)}`}>
                  <FindingCard finding={f} />
                </div>
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
