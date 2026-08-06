import React, { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import styles from "./FindingCard.module.css";

const SEV_CONFIG = {
  critical: { color: "#f87171", bg: "rgba(248,113,113,0.1)" },
  high:     { color: "#fb923c", bg: "rgba(251,146,60,0.1)" },
  medium:   { color: "#fbbf24", bg: "rgba(251,191,36,0.1)" },
  low:      { color: "#8b949e", bg: "rgba(139,148,158,0.1)" },
};

const AGENT_LABEL = {
  security_vulnerability: "Security Agent",
  code_analysis: "Code Analysis Agent",
};

// SVG icons to make it look like a developer tool
function BotIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className={styles.botIcon}
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="10" rx="2" />
      <circle cx="12" cy="5" r="2" />
      <path d="M12 7v4" />
      <line x1="8" y1="16" x2="8" y2="16" />
      <line x1="16" y1="16" x2="16" y2="16" />
    </svg>
  );
}

function ChevronIcon({ open }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
      style={{ transform: open ? "rotate(180deg)" : "rotate(0)", transition: "transform 0.2s" }}>
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
          <strong>Guideline Ref:</strong> {rag}
        </div>
      )}
      {base && <p className={styles.baseText}>{base}</p>}
    </div>
  );
}

export default function FindingCard({ finding }) {
  const [open, setOpen] = useState(true);
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState([]);
  const [isChatLoading, setIsChatLoading] = useState(false);

  const sev = SEV_CONFIG[finding.severity] || SEV_CONFIG.low;
  const rem = finding.remediation;
  const language = "python";

  const handleChatSubmit = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userMessage = chatInput.trim();
    setChatInput("");
    setChatHistory(prev => [...prev, { role: "user", text: userMessage }]);
    setIsChatLoading(true);

    try {
      const response = await fetch("http://localhost:8000/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage,
          finding_context: finding
        })
      });

      if (!response.ok) throw new Error("Network response was not ok");
      
      const data = await response.json();
      setChatHistory(prev => [...prev, { role: "bot", text: data.response }]);
    } catch (error) {
      console.error("Chat error:", error);
      setChatHistory(prev => [...prev, { role: "bot", text: "Sorry, I couldn't reach the chat server. Is it running on port 8000?" }]);
    } finally {
      setIsChatLoading(false);
    }
  };

  return (
    <div className={styles.threadContainer}>
      <div className={styles.threadLine} />
      <div className={styles.commentBox}>
        {/* Comment Header (GitHub style) */}
        <div className={styles.header} onClick={() => setOpen(!open)}>
          <div className={styles.headerLeft}>
            <BotIcon />
            <span className={styles.authorName}>CodeGuard Bot</span>
            <span className={styles.headerMuted}>left a comment on</span>
            <span className={styles.lineRef}>Line {finding.line_number}</span>
          </div>
          <div className={styles.headerRight}>
            <span className={styles.sevBadge} style={{ color: sev.color, borderColor: sev.color, background: sev.bg }}>
              {finding.severity.toUpperCase()}
            </span>
            <span className={styles.findingType}>{finding.finding_type}</span>
            <div className={styles.chevronWrap}>
              <ChevronIcon open={open} />
            </div>
          </div>
        </div>

        {/* Comment Body */}
        {open && (
          <div className={styles.body}>
            <p className={styles.issueText}>
              <strong>Issue:</strong> {finding.one_liner}
            </p>
            <p className={styles.fixActionText}>
              <strong>Recommendation:</strong> {finding.fix_action}
            </p>

            {finding.principle && (
              <p className={styles.principleText}>
                <strong>Principle:</strong> {finding.principle}
              </p>
            )}

            {rem && (
              <>
                <div className={styles.markdownBody}>
                  <Explanation text={rem.explanation} />
                </div>
                
                {/* Syntax Highlighted Code Block */}
                <div className={styles.codeBlockContainer}>
                  <div className={styles.codeBlockHeader}>Suggested Fix</div>
                  <SyntaxHighlighter 
                    language={language} 
                    style={vscDarkPlus}
                    customStyle={{ margin: 0, borderRadius: '0 0 6px 6px', fontSize: '0.85rem' }}
                    showLineNumbers={true}
                  >
                    {rem.corrected_code}
                  </SyntaxHighlighter>
                </div>
              </>
            )}
            
            {/* Chat Assistant Panel */}
            <div className={styles.chatPanel}>
              <div className={styles.chatHeader}>
                <BotIcon /> Ask CodeGuard Assistant
              </div>
              
              <div className={styles.chatHistory}>
                {chatHistory.map((msg, i) => (
                  <div key={i} className={`${styles.chatMsg} ${msg.role === 'user' ? styles.chatMsgUser : styles.chatMsgBot}`}>
                    {msg.role === 'bot' && <div className={styles.botAvatar}>🤖</div>}
                    <div className={styles.chatBubble}>
                      {msg.role === 'bot' ? (
                        <div className={styles.markdownBody}>
                          <Explanation text={msg.text} />
                        </div>
                      ) : (
                        msg.text
                      )}
                    </div>
                  </div>
                ))}
                {isChatLoading && (
                  <div className={`${styles.chatMsg} ${styles.chatMsgBot}`}>
                    <div className={styles.botAvatar}>🤖</div>
                    <div className={styles.chatBubble}>
                      <span className={styles.typingIndicator}>...</span>
                    </div>
                  </div>
                )}
              </div>
              
              <form onSubmit={handleChatSubmit} className={styles.chatForm}>
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="e.g. Why is this a problem? or How do I fix it?"
                  className={styles.chatInput}
                  disabled={isChatLoading}
                />
                <button type="submit" className={styles.chatSubmit} disabled={isChatLoading || !chatInput.trim()}>
                  Send
                </button>
              </form>
            </div>
            
          </div>
        )}
      </div>
    </div>
  );
}
