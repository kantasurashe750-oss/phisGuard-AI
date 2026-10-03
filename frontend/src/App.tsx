import { FormEvent, useEffect, useRef, useState } from "react";
import {
  ArrowUpRight,
  Check,
  CircleHelp,
  ExternalLink,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  MessageCircle,
  Radar,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";

type Explanation = {
  feature: string;
  label: string;
  value: number;
  display_value: string;
  effect: "increases" | "reduces";
  risk_contribution: string;
};

type ScanResult = {
  url: string;
  probability: number;
  risk: { level: string; label: string; color: string };
  explanations: Explanation[];
  recommendation: string;
  features: Record<string, number>;
  scorecard: Record<string, string>;
  model_type: string;
  disclaimer: string;
};

type Message = { role: "bot" | "user"; text: string };

const api = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "");

async function request<T>(endpoint: string, body?: unknown): Promise<T> {
  const response = await fetch(`${api}${endpoint}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) {
    const detail = data.detail;
    throw new Error(typeof detail === "string" ? detail : detail?.message ?? "The request failed.");
  }
  return data as T;
}

function App() {
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<Message[]>([
    { role: "bot", text: "Hi, I’m PhishGuard AI. Paste a website URL to scan it, then ask me why it was flagged or what to do next." },
  ]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [modelStatus, setModelStatus] = useState<"loading" | "trained" | "placeholder" | "offline">("loading");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const health = await request<{ model_status: string }>("/health");
        setModelStatus(health.model_status === "trained" ? "trained" : "placeholder");
      } catch {
        setModelStatus("offline");
      }
    };
    void checkHealth();
  }, []);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function scan(target: string) {
    setBusy(true);
    setError("");
    setMessages((current) => [...current, { role: "user", text: `Scan ${target}` }, { role: "bot", text: "Scanning the URL and available page signals…" }]);
    try {
      const scanned = await request<ScanResult>("/scan", { url: target });
      setResult(scanned);
      setMessages((current) => [
        ...current.slice(0, -1),
        { role: "bot", text: `${scanned.risk.label} — ${Math.round(scanned.probability * 100)}% predicted phishing probability. ${scanned.recommendation}` },
      ]);
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "Could not complete the scan.";
      setError(text);
      setMessages((current) => [...current.slice(0, -1), { role: "bot", text }]);
      if (text.toLowerCase().includes("placeholder") || text.toLowerCase().includes("trained model")) setModelStatus("placeholder");
    } finally {
      setBusy(false);
    }
  }

  async function sendChat(text: string) {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setMessage("");
    if (/https?:\/\/|(?:^|\s)(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}/i.test(trimmed)) {
      const match = trimmed.match(/https?:\/\/[^\s<>()]+|(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>()]*)?/i);
      if (match) {
        await scan(match[0].replace(/[.,!?]+$/, ""));
        return;
      }
    }
    setMessages((current) => [...current, { role: "user", text: trimmed }]);
    setBusy(true);
    try {
      const answer = await request<{ reply: string }>("/chat", { message: trimmed, scan_result: result });
      setMessages((current) => [...current, { role: "bot", text: answer.reply }]);
    } catch (cause) {
      setMessages((current) => [...current, { role: "bot", text: cause instanceof Error ? cause.message : "The chat request failed." }]);
    } finally {
      setBusy(false);
    }
  }

  function submitScan(event: FormEvent) {
    event.preventDefault();
    if (url.trim() && !busy) void scan(url.trim());
  }

  function submitChat(event: FormEvent) {
    event.preventDefault();
    void sendChat(message);
  }

  const riskClass = result?.risk.color ?? "green";

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#" aria-label="PhishGuard AI home">
          <span className="brand-mark"><Shield size={19} strokeWidth={2.4} /></span>
          <span>phishguard<span className="brand-ai">.ai</span></span>
        </a>
        <div className="topbar-right">
          <span className={`model-pill ${modelStatus}`}>
            <span className="status-dot" />
            {modelStatus === "trained" ? "MODEL ONLINE" : modelStatus === "loading" ? "CONNECTING" : modelStatus === "offline" ? "API OFFLINE" : "MODEL PLACEHOLDER"}
          </span>
          <a className="github-link" href={`${api === "/api" ? "http://127.0.0.1:8000" : api}/docs`} target="_blank" rel="noreferrer">API docs <ArrowUpRight size={14} /></a>
        </div>
      </header>

      <main className="layout">
        <section className="intro">
          <div className="eyebrow"><span className="eyebrow-line" /> EXPLAINABLE CYBERSECURITY</div>
          <h1>Trust, but <span>verify.</span></h1>
          <p className="intro-copy">An AI security analyst that tells you what it found, why it matters, and what to do next.</p>
        </section>

        {modelStatus === "placeholder" && (
          <div className="placeholder-notice">
            <Terminal size={16} />
            <span><strong>Model not trained yet.</strong> This project is ready to train, but predictions stay disabled until a labeled dataset produces a real model. See the README to get started.</span>
          </div>
        )}
        {error && <div className="error-notice" role="alert">{error}</div>}

        <section className="scan-panel">
          <div className="scan-panel-heading">
            <div className="section-icon"><Radar size={18} /></div>
            <div><h2>Run a website check</h2><p>We’ll inspect the URL and available page signals.</p></div>
            <span className="private-label"><LockKeyhole size={12} /> ON-DEMAND SCAN</span>
          </div>
          <form className="scan-form" onSubmit={submitScan}>
            <Globe2 size={17} className="input-icon" />
            <input
              aria-label="Website URL"
              placeholder="Paste a URL, e.g. https://example.com"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              maxLength={2048}
            />
            <button className="scan-button" disabled={busy || !url.trim()} type="submit">
              {busy ? <LoaderCircle size={16} className="spin" /> : <><span>Analyze URL</span><ArrowUpRight size={15} /></>}
            </button>
          </form>
          <div className="scan-footnote"><ShieldCheck size={13} /> Scan only links you have permission to inspect. Results are estimates, not proof.</div>
        </section>

        <div className="content-grid">
          <section className="result-column" aria-live="polite">
            {result ? (
              <>
                <div className={`result-card ${riskClass}`}>
                  <div className="result-topline">
                    <div className="result-label"><span className="result-icon">{riskClass === "green" ? <ShieldCheck size={19} /> : <ShieldAlert size={19} />}</span><span>{result.risk.label}</span></div>
                    <span className="model-tag"><Sparkles size={12} /> {result.model_type.replace(/_/g, " ")}</span>
                  </div>
                  <div className="probability-row"><strong>{Math.round(result.probability * 100)}<small>%</small></strong><span>predicted phishing<br />probability</span></div>
                  <div className="probability-track"><span style={{ width: `${Math.round(result.probability * 100)}%` }} /></div>
                  <p className="result-url"><Globe2 size={13} /> {result.url}</p>
                  <p className="disclaimer">{result.disclaimer}</p>
                </div>

                <div className="card scorecard">
                  <div className="card-heading"><span className="heading-symbol"><Shield size={16} /></span><div><h3>Security scorecard</h3><p>Signals observed in this scan</p></div></div>
                  <div className="score-grid">
                    {Object.entries(result.scorecard).map(([name, status]) => (
                      <div className="score-item" key={name}><span>{name}</span><span className={`score-indicator ${status}`}><Check size={12} /></span></div>
                    ))}
                  </div>
                  <div className="score-legend"><span><i className="legend-green" /> Fewer concerning signals</span><span><i className="legend-red" /> Review this area</span></div>
                </div>

                <div className="card why-card">
                  <div className="card-heading"><span className="heading-symbol purple"><Sparkles size={16} /></span><div><h3>Why this prediction?</h3><p>Top 3 SHAP contributions to this result</p></div></div>
                  <div className="explanation-list">
                    {result.explanations.map((item, index) => (
                      <div className="explanation" key={item.feature}>
                        <span className="explanation-number">{String(index + 1).padStart(2, "0")}</span>
                        <div><strong>{item.label} <span className="feature-value">{item.display_value}</span></strong><span className={`explanation-effect ${item.effect}`}>{item.effect === "increases" ? "Increases" : "Reduces"} predicted phishing risk</span></div>
                        <span className={`effect-mark ${item.effect}`}>{item.effect === "increases" ? "↑" : "↓"}</span>
                      </div>
                    ))}
                  </div>
                  <p className="shap-note">SHAP shows which measured features influenced this model prediction. It does not establish intent or certainty.</p>
                </div>

                <div className="recommendation">
                  <div className="recommendation-icon"><ShieldCheck size={18} /></div>
                  <div><div className="recommendation-title">YOUR NEXT STEP</div><p>{result.recommendation}</p></div>
                </div>
              </>
            ) : (
              <div className="empty-result">
                <div className="empty-orbit"><div><Shield size={27} /></div><span /><i /></div>
                <h2>Your scan results<br />will appear here.</h2>
                <p>Enter a URL above to see its risk estimate, the signals behind it, and practical next steps.</p>
                <div className="empty-features"><span><Check size={13} /> Feature analysis</span><span><Check size={13} /> SHAP explanations</span><span><Check size={13} /> Actionable guidance</span></div>
              </div>
            )}
          </section>

          <aside className="chat-card">
            <div className="chat-header">
              <div className="chat-avatar"><MessageCircle size={17} /></div>
              <div><h2>Security assistant</h2><p><span className="online-dot" /> Ready to explain</p></div>
              <CircleHelp className="chat-help" size={16} />
            </div>
            <div className="chat-context">
              <span className="context-spark"><Sparkles size={13} /></span>
              {result ? <>I’m looking at <strong>{new URL(result.url).hostname}</strong>. Ask me about this scan.</> : <>Scan a URL first, or paste one here to get started.</>}
            </div>
            <div className="chat-messages">
              {messages.map((item, index) => (
                <div className={`message-row ${item.role}`} key={`${index}-${item.text.slice(0, 16)}`}>
                  {item.role === "bot" && <div className="mini-avatar"><Shield size={12} /></div>}
                  <div className="message-bubble">{item.text}</div>
                </div>
              ))}
              {busy && <div className="typing"><i /><i /><i /></div>}
              <div ref={endRef} />
            </div>
            <form className="chat-form" onSubmit={submitChat}>
              <input
                aria-label="Ask PhishGuard a question"
                placeholder="Ask about this result…"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                maxLength={2000}
              />
              <button type="submit" aria-label="Send message" disabled={busy || !message.trim()}><ArrowUpRight size={17} /></button>
            </form>
            <div className="suggestions">
              <span>TRY ASKING</span>
              {["Why?", "What should I do?"].map((prompt) => <button key={prompt} type="button" onClick={() => void sendChat(prompt)} disabled={busy}>{prompt}</button>)}
            </div>
            <div className="chat-disclaimer"><LockKeyhole size={11} /> Advice is informational. Verify sensitive requests independently.</div>
          </aside>
        </div>

        <footer className="footer"><span>PHISHGUARD AI <b>·</b> EXPLAINABLE PHISHING DETECTION &amp; DECISION ASSISTANCE</span><span><ExternalLink size={12} /> College project · Educational use</span></footer>
      </main>
    </div>
  );
}

export default App;
