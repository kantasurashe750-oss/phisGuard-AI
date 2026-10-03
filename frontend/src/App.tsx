import { FormEvent, useEffect, useRef, useState } from "react";
import {
  ArrowUpRight,
  Check,
  CircleHelp,
  Copy,
  ExternalLink,
  Globe2,
  LoaderCircle,
  LockKeyhole,
  MessageCircle,
  ClipboardPaste,
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
  const [copyStatus, setCopyStatus] = useState("");
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

  async function pasteUrl() {
    setError("");
    try {
      const pasted = await navigator.clipboard.readText();
      if (!pasted.trim()) {
        setError("Your clipboard is empty. Copy a website link first.");
        return;
      }
      setUrl(pasted.trim());
    } catch {
      setError("Could not read the clipboard. Paste the link into the field instead.");
    }
  }

  async function copyScannedUrl() {
    if (!result) return;
    setCopyStatus("");
    try {
      await navigator.clipboard.writeText(result.url);
      setCopyStatus("Link copied");
    } catch {
      setCopyStatus("Could not copy link");
    }
  }

  const riskClass = result?.risk.color ?? "green";
  const riskColor = riskClass === "green" ? "#0b9a5d" : riskClass === "orange" ? "#d99815" : "#c94c43";
  const probabilityPercent = result ? Math.round(result.probability * 100) : 0;

  return (
    <div className="app-shell clear-ui">
      <header className="topbar">
        <a className="brand" href="#" aria-label="PhishGuard AI home">
          <span className="brand-mark"><Shield size={19} strokeWidth={2.4} /></span>
          <span>PhishGuard AI</span>
        </a>
        <div className="topbar-right">
          <span className={`model-pill ${modelStatus}`}>
            <span className="status-dot" />
            {modelStatus === "trained" ? "Model ready" : modelStatus === "loading" ? "Connecting…" : modelStatus === "offline" ? "API offline" : "Model not trained"}
          </span>
          <a className="github-link" href={`${api === "/api" ? "http://127.0.0.1:8000" : api}/docs`} target="_blank" rel="noreferrer">API status <ArrowUpRight size={14} /></a>
        </div>
      </header>

      <main className="layout">
        <section className="intro">
          <div className="eyebrow">PHISHING LINK CHECKER</div>
          <h1>Scan suspicious links <span>with AI.</span></h1>
          <p className="intro-copy">Check a website link and see the risk estimate, what influenced it, and what to do next.</p>
        </section>

        {modelStatus === "placeholder" && (
          <div className="placeholder-notice">
            <Terminal size={16} />
            <span><strong>The model is not trained yet.</strong> Scanning will be available after a labeled dataset is used to train it.</span>
          </div>
        )}
        {error && <div className="error-notice" role="alert">{error}</div>}

        <section className="scan-panel" aria-label="Scan a website link">
          <form className="scan-form" onSubmit={submitScan}>
            <Globe2 size={17} className="input-icon" />
            <input
              type="text"
              inputMode="url"
              aria-label="Website URL"
              placeholder="Example: www.example.com"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              maxLength={2048}
            />
            <div className="scan-actions">
              <button className="paste-button" disabled={busy} onClick={() => void pasteUrl()} type="button">
                <ClipboardPaste size={15} /><span>Paste</span>
              </button>
              <button className="scan-button" disabled={busy || !url.trim()} type="submit">
                {busy ? <><LoaderCircle size={16} className="spin" /><span>Scanning…</span></> : <><span>Scan link</span><ArrowUpRight size={15} /></>}
              </button>
            </div>
          </form>
          <div className="scan-footnote"><ShieldCheck size={13} /> Only check links you’re allowed to inspect. Results are estimates, not proof.</div>
        </section>

        {!result && !busy && (
          <section className="first-steps" aria-label="How the checker works">
            <h2>What you’ll get</h2>
            <div className="steps-grid">
              <div><span>1</span><p><strong>Risk estimate</strong>See the model’s result.</p></div>
              <div><span>2</span><p><strong>Why it was flagged</strong>Review the signals detected.</p></div>
              <div><span>3</span><p><strong>What to do next</strong>Get practical safety advice.</p></div>
            </div>
          </section>
        )}

        {busy && (
          <div className="loading-card" role="status">
            <LoaderCircle size={19} className="spin" />
            <div><strong>Checking this link…</strong><span>This can take a few seconds while website signals are checked.</span></div>
          </div>
        )}

        {result && <div className="content-grid">
          <section className="result-column" aria-live="polite">
            <div className={`result-card ${riskClass}`}>
              <div className="result-topline">
                <div className="result-label"><span className="result-icon">{riskClass === "green" ? <ShieldCheck size={21} /> : <ShieldAlert size={21} />}</span><span>{result.risk.label}</span><span className="estimate-badge">Model estimate</span></div>
                <span className="model-tag"><Sparkles size={13} /> {result.model_type.replace(/_/g, " ")}</span>
              </div>
              <div className="probability-overview">
                <div
                  className="probability-ring"
                  role="img"
                  aria-label={`${probabilityPercent}% predicted phishing probability`}
                  style={{ background: `conic-gradient(${riskColor} ${probabilityPercent}%, #e4ebe6 ${probabilityPercent}% 100%)` }}
                >
                  <div><strong>{probabilityPercent}<small>%</small></strong><span>phishing probability</span></div>
                </div>
                <div className="probability-copy">
                  <h2>Risk estimate</h2>
                  <p>Predicted phishing probability</p>
                  <span>Based on the URL signals the model learned from.</span>
                </div>
              </div>
              <div className="result-url-row">
                <p className="result-url"><Globe2 size={14} /> {result.url}</p>
                <button className="copy-button" onClick={() => void copyScannedUrl()} type="button" aria-label="Copy scanned URL" title="Copy scanned URL"><Copy size={15} /><span>{copyStatus || "Copy link"}</span></button>
              </div>
              <p className="disclaimer">{result.disclaimer}</p>
            </div>

            <div className="card why-card">
              <div className="card-heading"><span className="heading-symbol purple"><Sparkles size={17} /></span><div><h3>Why this result?</h3><p>These are the strongest URL signals that influenced the model.</p></div></div>
              <div className="explanation-list">
                {result.explanations.map((item, index) => (
                  <div className="explanation" key={item.feature}>
                    <span className="explanation-number">{String(index + 1).padStart(2, "0")}</span>
                    <div><strong>{item.label}</strong><span className="feature-value">Observed: {item.display_value}</span></div>
                    <span className={`effect-badge ${item.effect}`}>{item.effect === "increases" ? "Raises risk" : "Lowers risk"}</span>
                  </div>
                ))}
              </div>
              <p className="shap-note">These signals explain the model’s estimate. They do not prove that a site is safe or malicious.</p>
            </div>

            <div className={`recommendation ${riskClass}`}>
              <div className="recommendation-icon"><ShieldCheck size={20} /></div>
              <div><div className="recommendation-title">WHAT SHOULD I DO?</div><p>{result.recommendation}</p></div>
            </div>

            <details className="card scorecard">
              <summary className="card-heading"><span className="heading-symbol"><Shield size={16} /></span><div><h3>Technical signal summary</h3><p>Optional details from this scan</p></div></summary>
              <div className="score-grid">
                {Object.entries(result.scorecard).map(([name, status]) => (
                  <div className="score-item" key={name}><span>{name}</span><span className={`score-indicator ${status}`} aria-label={status}><Check size={12} /></span></div>
                ))}
              </div>
              <div className="score-legend"><span><i className="legend-green" /> Fewer concerning signals</span><span><i className="legend-red" /> Review this area</span></div>
            </details>
          </section>

          <aside className="chat-card">
            <div className="chat-header">
              <div className="chat-avatar"><MessageCircle size={18} /></div>
              <div><h2>Ask about this result</h2><p><span className="online-dot" /> Assistant ready</p></div>
              <CircleHelp className="chat-help" size={17} />
            </div>
            <div className="chat-context">
              <span className="context-spark"><Sparkles size={14} /></span>
              <span>Questions about <strong>{new URL(result.url).hostname}</strong>? Ask below.</span>
            </div>
            <div className="chat-messages" aria-live="polite">
              {messages.map((item, index) => (
                <div className={`message-row ${item.role}`} key={`${index}-${item.text.slice(0, 16)}`}>
                  {item.role === "bot" && <div className="mini-avatar"><Shield size={12} /></div>}
                  <div className="message-bubble">{item.text}</div>
                </div>
              ))}
              {busy && <div className="typing" role="status"><i /><i /><i /></div>}
              <div ref={endRef} />
            </div>
            <form className="chat-form" onSubmit={submitChat}>
              <input
                aria-label="Ask PhishGuard a question"
                placeholder="Ask a question…"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                maxLength={2000}
              />
              <button type="submit" aria-label="Send message" disabled={busy || !message.trim()}><ArrowUpRight size={17} /></button>
            </form>
            <div className="suggestions">
              {["Why this result?", "What should I do?"].map((prompt) => <button key={prompt} type="button" onClick={() => void sendChat(prompt)} disabled={busy}>{prompt}</button>)}
            </div>
            <div className="chat-disclaimer"><LockKeyhole size={12} /> Advice is informational. Verify independently.</div>
          </aside>
        </div>}

        <footer className="footer"><span>PHISHGUARD AI <b>·</b> EXPLAINABLE PHISHING GUIDANCE</span><span><ExternalLink size={12} /> College project · Educational use</span></footer>
      </main>
    </div>
  );
}

export default App;
