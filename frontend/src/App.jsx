import { useState, useEffect } from 'react';
import { checkUrl, getAnalytics, getRecentScans, getSampleUrls } from './api';

/* ============================================================
   SHIELD ICON COMPONENT
   ============================================================ */
function ShieldIcon({ tier, size = 48 }) {
  const colors = {
    SAFE: '#10b981',
    SUSPICIOUS: '#f59e0b',
    PHISHING: '#ef4444',
    DEFAULT: '#60a5fa',
  };
  const color = colors[tier] || colors.DEFAULT;

  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path
        d="M12 2L4 6V12C4 16.42 7.4 20.44 12 22C16.6 20.44 20 16.42 20 12V6L12 2Z"
        fill={color}
        fillOpacity="0.2"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {tier === 'SAFE' && (
        <path d="M9 12L11 14L15 10" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      )}
      {tier === 'SUSPICIOUS' && (
        <>
          <path d="M12 9V13" stroke={color} strokeWidth="2" strokeLinecap="round" />
          <circle cx="12" cy="16" r="1" fill={color} />
        </>
      )}
      {tier === 'PHISHING' && (
        <>
          <path d="M9 9L15 15" stroke={color} strokeWidth="2" strokeLinecap="round" />
          <path d="M15 9L9 15" stroke={color} strokeWidth="2" strokeLinecap="round" />
        </>
      )}
    </svg>
  );
}

/* ============================================================
   RISK METER COMPONENT
   ============================================================ */
function RiskMeter({ score, tier }) {
  const glowClass = tier === 'SAFE' ? 'glow-safe' : tier === 'SUSPICIOUS' ? 'glow-suspicious' : 'glow-phishing';
  const tierColor = tier === 'SAFE' ? 'text-safe' : tier === 'SUSPICIOUS' ? 'text-suspicious' : 'text-phishing';

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(148,163,184,0.1)" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="42" fill="none"
            stroke={tier === 'SAFE' ? '#10b981' : tier === 'SUSPICIOUS' ? '#f59e0b' : '#ef4444'}
            strokeWidth="8"
            strokeDasharray={`${(score / 100) * 264} 264`}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${tierColor}`}>{Math.round(score)}</span>
          <span className="text-xs text-slate-400">/ 100</span>
        </div>
      </div>
      <div className={`px-4 py-1.5 rounded-full text-sm font-semibold ${
        tier === 'SAFE' ? 'bg-safe/20 text-safe border border-safe/30' :
        tier === 'SUSPICIOUS' ? 'bg-suspicious/20 text-suspicious border border-suspicious/30' :
        'bg-phishing/20 text-phishing border border-phishing/30'
      }`}>
        {tier}
      </div>
    </div>
  );
}

/* ============================================================
   REASON CARD COMPONENT
   ============================================================ */
function ReasonCard({ reason, lang }) {
  const badgeClass = `badge-${reason.severity.toLowerCase()}`;
  const message = lang === 'hi' && reason.message_hi ? reason.message_hi : reason.message;

  return (
    <div className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
      <span className={`px-2 py-0.5 rounded text-xs font-medium shrink-0 ${badgeClass}`}>
        {reason.severity}
      </span>
      <div>
        <p className="text-sm text-slate-200">{message}</p>
        <p className="text-xs text-slate-500 mt-0.5 font-mono">{reason.code}</p>
      </div>
    </div>
  );
}

/* ============================================================
   RESULT CARD COMPONENT
   ============================================================ */
function ResultCard({ result, lang }) {
  if (!result) return null;

  const glowClass = result.risk_tier === 'SAFE' ? 'glow-safe' :
    result.risk_tier === 'SUSPICIOUS' ? 'glow-suspicious' : 'glow-phishing';

  const verdict = lang === 'hi' && result.verdict_hi ? result.verdict_hi : result.verdict;
  const actionMsg = lang === 'hi' && result.action?.message_hi ? result.action.message_hi : result.action?.message;

  return (
    <div className={`glass-card p-6 ${glowClass} transition-all duration-500`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <ShieldIcon tier={result.risk_tier} size={40} />
          <div>
            <h3 className="text-lg font-semibold text-white">Scan Result</h3>
            <p className="text-xs text-slate-400">ID: {result.scan_id} • {result.model_used}</p>
          </div>
        </div>
        {result.cached && (
          <span className="px-2 py-1 bg-brand-500/20 text-brand-300 text-xs rounded-full border border-brand-500/30">
            Cached
          </span>
        )}
      </div>

      {/* URL display */}
      <div className="mb-6 p-3 rounded-lg bg-slate-900/60 border border-slate-700/40">
        <p className="text-xs text-slate-500 mb-1">Scanned URL</p>
        <p className="text-sm text-slate-200 break-all font-mono">{result.url}</p>
        {result.resolved_url && result.resolved_url !== result.url && (
          <>
            <p className="text-xs text-slate-500 mt-2 mb-1">Resolved to</p>
            <p className="text-sm text-slate-300 break-all font-mono">{result.resolved_url}</p>
          </>
        )}
      </div>

      {/* Score + Verdict */}
      <div className="flex flex-col md:flex-row items-center gap-6 mb-6">
        <RiskMeter score={result.risk_score} tier={result.risk_tier} />
        <div className="flex-1 text-center md:text-left">
          <p className="text-slate-200 text-sm leading-relaxed mb-3">{verdict}</p>
          <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${
            result.action?.block
              ? 'bg-phishing/20 text-phishing border border-phishing/30'
              : result.action?.warn
              ? 'bg-suspicious/20 text-suspicious border border-suspicious/30'
              : 'bg-safe/20 text-safe border border-safe/30'
          }`}>
            {result.action?.block ? '🚫' : result.action?.warn ? '⚠️' : '✅'} {actionMsg}
          </div>
        </div>
      </div>

      {/* Risk bar */}
      <div className="mb-6">
        <div className="flex justify-between text-xs text-slate-500 mb-1">
          <span>Safe</span><span>Suspicious</span><span>Phishing</span>
        </div>
        <div className="h-2.5 rounded-full risk-meter-bg overflow-hidden relative">
          <div
            className="absolute top-0 h-full w-1 bg-white rounded-full shadow-lg transition-all duration-1000"
            style={{ left: `${result.risk_score}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-slate-600 mt-1">
          <span>0</span><span>34</span><span>69</span><span>100</span>
        </div>
      </div>

      {/* Reasons */}
      {result.reasons?.length > 0 && (
        <div className="mb-6">
          <h4 className="text-sm font-semibold text-slate-300 mb-3">
            🔍 {lang === 'hi' ? 'पहचान के कारण' : 'Detection Reasons'}
          </h4>
          <div className="flex flex-col gap-2">
            {result.reasons.map((r, i) => <ReasonCard key={i} reason={r} lang={lang} />)}
          </div>
        </div>
      )}

      {/* Confidence & Meta */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-center">
        <div className="p-3 rounded-lg bg-slate-900/40">
          <p className="text-xs text-slate-500">Confidence</p>
          <p className="text-lg font-semibold text-white">{(result.confidence * 100).toFixed(1)}%</p>
        </div>
        <div className="p-3 rounded-lg bg-slate-900/40">
          <p className="text-xs text-slate-500">Risk Score</p>
          <p className="text-lg font-semibold text-white">{result.risk_score}</p>
        </div>
        <div className="p-3 rounded-lg bg-slate-900/40 col-span-2 md:col-span-1">
          <p className="text-xs text-slate-500">Model</p>
          <p className="text-lg font-semibold text-white capitalize">{result.model_used}</p>
        </div>
      </div>
    </div>
  );
}

/* ============================================================
   ANALYTICS PANEL COMPONENT
   ============================================================ */
function AnalyticsPanel({ analytics, recentScans }) {
  if (!analytics) return null;

  return (
    <div className="glass-card p-6">
      <h3 className="text-lg font-semibold text-white mb-4">📊 Analytics</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <div className="p-3 rounded-lg bg-slate-900/40 text-center">
          <p className="text-2xl font-bold text-white">{analytics.total_scans}</p>
          <p className="text-xs text-slate-400">Total Scans</p>
        </div>
        <div className="p-3 rounded-lg bg-safe-bg/30 text-center">
          <p className="text-2xl font-bold text-safe">{analytics.safe_count}</p>
          <p className="text-xs text-slate-400">Safe</p>
        </div>
        <div className="p-3 rounded-lg bg-suspicious-bg/30 text-center">
          <p className="text-2xl font-bold text-suspicious">{analytics.suspicious_count}</p>
          <p className="text-xs text-slate-400">Suspicious</p>
        </div>
        <div className="p-3 rounded-lg bg-phishing-bg/30 text-center">
          <p className="text-2xl font-bold text-phishing">{analytics.phishing_count}</p>
          <p className="text-xs text-slate-400">Phishing</p>
        </div>
      </div>

      {/* Recent scans */}
      {recentScans?.length > 0 && (
        <>
          <h4 className="text-sm font-semibold text-slate-300 mb-3">Recent Scans</h4>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {recentScans.map((s, i) => (
              <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg bg-slate-900/40 text-sm">
                <span className={`w-2 h-2 rounded-full shrink-0 ${
                  s.risk_tier === 'SAFE' ? 'bg-safe' :
                  s.risk_tier === 'SUSPICIOUS' ? 'bg-suspicious' : 'bg-phishing'
                }`} />
                <span className="text-slate-300 truncate flex-1 font-mono text-xs">{s.url}</span>
                <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                  s.risk_tier === 'SAFE' ? 'text-safe' :
                  s.risk_tier === 'SUSPICIOUS' ? 'text-suspicious' : 'text-phishing'
                }`}>{s.risk_score}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/* ============================================================
   SAMPLE URLS COMPONENT
   ============================================================ */
function SampleUrls({ onSelect }) {
  const [samples, setSamples] = useState(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    getSampleUrls().then(setSamples).catch(() => {});
  }, []);

  if (!samples) return null;

  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen(!open)}
        className="text-sm text-brand-400 hover:text-brand-300 transition-colors flex items-center gap-1"
      >
        {open ? '▾' : '▸'} Try sample URLs
      </button>
      {open && (
        <div className="mt-3 grid gap-2 md:grid-cols-3">
          {[
            { label: '✅ Safe', urls: samples.safe_urls, color: 'border-safe/30 hover:border-safe/60' },
            { label: '⚠️ Suspicious', urls: samples.suspicious_urls, color: 'border-suspicious/30 hover:border-suspicious/60' },
            { label: '🚫 Phishing', urls: samples.phishing_urls, color: 'border-phishing/30 hover:border-phishing/60' },
          ].map((group) => (
            <div key={group.label} className="space-y-1.5">
              <p className="text-xs font-medium text-slate-400">{group.label}</p>
              {group.urls?.slice(0, 3).map((url, i) => (
                <button
                  key={i}
                  onClick={() => { onSelect(url); setOpen(false); }}
                  className={`w-full text-left px-3 py-2 rounded-lg bg-slate-900/40 border ${group.color} text-xs text-slate-300 font-mono truncate transition-all hover:bg-slate-800/60`}
                >
                  {url}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ============================================================
   MAIN APP COMPONENT
   ============================================================ */
export default function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [lang, setLang] = useState('en');
  const [analytics, setAnalytics] = useState(null);
  const [recentScans, setRecentScans] = useState([]);

  // Load analytics
  useEffect(() => {
    const load = () => {
      getAnalytics().then(setAnalytics).catch(() => {});
      getRecentScans(8).then(setRecentScans).catch(() => {});
    };
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleScan = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await checkUrl(url.trim());
      setResult(data);
      // Refresh analytics
      getAnalytics().then(setAnalytics).catch(() => {});
      getRecentScans(8).then(setRecentScans).catch(() => {});
    } catch (err) {
      setError(err.message || 'Scan failed. Please check the URL and try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleScan();
  };

  return (
    <div className="min-h-screen pb-12">
      {/* Header */}
      <header className="border-b border-slate-800/60 backdrop-blur-md bg-slate-900/40 sticky top-0 z-50">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldIcon tier="DEFAULT" size={36} />
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-brand-400 to-brand-200 bg-clip-text text-transparent">
                ShieldYONO
              </h1>
              <p className="text-xs text-slate-500">URL Phishing Classifier</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setLang(lang === 'en' ? 'hi' : 'en')}
              className="px-3 py-1.5 rounded-lg bg-slate-800 text-sm text-slate-300 hover:bg-slate-700 transition-colors border border-slate-700"
            >
              {lang === 'en' ? 'हिंदी' : 'English'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 mt-8 space-y-8">
        {/* Hero section */}
        <div className="text-center mb-8">
          <div className="inline-block animate-shield-pulse mb-4">
            <ShieldIcon tier="DEFAULT" size={64} />
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-3">
            {lang === 'hi' ? 'URL सुरक्षा जाँच करें' : 'Check URL Safety'}
          </h2>
          <p className="text-slate-400 max-w-lg mx-auto text-sm">
            {lang === 'hi'
              ? 'किसी भी संदिग्ध URL को स्कैन करें और तुरंत जानें कि वह सुरक्षित है या फ़िशिंग प्रयास।'
              : 'Scan any suspicious URL to instantly know if it\'s safe or a phishing attempt. Powered by ML + rule-based analysis.'}
          </p>
        </div>

        {/* Input section */}
        <div className="glass-card p-6">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="flex-1 relative">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
                  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
                </svg>
              </div>
              <input
                id="url-input"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder={lang === 'hi' ? 'यहाँ URL दर्ज करें...' : 'Enter URL to scan...'}
                className="w-full pl-11 pr-4 py-3.5 rounded-xl bg-slate-900/60 border border-slate-700/60 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500/50 text-sm font-mono transition-all"
              />
            </div>
            <button
              id="scan-button"
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="px-8 py-3.5 rounded-xl bg-gradient-to-r from-brand-600 to-brand-500 text-white font-semibold text-sm hover:from-brand-500 hover:to-brand-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-brand-500/20 hover:shadow-brand-500/40 flex items-center justify-center gap-2 min-w-[140px]"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  {lang === 'hi' ? 'स्कैन हो रहा...' : 'Scanning...'}
                </>
              ) : (
                <>
                  🔍 {lang === 'hi' ? 'स्कैन करें' : 'Scan URL'}
                </>
              )}
            </button>
          </div>

          <SampleUrls onSelect={(u) => setUrl(u)} />
        </div>

        {/* Loading state */}
        {loading && (
          <div className="glass-card p-8 text-center">
            <div className="inline-block animate-shield-pulse mb-3">
              <ShieldIcon tier="DEFAULT" size={48} />
            </div>
            <p className="text-slate-300 text-sm">
              {lang === 'hi' ? 'URL की जाँच हो रही है...' : 'Analyzing URL for threats...'}
            </p>
            <div className="mt-4 h-1 bg-slate-800 rounded-full overflow-hidden max-w-xs mx-auto">
              <div className="h-full bg-brand-500 rounded-full animate-scan" />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="glass-card p-4 border-phishing/30">
            <p className="text-phishing text-sm flex items-center gap-2">
              <span className="text-lg">⚠️</span> {error}
            </p>
          </div>
        )}

        {/* Result */}
        {result && <ResultCard result={result} lang={lang} />}

        {/* Analytics */}
        <AnalyticsPanel analytics={analytics} recentScans={recentScans} />

        {/* Footer */}
        <footer className="text-center pt-8 pb-4 border-t border-slate-800/40">
          <p className="text-xs text-slate-600">
            ShieldYONO v1.0 — Built for SBI Hackathon 2026 •
            Protected by ML + Rule-based Analysis
          </p>
        </footer>
      </main>
    </div>
  );
}
