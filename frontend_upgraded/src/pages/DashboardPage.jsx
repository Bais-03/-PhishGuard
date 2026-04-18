import React, { useState } from 'react'
import { Shield, AlertCircle, TrendingUp, Zap } from 'lucide-react'
import InputForm from '../components/InputForm'
import ScanHistory from '../components/ScanHistory'
import ScoreRing from '../components/ScoreRing'
import FlagBreakdown from '../components/FlagBreakdown'
import HealthBar from '../components/HealthBar'
import { Clock, Database } from 'lucide-react'

const DETECTION_LAYERS = [
  { id: 'L1', label: 'Local',   timing: '<10ms',   desc: 'Homoglyphs · entropy · IP-in-URL' },
  { id: 'L2', label: 'DNS',     timing: '<300ms',  desc: 'SPF / DKIM / DMARC · WHOIS' },
  { id: 'L3', label: 'APIs',    timing: '<1.5s',   desc: 'VirusTotal · Safe Browsing · AbuseIPDB' },
  { id: 'L4', label: 'Content', timing: '<8s',     desc: 'HTML forms · Playwright rendering' },
]

const SEVERITY_TABS = [
  { id: 'all',    label: 'All Flags', color: 'text-text-secondary' },
  { id: 'high',   label: 'High',      color: 'text-danger-400' },
  { id: 'medium', label: 'Medium',    color: 'text-warning-400' },
  { id: 'low',    label: 'Low',       color: 'text-accent-400' },
]

function VerdictBanner({ verdict }) {
  const config = {
    'PHISHING':    { bg: 'bg-danger-500/10 border-danger-500/30',  text: 'text-danger-400',  icon: '🔴', msg: 'This is almost certainly a phishing attempt. Do not interact with this content.' },
    'SUSPICIOUS':  { bg: 'bg-warning-500/10 border-warning-500/30', text: 'text-warning-400', icon: '🟡', msg: 'Suspicious indicators detected. Proceed with extreme caution.' },
    'LIKELY SAFE': { bg: 'bg-safe-500/10 border-safe-500/30',      text: 'text-safe-400',    icon: '🟢', msg: 'No significant phishing indicators detected.' },
  }
  const c = config[verdict] || config['LIKELY SAFE']
  return (
    <div className={`rounded-lg border p-3 ${c.bg}`}>
      <p className={`text-sm ${c.text}`}><span className="mr-2">{c.icon}</span>{c.msg}</p>
    </div>
  )
}

function SeverityTabPanel({ flags }) {
  const [activeTab, setActiveTab] = useState('all')

  const flagsByTab = {
    all:    flags,
    high:   flags.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH'),
    medium: flags.filter(f => f.severity === 'MEDIUM'),
    low:    flags.filter(f => f.severity === 'LOW'),
  }

  const tabCounts = {
    all:    flags.length,
    high:   flagsByTab.high.length,
    medium: flagsByTab.medium.length,
    low:    flagsByTab.low.length,
  }

  return (
    <div>
      {/* Tabs */}
      <div className="flex gap-1 border-b border-border mb-4">
        {SEVERITY_TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-all duration-150 -mb-px ${
              activeTab === tab.id
                ? `${tab.color} border-current`
                : 'text-text-muted border-transparent hover:text-text-secondary'
            }`}
          >
            {tab.label}
            {tabCounts[tab.id] > 0 && (
              <span className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${
                activeTab === tab.id ? 'bg-current/10' : 'bg-bg-raised text-text-muted'
              }`}>
                {tabCounts[tab.id]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Flags */}
      {flagsByTab[activeTab].length > 0 ? (
        <FlagBreakdown flags={flagsByTab[activeTab]} compact />
      ) : (
        <div className="py-8 text-center">
          <p className="text-sm text-text-muted">No {activeTab === 'all' ? '' : activeTab + ' '} flags found</p>
        </div>
      )}
    </div>
  )
}

export default function DashboardPage({ result, loading, error, history, onAnalyze, onHistorySelect, onNavigate }) {
  const safeReasons = Array.isArray(result?.reasons)
    ? result.reasons.map(r => typeof r === 'string' ? r : String(r))
    : []

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-5">
      {/* Status bar */}
      <div className="card !py-3 flex items-center gap-4 overflow-x-auto">
        <HealthBar />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* ── Left column ── */}
        <div className="lg:col-span-1 space-y-4">
          <InputForm onAnalyze={onAnalyze} loading={loading} />
          <ScanHistory history={history} onSelect={onHistorySelect} />
          {/* Detection pipeline */}
          <div className="card">
            <p className="text-xs font-mono text-text-muted uppercase tracking-widest mb-4">Detection Pipeline</p>
            <div className="space-y-3">
              {DETECTION_LAYERS.map(({ id, label, timing, desc }) => (
                <div key={id} className="flex gap-3 items-start group">
                  <div className="shrink-0 w-7 h-7 rounded bg-bg-raised border border-border flex items-center justify-center group-hover:border-accent-500/40 group-hover:bg-accent-500/10 transition-all">
                    <span className="text-[10px] font-mono text-text-secondary group-hover:text-accent-400 transition-colors">{id}</span>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-text-primary">{label}</span>
                      <span className="text-[10px] font-mono text-accent-400/70">{timing}</span>
                    </div>
                    <p className="text-[11px] text-text-muted leading-relaxed mt-0.5">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Right column ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Loading */}
          {loading && (
            <div className="card flex flex-col items-center justify-center py-16 gap-5">
              <div className="relative w-20 h-20">
                <div className="absolute inset-0 rounded-full border border-border" />
                <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-accent-500 animate-spin" />
                <div className="absolute inset-[6px] rounded-full bg-accent-500/10 flex items-center justify-center">
                  <Shield size={22} className="text-accent-400" />
                </div>
              </div>
              <div className="text-center space-y-1">
                <p className="text-sm font-medium text-text-primary">Scanning<span className="animate-blink">_</span></p>
                <p className="text-xs text-text-muted font-mono">Running all detection layers in parallel</p>
              </div>
            </div>
          )}

          {/* Error */}
          {error && !loading && (
            <div className="card border-danger-500/30 bg-danger-500/5">
              <div className="flex items-start gap-3">
                <AlertCircle size={16} className="text-danger-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-danger-400">Analysis failed</p>
                  <p className="text-xs text-text-secondary mt-1 font-mono">{error}</p>
                  <p className="text-xs text-text-muted mt-2">Ensure the backend is running on port 8000.</p>
                </div>
              </div>
            </div>
          )}

          {/* Results */}
          {result && !loading && (() => {
            const { score, verdict, flags = [], duration_ms, cache_hit, input_type, analyzed_at } = result
            const analyzedAt = analyzed_at ? new Date(analyzed_at).toLocaleTimeString() : 'just now'
            return (
              <div className="space-y-4 fade-in">
                {/* Score card */}
                <div className="card flex flex-col sm:flex-row items-center gap-6">
                  <ScoreRing score={score} verdict={verdict} />
                  <div className="flex-1 space-y-3">
                    <VerdictBanner verdict={verdict} />
                    {safeReasons.length > 0 && (
                      <div>
                        <p className="text-xs text-accent-400 uppercase tracking-wider mb-2">Top Reasons</p>
                        <ul className="space-y-1">
                          {safeReasons.slice(0, 5).map((r, i) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                              <span className="text-accent-400 font-mono mt-0.5">{i + 1}.</span>{r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-4 text-xs text-accent-400 pt-1">
                      <span className="flex items-center gap-1"><Clock size={12} />{duration_ms}ms</span>
                      <span className="flex items-center gap-1"><Database size={12} />{cache_hit ? 'Cache hit' : 'Fresh scan'}</span>
                      <span className="flex items-center gap-1"><Shield size={12} />{input_type === 'email' ? 'Email analysis' : 'URL analysis'}</span>
                      <span>{analyzedAt}</span>
                    </div>
                  </div>
                </div>

                {/* Flags with severity tabs */}
                {flags && flags.length > 0 && (
                  <div className="card">
                    <div className="flex items-center justify-between mb-1">
                      <h3 className="text-sm font-semibold text-text-primary">Signal Breakdown</h3>
                      <span className="text-xs text-text-muted">{flags.filter(f => f.severity !== 'NONE').length} threat signals</span>
                    </div>
                    <SeverityTabPanel flags={flags} />
                  </div>
                )}
              </div>
            )
          })()}

          {/* Empty state */}
          {!result && !loading && !error && (
            <div className="card flex flex-col items-center justify-center py-20 text-center gap-4">
              <div className="w-16 h-16 rounded-2xl border border-border bg-bg-raised flex items-center justify-center">
                <Shield size={28} className="text-text-muted" />
              </div>
              <div className="space-y-1.5">
                <p className="text-sm font-semibold text-text-primary">Ready to analyze</p>
                <p className="text-xs text-text-muted max-w-xs leading-relaxed">
                  Paste a URL or email on the left to run the full 11-layer phishing detection pipeline.
                </p>
              </div>
              <button
                onClick={() => onNavigate('analysis')}
                className="text-xs text-accent-400 hover:text-accent-300 underline transition-colors"
              >
                Go to Analysis →
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
