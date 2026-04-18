import React, { useState, useCallback } from 'react'
import { Shield, AlertCircle, Zap } from 'lucide-react'
import InputForm from './components/InputForm'
import AnalysisResult from './components/AnalysisResult'
import HealthBar from './components/HealthBar'
import ScanHistory from './components/ScanHistory'
import CyberBackground from './components/CyberBackground'
import { Card } from './components/ui'
import { analyzeUrl, analyzeEmail, analyzeEmailFile } from './api/client'

const MAX_HISTORY = 10

const DETECTION_LAYERS = [
  { id: 'L1', label: 'Local',   timing: '<10ms',   desc: 'Homoglyphs · entropy · IP-in-URL' },
  { id: 'L2', label: 'DNS',     timing: '<300ms',  desc: 'SPF / DKIM / DMARC · WHOIS · similarity' },
  { id: 'L3', label: 'APIs',    timing: '<1.5s',   desc: 'VirusTotal · Safe Browsing · AbuseIPDB' },
  { id: 'L4', label: 'Content', timing: '<8s',     desc: 'HTML forms · Playwright rendering' },
]

export default function App() {
  const [result, setResult]           = useState(null)
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState(null)
  const [history, setHistory]         = useState([])
  const [currentInput, setCurrentInput] = useState('')

  const handleAnalyze = useCallback(async ({ type, value }) => {
    setLoading(true)
    setError(null)
    setCurrentInput(typeof value === 'string' ? value : value.name)

    try {
      let data
      if (type === 'url')         data = await analyzeUrl(value)
      else if (type === 'email')  data = await analyzeEmail(value)
      else if (type === 'email_file') data = await analyzeEmailFile(value)
      else throw new Error(`Unknown type: ${type}`)

      setResult(data)
      setHistory(prev => [
        { input: typeof value === 'string' ? value.slice(0, 60) : value.name, result: data },
        ...prev.slice(0, MAX_HISTORY - 1),
      ])
    } catch (err) {
      console.error('Analysis error:', err)
      const msg = err.response?.data?.detail || err.message || 'Analysis failed'
      setError(msg)
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleHistorySelect = useCallback((item) => {
    setResult(item.result)
    setCurrentInput(item.input)
    setError(null)
  }, [])

  return (
    <div className="min-h-screen relative bg-bg-base">
      {/* Atmospheric background */}
      <div className="cyber-grid" />
      <div className="cyber-shield" />
      <div className="cyber-corner-dots" />
      <CyberBackground />

      {/* Content */}
      <div className="relative z-10 flex flex-col min-h-screen">

        {/* ── Header ───────────────────────────────────────────── */}
        <header className="border-b border-border sticky top-0 z-20 glass">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">

            {/* Brand */}
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-accent-500 rounded-md flex items-center justify-center shadow-glow-accent">
                <Shield size={16} className="text-white" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-base font-semibold text-text-primary tracking-tight">PhishGuard</span>
                <span className="hidden sm:inline text-xs text-text-muted font-mono">v2.0</span>
              </div>
            </div>

            {/* Health bar — center */}
            <div className="flex-1 max-w-lg hidden md:block">
              <HealthBar />
            </div>

            {/* Badge */}
            <div className="flex items-center gap-2">
              <span className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-accent-400 border border-accent-500/30 bg-accent-500/10 rounded px-2.5 py-1">
                <Zap size={10} className="text-accent-400" />
                11-Layer Detection
              </span>
            </div>
          </div>

          {/* Mobile health bar */}
          <div className="md:hidden border-t border-border px-4 py-2">
            <HealthBar />
          </div>
        </header>

        {/* ── Main ─────────────────────────────────────────────── */}
        <main className="flex-1 max-w-6xl mx-auto w-full px-4 sm:px-6 py-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

            {/* ── Left column ── */}
            <div className="lg:col-span-1 space-y-4">
              <InputForm onAnalyze={handleAnalyze} loading={loading} />
              <ScanHistory history={history} onSelect={handleHistorySelect} />

              {/* Detection layers card */}
              <div className="card">
                <p className="text-xs font-mono text-text-muted uppercase tracking-widest mb-4">
                  Detection Pipeline
                </p>
                <div className="space-y-3">
                  {DETECTION_LAYERS.map(({ id, label, timing, desc }) => (
                    <div key={id} className="flex gap-3 items-start group">
                      <div className="flex-shrink-0 w-7 h-7 rounded bg-bg-raised border border-border flex items-center justify-center
                                      group-hover:border-accent-500/40 group-hover:bg-accent-500/10 transition-all duration-150">
                        <span className="text-[10px] font-mono text-text-secondary group-hover:text-accent-400 transition-colors">
                          {id}
                        </span>
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
                    {/* Outer ring */}
                    <div className="absolute inset-0 rounded-full border border-border" />
                    {/* Spinning ring */}
                    <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-accent-500 animate-spin" />
                    {/* Inner pulse */}
                    <div className="absolute inset-[6px] rounded-full bg-accent-500/10 flex items-center justify-center">
                      <Shield size={22} className="text-accent-400" />
                    </div>
                    {/* Scan line */}
                    <div className="absolute inset-x-0 h-px bg-gradient-to-r from-transparent via-accent-400 to-transparent scan-bar" />
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
                      <p className="text-xs text-text-muted mt-2">
                        Ensure the backend is running on port 8000.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Results */}
              {result && !loading && (
                <div className="fade-in">
                  <AnalysisResult result={result} />
                </div>
              )}

              {/* Empty state */}
              {!result && !loading && !error && (
                <div className="card flex flex-col items-center justify-center py-20 text-center gap-4">
                  <div className="w-14 h-14 rounded-full border border-border bg-bg-raised flex items-center justify-center">
                    <Shield size={24} className="text-text-muted" />
                  </div>
                  <div className="space-y-1">
                    <p className="text-sm font-medium text-text-primary">Ready to analyze</p>
                    <p className="text-xs text-text-muted max-w-xs leading-relaxed">
                      Paste a URL or email on the left to run the full 11-layer phishing detection pipeline.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </main>

        {/* ── Footer ───────────────────────────────────────────── */}
        <footer className="border-t border-border mt-auto">
          <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
            <span className="text-xs font-mono text-text-muted">
              PhishGuard · 11-Layer Detection
            </span>
            <span className="text-xs text-text-muted">
              AI-Powered · Real-time Threat Intelligence
            </span>
          </div>
        </footer>
      </div>
    </div>
  )
}