import React, { useState, useCallback } from 'react'
import { Shield, AlertCircle } from 'lucide-react'
import InputForm from './components/InputForm'
import AnalysisResult from './components/AnalysisResult'
import HealthBar from './components/HealthBar'
import ScanHistory from './components/ScanHistory'
import { analyzeUrl, analyzeEmail } from './api/client'

const MAX_HISTORY = 10

export default function App() {
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [history, setHistory] = useState([])
  const [currentInput, setCurrentInput] = useState('')

  const handleAnalyze = useCallback(async ({ type, value }) => {
    setLoading(true)
    setError(null)
    setCurrentInput(value)
    try {
      const data = type === 'url'
        ? await analyzeUrl(value)
        : await analyzeEmail(value)

      setResult(data)
      setHistory(prev => [
        { input: value.slice(0, 60), result: data },
        ...prev.slice(0, MAX_HISTORY - 1),
      ])
    } catch (err) {
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
    <div className="min-h-screen bg-phish-dark">
      {/* Header */}
      <header className="border-b border-phish-border bg-phish-card">
        <div className="max-w-5xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-blue-600 rounded-lg flex items-center justify-center shadow-lg shadow-blue-900/40">
                <Shield size={20} className="text-white" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white tracking-tight">PhishGuard</h1>
                <p className="text-xs text-slate-500">11-Layer Phishing Detection Engine</p>
              </div>
            </div>
            <div className="hidden sm:block">
              <span className="text-xs font-mono text-slate-600 border border-phish-border rounded px-2 py-1">
                Resonance 2K26 · VIT Pune
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Health bar */}
      <div className="border-b border-phish-border bg-slate-900/50">
        <div className="max-w-5xl mx-auto px-4 py-2">
          <HealthBar />
        </div>
      </div>

      {/* Main content */}
      <main className="max-w-5xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left column: input + history */}
          <div className="lg:col-span-1 space-y-5">
            <InputForm onAnalyze={handleAnalyze} loading={loading} />
            <ScanHistory history={history} onSelect={handleHistorySelect} />

            {/* Architecture info card */}
            <div className="card text-xs space-y-2">
              <p className="text-slate-400 font-semibold uppercase tracking-wider">Detection Layers</p>
              {[
                ['Layer 1', 'Local  ·  &lt;10ms',   'Homoglyphs, entropy, IP-in-URL'],
                ['Layer 2', 'DNS    ·  &lt;300ms',  'SPF/DKIM/DMARC, WHOIS, similarity'],
                ['Layer 3', 'APIs   ·  &lt;1500ms', 'VT, Safe Browsing, AbuseIPDB'],
                ['Layer 4', 'Content ·  &lt;8s',    'HTML, forms, Playwright'],
              ].map(([layer, timing, desc]) => (
                <div key={layer} className="flex gap-3 items-start">
                  <span className="font-mono text-blue-400 shrink-0 w-14">{layer}</span>
                  <div>
                    <span className="text-slate-500 font-mono"
                      dangerouslySetInnerHTML={{ __html: timing }} />
                    <p className="text-slate-600">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right column: results */}
          <div className="lg:col-span-2 space-y-5">
            {/* Loading state */}
            {loading && (
              <div className="card flex flex-col items-center justify-center py-16 gap-4">
                <div className="relative w-16 h-16">
                  <div className="absolute inset-0 border-2 border-blue-500/20 rounded-full" />
                  <div className="absolute inset-0 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  <Shield size={24} className="absolute inset-0 m-auto text-blue-400" />
                </div>
                <div className="text-center">
                  <p className="text-slate-300 font-medium">Analyzing...</p>
                  <p className="text-xs text-slate-500 mt-1">Running all detection layers in parallel</p>
                </div>
              </div>
            )}

            {/* Error state */}
            {error && !loading && (
              <div className="card flex items-start gap-3 border-red-900 bg-red-950/30">
                <AlertCircle size={18} className="text-red-400 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-medium text-red-300">Analysis failed</p>
                  <p className="text-xs text-red-400/70 mt-1">{error}</p>
                  <p className="text-xs text-slate-500 mt-2">
                    Make sure the backend is running on port 8000.
                  </p>
                </div>
              </div>
            )}

            {/* Results */}
            {result && !loading && (
              <AnalysisResult result={result} />
            )}

            {/* Empty state */}
            {!result && !loading && !error && (
              <div className="card flex flex-col items-center justify-center py-20 text-center">
                <Shield size={48} className="text-slate-700 mb-4" />
                <p className="text-slate-400 font-medium">Ready to analyze</p>
                <p className="text-slate-600 text-sm mt-1 max-w-xs">
                  Paste a URL or raw email on the left to run the full 11-layer phishing detection pipeline.
                </p>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-phish-border mt-12">
        <div className="max-w-5xl mx-auto px-4 py-4 text-center text-xs text-slate-600">
          PhishGuard · CyberSecurity Track · Resonance 2K26 · VIT Pune Bibwewadi · April 17, 2026
        </div>
      </footer>
    </div>
  )
}
