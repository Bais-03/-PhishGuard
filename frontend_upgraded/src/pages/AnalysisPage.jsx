import React from 'react'
import { Search, ArrowLeft, Zap, Shield } from 'lucide-react'
import InputForm from '../components/InputForm'

export default function AnalysisPage({ onAnalyze, loading, onNavigate }) {
  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Header with back button */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => onNavigate('home')}
          className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors"
        >
          <ArrowLeft size={16} />
          Back to Home
        </button>
        
        {/* Status Badge */}
        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-accent-400 border border-accent-500/30 bg-accent-500/5 rounded-full px-3 py-1">
          <Zap size={10} />
          <span>11-Layer Detection Ready</span>
        </div>
      </div>

      {/* Hero Section */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-accent-500/10 border border-accent-500/20 mx-auto">
          <Search size={24} className="text-accent-400" />
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-text-primary">
          Analyze Suspicious Content
        </h1>
        <p className="text-sm text-text-muted max-w-md mx-auto">
          Submit a URL or paste an email to run through our 11-layer phishing detection pipeline.
          Results appear instantly on the Insights page.
        </p>
      </div>

      {/* Input Form Card */}
      <div className="card !p-0 overflow-hidden">
        <div className="bg-bg-raised border-b border-border px-5 py-3">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-accent-400" />
            <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
              New Analysis
            </span>
          </div>
        </div>
        <div className="p-5">
          <InputForm onAnalyze={onAnalyze} loading={loading} />
        </div>
      </div>

      {/* Quick Tips */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="card !p-4">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent-500/10 border border-accent-500/20 flex items-center justify-center shrink-0">
              <span className="text-xs font-mono text-accent-400">URL</span>
            </div>
            <div>
              <p className="text-xs font-semibold text-text-primary">URL Analysis</p>
              <p className="text-xs text-text-muted mt-0.5">Paste any suspicious link. We'll check homoglyphs, WHOIS, and threat intel APIs.</p>
            </div>
          </div>
        </div>
        <div className="card !p-4">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent-500/10 border border-accent-500/20 flex items-center justify-center shrink-0">
              <span className="text-xs font-mono text-accent-400">EML</span>
            </div>
            <div>
              <p className="text-xs font-semibold text-text-primary">Email Forensics</p>
              <p className="text-xs text-text-muted mt-0.5">Upload .eml files or paste raw email content. We analyze headers, SPF, DKIM, DMARC.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Layers Summary */}
      <div className="card !p-4">
        <p className="text-xs font-mono text-text-muted uppercase tracking-wider mb-3">Detection Pipeline</p>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { layer: 'L1', label: 'Local', timing: '<10ms', desc: 'Homoglyphs · entropy' },
            { layer: 'L2', label: 'DNS', timing: '<300ms', desc: 'SPF · DKIM · WHOIS' },
            { layer: 'L3', label: 'APIs', timing: '<1.5s', desc: 'VirusTotal · Safe Browsing' },
            { layer: 'L4', label: 'Content', timing: '<8s', desc: 'HTML · Playwright' },
          ].map(({ layer, label, timing, desc }) => (
            <div key={layer} className="flex items-start gap-2">
              <div className="w-6 h-6 rounded bg-bg-raised border border-border flex items-center justify-center shrink-0">
                <span className="text-[9px] font-mono text-text-secondary">{layer}</span>
              </div>
              <div>
                <p className="text-xs font-medium text-text-primary">{label}</p>
                <p className="text-[10px] font-mono text-accent-400/70">{timing}</p>
                <p className="text-[10px] text-text-muted hidden sm:block">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}