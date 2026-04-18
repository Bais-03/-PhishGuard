import React from 'react'
import { Shield, Zap, Globe, Mail, Lock, ChevronRight, ArrowRight, Activity } from 'lucide-react'

const FEATURES = [
  { icon: Zap,      label: 'Sub-10ms Local Detection',  desc: 'Homoglyphs, entropy & IP-in-URL checks run instantly on-device.' },
  { icon: Globe,    label: 'DNS & WHOIS Intelligence',  desc: 'SPF / DKIM / DMARC validation and domain registration analysis.' },
  { icon: Mail,     label: 'Email File Analysis',       desc: 'Upload raw .eml files for deep header and body inspection.' },
  { icon: Lock,     label: '11-Layer Pipeline',         desc: 'VirusTotal, Safe Browsing, AbuseIPDB and Playwright rendering.' },
]

const STATS = [
  { value: '11',     label: 'Detection Layers' },
  { value: '<10ms',  label: 'Local Scan Speed' },
  { value: '99.4%',  label: 'Accuracy Rate' },
  { value: '3 APIs', label: 'Threat Intel Feeds' },
]

export default function HomePage({ onNavigate }) {
  return (
    <div className="min-h-screen">
      {/* ── Hero ── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 pt-20 pb-16 lg:pt-28 lg:pb-24">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">

          {/* Left: copy */}
          <div className="space-y-7">
            {/* Eyebrow badge */}
            <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-accent-500/30 bg-accent-500/5 text-xs font-mono text-accent-400">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-400 animate-pulse" />
              Phishing Detection · Powered by 11 Layers
            </div>

            <div className="space-y-4">
              <h1 className="text-4xl sm:text-5xl lg:text-[3.25rem] font-bold leading-tight text-text-primary tracking-tight">
                Stop phishing
                <br />
                <span className="text-accent-400">before it strikes.</span>
              </h1>
              <p className="text-base sm:text-lg text-text-secondary leading-relaxed max-w-lg">
                PhishGuard runs URLs and emails through an 11-layer detection pipeline—
                from sub-10ms local heuristics to full browser rendering—giving you
                a verdict in seconds, not days.
              </p>
            </div>

            {/* CTAs */}
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={() => onNavigate('analysis')}
                className="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-lg bg-accent-500 hover:bg-accent-400 text-white text-sm font-semibold shadow-glow-accent transition-all duration-150 group"
              >
                Start Analysis
                <ArrowRight size={15} className="group-hover:translate-x-0.5 transition-transform" />
              </button>
              <button
                onClick={() => onNavigate('insights')}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg border border-border text-sm font-medium text-text-secondary hover:text-text-primary hover:border-border-strong hover:bg-bg-raised transition-all duration-150"
              >
                View Insights
                <ChevronRight size={14} />
              </button>
            </div>

            {/* Micro-stats row */}
            <div className="flex flex-wrap gap-5 pt-2">
              {STATS.map(({ value, label }) => (
                <div key={label} className="space-y-0.5">
                  <p className="text-xl font-bold text-text-primary font-mono">{value}</p>
                  <p className="text-xs text-text-muted">{label}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Right: visual card mock */}
          <div className="hidden lg:flex justify-center">
            <div className="relative w-full max-w-md">
              {/* Glow blob */}
              <div className="absolute -inset-8 bg-accent-500/10 rounded-3xl blur-3xl pointer-events-none" />

              {/* Main card */}
              <div className="relative card space-y-5">
                {/* Score ring mock */}
                <div className="flex items-center gap-5">
                  <div className="relative w-20 h-20 shrink-0">
                    <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
                      <circle cx="40" cy="40" r="32" fill="none" stroke="currentColor" className="text-border" strokeWidth="6" />
                      <circle
                        cx="40" cy="40" r="32" fill="none"
                        stroke="currentColor" className="text-danger-400"
                        strokeWidth="6"
                        strokeDasharray={`${2 * Math.PI * 32 * 0.82} ${2 * Math.PI * 32}`}
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-lg font-bold text-danger-400 leading-none">82</span>
                      <span className="text-[9px] text-text-muted font-mono mt-0.5">RISK</span>
                    </div>
                  </div>
                  <div className="space-y-2 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-danger-400" />
                      <span className="text-sm font-semibold text-danger-400">PHISHING</span>
                    </div>
                    <p className="text-xs text-text-muted font-mono truncate">http://paypa1-secure-login.xyz/</p>
                    <div className="text-xs text-text-muted">Scanned in <span className="text-accent-400 font-mono">1.2s</span> · 4 threat signals</div>
                  </div>
                </div>

                {/* Flag rows */}
                <div className="space-y-2">
                  {[
                    { sev: 'HIGH',   color: 'text-danger-400  bg-danger-500/10  border-danger-500/20',  label: 'Homoglyph substitution detected' },
                    { sev: 'HIGH',   color: 'text-danger-400  bg-danger-500/10  border-danger-500/20',  label: 'Domain registered < 7 days ago' },
                    { sev: 'MEDIUM', color: 'text-warning-400 bg-warning-500/10 border-warning-500/20', label: 'Missing DMARC record' },
                    { sev: 'LOW',    color: 'text-safe-400    bg-safe-500/10    border-safe-500/20',    label: 'Redirect chain depth: 3' },
                  ].map(({ sev, color, label }) => (
                    <div key={label} className="flex items-center gap-3 p-2.5 rounded-md bg-bg-raised border border-border">
                      <span className={`shrink-0 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${color}`}>{sev}</span>
                      <span className="text-xs text-text-secondary truncate">{label}</span>
                    </div>
                  ))}
                </div>

                {/* Bottom meta */}
                <div className="flex items-center justify-between pt-1 border-t border-border">
                  <span className="text-xs text-text-muted font-mono">cache miss · fresh scan</span>
                  <div className="flex items-center gap-1 text-xs text-accent-400">
                    <Activity size={11} />
                    <span>All layers passed</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ── Feature grid ── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 pb-20">
        <div className="mb-8 space-y-1.5">
          <p className="text-xs font-mono text-accent-400 uppercase tracking-widest">Capabilities</p>
          <h2 className="text-xl font-semibold text-text-primary">Everything you need to detect threats</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {FEATURES.map(({ icon: Icon, label, desc }) => (
            <div key={label} className="card group hover:border-accent-500/30 hover:bg-accent-500/5 transition-all duration-200 space-y-3">
              <div className="w-9 h-9 rounded-lg bg-accent-500/10 border border-accent-500/20 flex items-center justify-center group-hover:bg-accent-500/20 transition-colors">
                <Icon size={17} className="text-accent-400" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-semibold text-text-primary">{label}</p>
                <p className="text-xs text-text-muted leading-relaxed">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Bottom CTA strip ── */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 pb-20">
        <div className="card flex flex-col sm:flex-row items-center justify-between gap-5 bg-accent-500/5 border-accent-500/20">
          <div className="space-y-1 text-center sm:text-left">
            <p className="text-sm font-semibold text-text-primary">Ready to analyze a suspicious link or email?</p>
            <p className="text-xs text-text-muted">Paste a URL or upload an .eml file — results in under 8 seconds.</p>
          </div>
          <button
            onClick={() => onNavigate('analysis')}
            className="shrink-0 inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-accent-500 hover:bg-accent-400 text-white text-sm font-semibold shadow-glow-accent transition-all duration-150 group"
          >
            Start Analysis
            <ArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
          </button>
        </div>
      </section>
    </div>
  )
}