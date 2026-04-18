import React, { useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react'
import { SeverityBadge } from './ui'

const SEVERITY_CONFIG = {
  CRITICAL: { color: 'text-danger-400',  bg: 'bg-danger-500/15 border-danger-500/40',  icon: AlertCircle },
  HIGH:     { color: 'text-danger-400',  bg: 'bg-danger-500/10 border-danger-500/30',  icon: AlertTriangle },
  MEDIUM:   { color: 'text-warning-400', bg: 'bg-warning-500/10 border-warning-500/30', icon: AlertTriangle },
  LOW:      { color: 'text-accent-400',  bg: 'bg-accent-500/10 border-accent-500/30',  icon: Info },
  NONE:     { color: 'text-safe-400',    bg: 'bg-safe-500/10 border-safe-500/30',       icon: CheckCircle },
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']

function FlagItem({ flag }) {
  const cfg = SEVERITY_CONFIG[flag.severity] || SEVERITY_CONFIG.LOW
  const Icon = cfg.icon
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${cfg.bg}`}>
      <Icon size={15} className={`${cfg.color} mt-0.5 shrink-0`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs font-semibold text-text-primary">
            {flag.type.replace(/_/g, ' ').toUpperCase()}
          </span>
          <SeverityBadge severity={flag.severity} score={flag.score} />
        </div>
        {flag.detail && <p className="text-xs text-text-secondary mt-1 break-words leading-relaxed">{flag.detail}</p>}
        {flag.source && <span className="text-xs text-text-muted mt-0.5 block">source: {flag.source}</span>}
      </div>
    </div>
  )
}

// compact=true: flat list of flags (already filtered by caller)
// compact=false (default): grouped with collapsible sections + NONE toggle
export default function FlagBreakdown({ flags, compact = false }) {
  const [expanded, setExpanded] = useState({ CRITICAL: true, HIGH: true, MEDIUM: true })
  const [showClean, setShowClean] = useState(false)

  if (compact) {
    return (
      <div className="space-y-2">
        {flags.length === 0 ? (
          <p className="text-sm text-text-muted py-4 text-center">No flags in this category</p>
        ) : (
          flags.map((flag, i) => <FlagItem key={i} flag={flag} />)
        )}
      </div>
    )
  }

  const grouped = {}
  for (const sev of SEVERITY_ORDER) grouped[sev] = flags.filter(f => f.severity === sev)
  const meaningful = SEVERITY_ORDER.filter(s => s !== 'NONE')
  const cleanCount = grouped['NONE']?.length || 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-accent-400 uppercase tracking-wider">Flag Breakdown</h3>
        <span className="text-xs text-text-secondary">{flags.filter(f => f.severity !== 'NONE').length} signals detected</span>
      </div>

      {meaningful.map(severity => {
        const items = grouped[severity] || []
        if (items.length === 0) return null
        const isOpen = expanded[severity] !== false
        const cfg = SEVERITY_CONFIG[severity]
        return (
          <div key={severity} className="rounded-lg border border-border overflow-hidden">
            <button
              onClick={() => setExpanded(e => ({ ...e, [severity]: !isOpen }))}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-bg-raised hover:bg-border transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className={`text-xs font-bold ${cfg.color}`}>{severity}</span>
                <span className="text-xs px-1.5 py-0.5 rounded-full font-mono bg-bg-surface text-text-secondary">{items.length}</span>
              </div>
              {isOpen ? <ChevronDown size={14} className="text-text-secondary" /> : <ChevronRight size={14} className="text-text-secondary" />}
            </button>
            {isOpen && (
              <div className="p-3 space-y-2 bg-bg-surface/50">
                {items.map((flag, i) => <FlagItem key={i} flag={flag} />)}
              </div>
            )}
          </div>
        )
      })}

      {cleanCount > 0 && (
        <button onClick={() => setShowClean(v => !v)} className="text-xs text-accent-400 hover:text-accent-300 flex items-center gap-1 mt-2">
          {showClean ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          {showClean ? 'Hide' : 'Show'} {cleanCount} passing signal{cleanCount !== 1 ? 's' : ''}
        </button>
      )}
      {showClean && (
        <div className="space-y-2 mt-2">
          {(grouped['NONE'] || []).map((flag, i) => <FlagItem key={i} flag={flag} />)}
        </div>
      )}
    </div>
  )
}
