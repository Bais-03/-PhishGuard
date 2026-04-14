import React, { useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react'

const SEVERITY_CONFIG = {
  CRITICAL: {
    color: 'text-red-400',
    bg: 'bg-red-950 border-red-800',
    badge: 'bg-red-900 text-red-200',
    icon: AlertCircle,
  },
  HIGH: {
    color: 'text-orange-400',
    bg: 'bg-orange-950 border-orange-800',
    badge: 'bg-orange-900 text-orange-200',
    icon: AlertTriangle,
  },
  MEDIUM: {
    color: 'text-amber-400',
    bg: 'bg-amber-950 border-amber-800',
    badge: 'bg-amber-900 text-amber-200',
    icon: AlertTriangle,
  },
  LOW: {
    color: 'text-blue-400',
    bg: 'bg-blue-950 border-blue-800',
    badge: 'bg-blue-900 text-blue-200',
    icon: Info,
  },
  NONE: {
    color: 'text-green-400',
    bg: 'bg-green-950 border-green-800',
    badge: 'bg-green-900 text-green-200',
    icon: CheckCircle,
  },
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']

function FlagItem({ flag }) {
  const cfg = SEVERITY_CONFIG[flag.severity] || SEVERITY_CONFIG.LOW
  const Icon = cfg.icon

  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border ${cfg.bg}`}>
      <Icon size={16} className={`${cfg.color} mt-0.5 shrink-0`} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-sm font-semibold text-slate-200">
            {flag.type.replace(/_/g, ' ')}
          </span>
          <span className={`text-xs px-1.5 py-0.5 rounded font-semibold ${cfg.badge}`}>
            {flag.severity}
          </span>
          <span className="text-xs text-slate-400 ml-auto font-mono">
            +{flag.score}pts
          </span>
        </div>
        {flag.detail && (
          <p className="text-xs text-slate-400 mt-1 break-words">{flag.detail}</p>
        )}
        {flag.source && (
          <span className="text-xs text-slate-600 mt-0.5 block">
            source: {flag.source}
          </span>
        )}
      </div>
    </div>
  )
}

export default function FlagBreakdown({ flags }) {
  const [expanded, setExpanded] = useState({ CRITICAL: true, HIGH: true, MEDIUM: true })

  // Filter out NONE severity (pass signals) unless user wants them
  const [showClean, setShowClean] = useState(false)

  const grouped = {}
  for (const sev of SEVERITY_ORDER) {
    grouped[sev] = flags.filter(f => f.severity === sev)
  }

  const meaningful = SEVERITY_ORDER.filter(s => s !== 'NONE')
  const cleanCount = grouped['NONE']?.length || 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          Flag Breakdown
        </h3>
        <span className="text-xs text-slate-500">
          {flags.filter(f => f.severity !== 'NONE').length} signals detected
        </span>
      </div>

      {meaningful.map(severity => {
        const items = grouped[severity] || []
        if (items.length === 0) return null
        const isOpen = expanded[severity] !== false
        const cfg = SEVERITY_CONFIG[severity]

        return (
          <div key={severity} className="rounded-lg border border-phish-border overflow-hidden">
            <button
              onClick={() => setExpanded(e => ({ ...e, [severity]: !isOpen }))}
              className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-800 hover:bg-slate-750 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className={`text-xs font-bold ${cfg.color}`}>{severity}</span>
                <span className={`text-xs px-1.5 rounded-full font-mono ${cfg.badge}`}>
                  {items.length}
                </span>
              </div>
              {isOpen
                ? <ChevronDown size={14} className="text-slate-400" />
                : <ChevronRight size={14} className="text-slate-400" />
              }
            </button>
            {isOpen && (
              <div className="p-3 space-y-2 bg-slate-900">
                {items.map((flag, i) => <FlagItem key={i} flag={flag} />)}
              </div>
            )}
          </div>
        )
      })}

      {/* Clean signals toggle */}
      {cleanCount > 0 && (
        <button
          onClick={() => setShowClean(v => !v)}
          className="text-xs text-slate-500 hover:text-slate-400 flex items-center gap-1 mt-2"
        >
          {showClean ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          {showClean ? 'Hide' : 'Show'} {cleanCount} passing signal{cleanCount !== 1 ? 's' : ''}
        </button>
      )}

      {showClean && (
        <div className="space-y-2">
          {(grouped['NONE'] || []).map((flag, i) => <FlagItem key={i} flag={flag} />)}
        </div>
      )}
    </div>
  )
}
