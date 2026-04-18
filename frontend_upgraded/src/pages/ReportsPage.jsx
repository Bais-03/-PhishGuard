import React, { useState } from 'react'
import { FileText, TrendingUp, AlertTriangle, CheckCircle, Clock, Download, Calendar, Filter } from 'lucide-react'
import clsx from 'clsx'

const VERDICT_STYLE = {
  'PHISHING':    'bg-danger-500/20 text-danger-300 border-danger-500/40',
  'SUSPICIOUS':  'bg-warning-500/15 text-warning-300 border-warning-500/40',
  'LIKELY SAFE': 'bg-safe-500/15 text-safe-300 border-safe-500/40',
}

const VERDICT_BADGE = {
  'PHISHING':    { bg: 'bg-danger-500/10 text-danger-400 border-danger-500/30', label: 'Phishing' },
  'SUSPICIOUS':  { bg: 'bg-warning-500/10 text-warning-400 border-warning-500/30', label: 'Suspicious' },
  'LIKELY SAFE': { bg: 'bg-safe-500/10 text-safe-400 border-safe-500/30', label: 'Safe' },
}

function StatCard({ icon: Icon, label, value, color }) {
  return (
    <div className="card flex items-center gap-4 !p-4">
      <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${color}`}>
        <Icon size={18} />
      </div>
      <div>
        <p className="text-2xl font-bold font-mono text-text-primary">{value}</p>
        <p className="text-xs text-text-muted">{label}</p>
      </div>
    </div>
  )
}

export default function ReportsPage({ history, onSelect }) {
  const [filter, setFilter] = useState('all')
  const [dateRange, setDateRange] = useState('week')

  const phishing   = history.filter(h => h.result.verdict === 'PHISHING').length
  const suspicious = history.filter(h => h.result.verdict === 'SUSPICIOUS').length
  const safe       = history.filter(h => h.result.verdict === 'LIKELY SAFE').length

  const filteredHistory = history.filter(item => {
    if (filter === 'all') return true
    if (filter === 'phishing') return item.result.verdict === 'PHISHING'
    if (filter === 'suspicious') return item.result.verdict === 'SUSPICIOUS'
    if (filter === 'safe') return item.result.verdict === 'LIKELY SAFE'
    return true
  })

  const filterButtons = [
    { id: 'all', label: 'All', count: history.length },
    { id: 'phishing', label: 'Phishing', count: phishing, color: 'text-danger-400' },
    { id: 'suspicious', label: 'Suspicious', count: suspicious, color: 'text-warning-400' },
    { id: 'safe', label: 'Safe', count: safe, color: 'text-safe-400' },
  ]

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-9 h-9 bg-accent-500/10 border border-accent-500/30 rounded-xl flex items-center justify-center">
            <FileText size={16} className="text-accent-400" />
          </div>
          <h1 className="text-xl font-semibold text-text-primary">Reports</h1>
        </div>
        <p className="text-sm text-text-muted">Overview and history of all security scans</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard icon={TrendingUp} label="Total Scans" value={history.length} color="bg-accent-500/10 text-accent-400" />
        <StatCard icon={AlertTriangle} label="Phishing" value={phishing} color="bg-danger-500/10 text-danger-400" />
        <StatCard icon={Clock} label="Suspicious" value={suspicious} color="bg-warning-500/10 text-warning-400" />
        <StatCard icon={CheckCircle} label="Safe" value={safe} color="bg-safe-500/10 text-safe-400" />
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 justify-between items-start sm:items-center">
        <div className="flex gap-1 p-1 bg-bg-raised rounded-lg border border-border">
          {filterButtons.map(btn => (
            <button
              key={btn.id}
              onClick={() => setFilter(btn.id)}
              className={clsx(
                'px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-150',
                filter === btn.id
                  ? 'bg-accent-500 text-white shadow-sm'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-surface'
              )}
            >
              {btn.label}
              <span className="ml-1.5 text-[10px] opacity-80">({btn.count})</span>
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-bg-raised border border-border">
            <Calendar size={12} className="text-text-muted" />
            <select 
              value={dateRange} 
              onChange={(e) => setDateRange(e.target.value)}
              className="bg-transparent text-xs text-text-primary focus:outline-none"
            >
              <option value="day">Last 24 hours</option>
              <option value="week">Last 7 days</option>
              <option value="month">Last 30 days</option>
              <option value="all">All time</option>
            </select>
          </div>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-bg-raised border border-border text-xs text-text-secondary hover:text-text-primary transition-colors">
            <Download size={12} />
            Export
          </button>
        </div>
      </div>

      {/* Scan History Table */}
      <div className="card !p-0 overflow-hidden">
        <div className="bg-bg-raised border-b border-border px-5 py-3">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Scan History</h2>
        </div>
        
        {filteredHistory.length === 0 ? (
          <div className="py-16 text-center">
            <div className="w-12 h-12 rounded-full bg-bg-raised border border-border flex items-center justify-center mx-auto mb-3">
              <FileText size={20} className="text-text-muted" />
            </div>
            <p className="text-sm text-text-muted">No scans found</p>
            <p className="text-xs text-text-muted/70 mt-1">Run your first analysis from the Analysis page</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {filteredHistory.map((item, i) => {
              const badge = VERDICT_BADGE[item.result.verdict] || VERDICT_BADGE['LIKELY SAFE']
              return (
                <button
                  key={i}
                  onClick={() => onSelect(item)}
                  className="w-full flex items-center gap-3 p-4 hover:bg-bg-raised transition-all text-left group"
                >
                  {/* Score Badge */}
                  <span className={clsx(
                    'text-sm font-bold px-2.5 py-1 rounded shrink-0 min-w-[52px] text-center font-mono',
                    VERDICT_STYLE[item.result.verdict] || VERDICT_STYLE['LIKELY SAFE']
                  )}>
                    {item.result.score}
                  </span>
                  
                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-text-primary truncate font-mono">{item.input}</p>
                    <div className="flex flex-wrap items-center gap-2 mt-1">
                      <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${badge.bg}`}>
                        {badge.label}
                      </span>
                      <span className="text-xs text-text-muted">{item.result.input_type}</span>
                      <span className="text-xs text-text-muted">{item.result.duration_ms}ms</span>
                      <span className="text-xs text-text-muted">
                        {item.result.analyzed_at ? new Date(item.result.analyzed_at).toLocaleDateString() : 'Just now'}
                      </span>
                    </div>
                  </div>
                  
                  {/* Verdict indicator */}
                  <div className={clsx(
                    'hidden sm:block w-2 h-2 rounded-full',
                    item.result.verdict === 'PHISHING' ? 'bg-danger-400' :
                    item.result.verdict === 'SUSPICIOUS' ? 'bg-warning-400' : 'bg-safe-400'
                  )} />
                </button>
              )
            })}
          </div>
        )}
      </div>

      {/* Export Footer */}
      {filteredHistory.length > 0 && (
        <div className="flex justify-end">
          <button className="flex items-center gap-2 px-4 py-2 rounded-lg border border-border text-sm text-text-secondary hover:text-text-primary hover:bg-bg-raised transition-all">
            <Download size={14} />
            Export Full Report (CSV)
          </button>
        </div>
      )}
    </div>
  )
}