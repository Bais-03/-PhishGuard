import React from 'react'
import { History, ExternalLink } from 'lucide-react'
import clsx from 'clsx'
import { Card } from './ui'

const VERDICT_COLOR = {
  'PHISHING': 'bg-danger-500/20 text-danger-300 border-danger-500/40 font-bold',
  'SUSPICIOUS': 'bg-warning-500/15 text-warning-300 border-warning-500/40 font-bold',
  'LIKELY SAFE': 'bg-safe-500/15 text-safe-300 border-safe-500/40 font-bold',
}

export default function ScanHistory({ history, onSelect }) {
  if (history.length === 0) return null

  return (
    <Card className="space-y-3">
      <div className="flex items-center gap-2">
        <History size={14} className="text-accent-400" />
        <h3 className="text-xs font-semibold text-accent-400 uppercase tracking-wider">
          Recent Scans
        </h3>
      </div>
      <div className="space-y-2">
        {history.map((item, i) => (
          <button
            key={i}
            onClick={() => onSelect(item)}
            className="w-full flex items-center gap-3 p-3 rounded-lg bg-bg-surface
                       hover:bg-bg-raised border border-border hover:border-border-strong
                       transition-all duration-150 text-left group"
          >
            <span className={clsx(
              'text-sm font-bold px-2.5 py-1 rounded shrink-0 min-w-[48px] text-center',
              VERDICT_COLOR[item.result.verdict] || VERDICT_COLOR['LIKELY SAFE']
            )}>
              {item.result.score}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-text-primary truncate font-mono font-medium">{item.input}</p>
              <p className="text-xs text-text-secondary mt-0.5">{item.result.input_type}</p>
            </div>
            <ExternalLink size={14} className="text-text-secondary group-hover:text-accent-400 shrink-0 transition-colors" />
          </button>
        ))}
      </div>
    </Card>
  )
}