import React from 'react'
import { History, ExternalLink } from 'lucide-react'
import clsx from 'clsx'

const VERDICT_COLOR = {
  'PHISHING':    'text-red-400 bg-red-950 border-red-800',
  'SUSPICIOUS':  'text-amber-400 bg-amber-950 border-amber-800',
  'LIKELY SAFE': 'text-green-400 bg-green-950 border-green-800',
}

export default function ScanHistory({ history, onSelect }) {
  if (history.length === 0) return null

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <History size={14} className="text-slate-400" />
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          Recent Scans
        </h3>
      </div>
      <div className="space-y-2">
        {history.map((item, i) => (
          <button
            key={i}
            onClick={() => onSelect(item)}
            className="w-full flex items-center gap-3 p-2.5 rounded-lg bg-slate-900
                       hover:bg-slate-800 transition-colors text-left group"
          >
            <span className={clsx(
              'text-xs font-bold px-2 py-0.5 rounded border shrink-0',
              VERDICT_COLOR[item.result.verdict] || VERDICT_COLOR['LIKELY SAFE']
            )}>
              {item.result.score}
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-xs text-slate-300 truncate font-mono">{item.input}</p>
              <p className="text-xs text-slate-600">{item.result.input_type}</p>
            </div>
            <ExternalLink size={12} className="text-slate-600 group-hover:text-slate-400 shrink-0" />
          </button>
        ))}
      </div>
    </div>
  )
}
